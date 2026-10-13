//! VERA-Engine: Continuous Session Context & Shared Dictionary Primitives
//! Opcodes: OP_VERA_DICT_INIT (0xC5), OP_VERA_DICT_PACK (0xC6)
//!
//! Provides zero-RTT stream compression across chunk boundaries by maintaining
//! a persistent LZ77 sliding window and Huffman symbol dictionary across frames.
//! This eliminates chunk-boundary amnesia and dramatically improves compression
//! ratios for multi-megabyte structured streams (e.g. JSON, logs, blockchain state).

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

pub const OP_VERA_DICT_INIT: u8 = 0xC5;
pub const OP_VERA_DICT_PACK: u8 = 0xC6;

/// Continuous context compressor across multiple chunks (persistent Sliding Window)
pub struct VeraSessionCompressor {
    compressor: Compress,
    total_uncompressed: u64,
    total_compressed: u64,
}

impl VeraSessionCompressor {
    pub fn new() -> Self {
        Self {
            // zlib_header = false (raw pure DEFLATE format)
            compressor: Compress::new(Compression::best(), false),
            total_uncompressed: 0,
            total_compressed: 0,
        }
    }

    /// Compresses a chunk while preserving symbol history for subsequent chunks.
    /// Uses `FlushCompress::Sync` to enable immediate receiver decoding without losing context.
    pub fn compress_chunk(&mut self, input: &[u8], is_final: bool) -> Result<Vec<u8>, String> {
        let flush_mode = if is_final {
            FlushCompress::Finish
        } else {
            FlushCompress::Sync
        };

        // Initial estimate: if compressible, output is smaller; allocate with headroom
        let mut output = Vec::with_capacity(input.len().max(512));
        let mut in_pos = 0;

        let before_in = self.compressor.total_in();
        let before_out = self.compressor.total_out();

        while in_pos < input.len() || flush_mode == FlushCompress::Finish {
            let chunk_out_start = output.len();
            output.resize(chunk_out_start + 65536, 0);

            let res = self.compressor.compress(
                &input[in_pos..],
                &mut output[chunk_out_start..],
                flush_mode,
            ).map_err(|e| format!("Error in VeraSessionCompressor: {:?}", e))?;

            let bytes_consumed = (self.compressor.total_in() - before_in - in_pos as u64) as usize;
            in_pos += bytes_consumed;

            let bytes_produced = (self.compressor.total_out() - before_out - chunk_out_start as u64) as usize;
            output.truncate(chunk_out_start + bytes_produced);

            if res == Status::StreamEnd || (flush_mode == FlushCompress::Sync && in_pos >= input.len()) {
                break;
            }
        }

        let consumed = (self.compressor.total_in() - before_in) as u64;
        let produced = (self.compressor.total_out() - before_out) as u64;
        self.total_uncompressed += consumed;
        self.total_compressed += produced;

        Ok(output)
    }

    pub fn total_in(&self) -> u64 {
        self.total_uncompressed
    }

    pub fn total_out(&self) -> u64 {
        self.total_compressed
    }
}

impl Default for VeraSessionCompressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Continuous context decompressor across multiple chunks
pub struct VeraSessionDecompressor {
    decompressor: Decompress,
    total_in: u64,
    total_out: u64,
}

impl VeraSessionDecompressor {
    pub fn new() -> Self {
        Self {
            decompressor: Decompress::new(false),
            total_in: 0,
            total_out: 0,
        }
    }

    /// Decompresses an incoming chunk, updating local sliding window history.
    pub fn decompress_chunk(&mut self, input: &[u8], is_final: bool) -> Result<Vec<u8>, String> {
        let flush_mode = if is_final {
            FlushDecompress::Finish
        } else {
            FlushDecompress::Sync
        };

        let mut output = Vec::with_capacity(input.len() * 4);
        let mut in_pos = 0;

        let before_in = self.decompressor.total_in();
        let before_out = self.decompressor.total_out();

        while in_pos < input.len() || flush_mode == FlushDecompress::Finish {
            let chunk_out_start = output.len();
            output.resize(chunk_out_start + 65536, 0);

            let res = self.decompressor.decompress(
                &input[in_pos..],
                &mut output[chunk_out_start..],
                flush_mode,
            ).map_err(|e| format!("Error in VeraSessionDecompressor: {:?}", e))?;

            let bytes_consumed = (self.decompressor.total_in() - before_in - in_pos as u64) as usize;
            in_pos += bytes_consumed;

            let bytes_produced = (self.decompressor.total_out() - before_out - chunk_out_start as u64) as usize;
            output.truncate(chunk_out_start + bytes_produced);

            if res == Status::StreamEnd || (flush_mode == FlushDecompress::Sync && in_pos >= input.len()) {
                break;
            }
        }

        let consumed = (self.decompressor.total_in() - before_in) as u64;
        let produced = (self.decompressor.total_out() - before_out) as u64;
        self.total_in += consumed;
        self.total_out += produced;

        Ok(output)
    }

    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    pub fn total_out(&self) -> u64 {
        self.total_out
    }
}

impl Default for VeraSessionDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_dict_continuous_chunks() {
        let mut compressor = VeraSessionCompressor::new();
        let mut decompressor = VeraSessionDecompressor::new();

        // 3 JSON data chunks with repetitive schema and keys
        let chunk1 = b"{\"user\":\"alice\",\"role\":\"admin\",\"permissions\":[\"read\",\"write\",\"execute\"],\"token\":\"abc123xyz\"}".repeat(50);
        let chunk2 = b"{\"user\":\"bob\",\"role\":\"editor\",\"permissions\":[\"read\",\"write\"],\"token\":\"def456uvw\"}".repeat(50);
        let chunk3 = b"{\"user\":\"charlie\",\"role\":\"viewer\",\"permissions\":[\"read\"],\"token\":\"ghi789rst\"}".repeat(50);

        let comp1 = compressor.compress_chunk(&chunk1, false).expect("Comp 1 failed");
        let dec1 = decompressor.decompress_chunk(&comp1, false).expect("Dec 1 failed");
        assert_eq!(chunk1.as_slice(), dec1.as_slice());

        let comp2 = compressor.compress_chunk(&chunk2, false).expect("Comp 2 failed");
        let dec2 = decompressor.decompress_chunk(&comp2, false).expect("Dec 2 failed");
        assert_eq!(chunk2.as_slice(), dec2.as_slice());

        let comp3 = compressor.compress_chunk(&chunk3, true).expect("Comp 3 failed");
        let dec3 = decompressor.decompress_chunk(&comp3, true).expect("Dec 3 failed");
        assert_eq!(chunk3.as_slice(), dec3.as_slice());

        println!(
            "Total original: {} bytes | Total continuous compressed: {} bytes (Ratio: {:.2}x)",
            chunk1.len() + chunk2.len() + chunk3.len(),
            comp1.len() + comp2.len() + comp3.len(),
            (chunk1.len() + chunk2.len() + chunk3.len()) as f64 / (comp1.len() + comp2.len() + comp3.len()) as f64
        );
    }
}
