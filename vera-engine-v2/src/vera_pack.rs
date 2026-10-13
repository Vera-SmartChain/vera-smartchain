//! VERA-Engine: In-Silicon Streaming Compression Primitives
//! Opcodes: OP_VERA_PACK (0xC1), OP_VERA_UNPACK (0xC2)
//!
//! Provides ultra-fast, lossless in-memory compression/decompression
//! with adaptive heuristics to bypass the physical BDP bottleneck
//! on high-latency transatlantic links.

pub const OP_VERA_PACK: u8 = 0xC1;
pub const OP_VERA_UNPACK: u8 = 0xC2;

/// Minimum space savings threshold to keep block compressed (e.g., 10% gain).
/// If compressed block occupies >= 90% of original size, block is sent uncompressed
/// to save receiver CPU cycles and prevent high-entropy data inflation.
pub const MIN_COMPRESSION_RATIO: f64 = 0.90;
pub const MIN_COMPRESSIBLE_SIZE: usize = 64;

/// Executes adaptive silicon compression (`OP_VERA_PACK`).
/// Returns `(data, is_compressed)`.
/// If the block is not advantageous for compression, returns original data with `false`.
pub fn vera_pack(input: &[u8]) -> (Vec<u8>, bool) {
    if input.len() < MIN_COMPRESSIBLE_SIZE {
        return (input.to_vec(), false);
    }

    let compressed = lz4_flex::compress(input);
    let threshold = (input.len() as f64 * MIN_COMPRESSION_RATIO) as usize;

    if compressed.len() <= threshold {
        (compressed, true)
    } else {
        // Incompressible data (e.g., pre-compressed binaries or cryptographic noise)
        (input.to_vec(), false)
    }
}

/// Executes silicon decompression (`OP_VERA_UNPACK`).
/// If `is_compressed` is false, returns immediate clone of input data.
/// If true, decompresses into buffer of exact `uncompressed_size`.
pub fn vera_unpack(
    input: &[u8],
    is_compressed: bool,
    uncompressed_size: usize,
) -> Result<Vec<u8>, String> {
    if !is_compressed {
        return Ok(input.to_vec());
    }

    lz4_flex::decompress(input, uncompressed_size)
        .map_err(|e| format!("Error in OP_VERA_UNPACK (LZ4): {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vera_pack_compressible() {
        let original = b"VERACHAIN SOVEREIGN PROTOCOL 0-RTT LAYER 0 OP_VERA_PACK TEST "
            .repeat(500); // ~30 KB
        let (packed, is_compressed) = vera_pack(&original);

        assert!(is_compressed, "Repetitive data must be compressed");
        assert!(packed.len() < original.len() / 5, "Compression must exceed 80%");

        let unpacked = vera_unpack(&packed, is_compressed, original.len())
            .expect("OP_VERA_UNPACK must restore data perfectly");
        assert_eq!(original, unpacked.as_slice());
    }

    #[test]
    fn test_vera_pack_incompressible_fallback() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut random_bytes = vec![0u8; 4096];
        rng.fill_bytes(&mut random_bytes);

        let (packed, is_compressed) = vera_pack(&random_bytes);
        assert!(!is_compressed, "High-entropy cryptographic random data must not be compressed");
        assert_eq!(packed.len(), random_bytes.len());

        let unpacked = vera_unpack(&packed, is_compressed, random_bytes.len())
            .expect("Unpack must process raw uncompressed data without error");
        assert_eq!(random_bytes, unpacked);
    }
}
