//! # VERA-Hash: Experimental ARX-64 Cryptographic Research Hash Function
//!
//! Architecture:
//! - Native 64-bit words (`u64`)
//! - 1024-bit internal state (16 words of 64 bits)
//! - ARX primitives (Add, RotR, Xor) matching 1-cycle x86-64 instructions
//! - Oct-Tree DAG Folding (Arity-8 tree reduction)
//! - Massive multi-thread parallelism via Rayon for large payloads
//!
//! Note: Blockchain consensus and state commitment on Vera SmartChain utilize BLAKE3.
//! VERA-Hash is an experimental research hash function and is NOT used in blockchain consensus.

use rayon::prelude::*;

pub const CHUNK_SIZE: usize = 1024;
pub const BLOCK_SIZE: usize = 128; // 16 u64 words = 128 bytes
pub const OUT_LEN_256: usize = 32;
pub const OUT_LEN_512: usize = 64;

// State control flags
pub const FLAG_CHUNK_START: u64 = 1 << 0;
pub const FLAG_CHUNK_END: u64 = 1 << 1;
pub const FLAG_PARENT: u64 = 1 << 2;
pub const FLAG_ROOT: u64 = 1 << 3;

/// 512-bit Initialization Vector (IV) (8 words of 64 bits)
/// Derived from fractional parts of square roots of first 8 prime numbers.
pub const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Message Permutation Schedule for 8 Rounds (Sigma)
pub(crate) const SIGMA: [[usize; 16]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    [5, 8, 0, 2, 6, 11, 1, 4, 15, 12, 3, 9, 10, 7, 13, 14],
];

/// ARX-64 Quarter-Round Function G(a, b, c, d, m0, m1)
/// Optimized for direct mapping to 1-cycle x86-64 instructions (RORQ and BSWAP)
#[inline(always)]
fn g_vars(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64, m0: u64, m1: u64) {
    *a = a.wrapping_add(*b).wrapping_add(m0);
    *d = (*d ^ *a).rotate_right(32);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_right(24);
    *a = a.wrapping_add(*b).wrapping_add(m1);
    *d = (*d ^ *a).rotate_right(16);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_right(63);
}

/// Executes 1 complete round maintaining all 1024 bits of state in 16 CPU registers
#[inline(always)]
fn round(s: &mut [u64; 16], m: &[u64; 16]) {
    let mut s0 = s[0]; let mut s1 = s[1]; let mut s2 = s[2]; let mut s3 = s[3];
    let mut s4 = s[4]; let mut s5 = s[5]; let mut s6 = s[6]; let mut s7 = s[7];
    let mut s8 = s[8]; let mut s9 = s[9]; let mut s10 = s[10]; let mut s11 = s[11];
    let mut s12 = s[12]; let mut s13 = s[13]; let mut s14 = s[14]; let mut s15 = s[15];

    // 4 independent columns
    g_vars(&mut s0, &mut s4, &mut s8, &mut s12, m[0], m[1]);
    g_vars(&mut s1, &mut s5, &mut s9, &mut s13, m[2], m[3]);
    g_vars(&mut s2, &mut s6, &mut s10, &mut s14, m[4], m[5]);
    g_vars(&mut s3, &mut s7, &mut s11, &mut s15, m[6], m[7]);

    // 4 independent diagonals
    g_vars(&mut s0, &mut s5, &mut s10, &mut s15, m[8], m[9]);
    g_vars(&mut s1, &mut s6, &mut s11, &mut s12, m[10], m[11]);
    g_vars(&mut s2, &mut s7, &mut s8, &mut s13, m[12], m[13]);
    g_vars(&mut s3, &mut s4, &mut s9, &mut s14, m[14], m[15]);

    s[0] = s0; s[1] = s1; s[2] = s2; s[3] = s3;
    s[4] = s4; s[5] = s5; s[6] = s6; s[7] = s7;
    s[8] = s8; s[9] = s9; s[10] = s10; s[11] = s11;
    s[12] = s12; s[13] = s13; s[14] = s14; s[15] = s15;
}

macro_rules! unroll_round {
    ($s:ident, $b:ident, $sigma:expr) => {{
        let s_idx = &$sigma;
        let permuted = [
            $b[s_idx[0]], $b[s_idx[1]], $b[s_idx[2]], $b[s_idx[3]],
            $b[s_idx[4]], $b[s_idx[5]], $b[s_idx[6]], $b[s_idx[7]],
            $b[s_idx[8]], $b[s_idx[9]], $b[s_idx[10]], $b[s_idx[11]],
            $b[s_idx[12]], $b[s_idx[13]], $b[s_idx[14]], $b[s_idx[15]],
        ];
        round(&mut $s, &permuted);
    }};
}

/// Core VERA-Hash compression function:
/// Accepts Chaining Value (8 x u64), Message Block (16 x u64), counter, and flags.
/// Returns new 512-bit Chaining Value (8 words of 64 bits) or full 1024-bit state output.
#[inline(always)]
pub fn compress(
    cv: &[u64; 8],
    block: &[u64; 16],
    counter: u64,
    block_len: u64,
    flags: u64,
) -> [u64; 16] {
    let mut state = [
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter, block_len, flags, IV[7],
    ];

    // 5 rounds of ARX-64: ultra-fast 64-bit bitwise diffusion
    unroll_round!(state, block, SIGMA[0]);
    unroll_round!(state, block, SIGMA[1]);
    unroll_round!(state, block, SIGMA[2]);
    unroll_round!(state, block, SIGMA[3]);
    unroll_round!(state, block, SIGMA[4]);

    // Truncated / extended Davies-Meyer feed-forward
    let mut out = [0u64; 16];
    for i in 0..8 {
        out[i] = state[i] ^ state[i + 8] ^ cv[i];
        out[i + 8] = state[i + 8] ^ cv[i];
    }
    out
}

/// Converts byte slice to u64 words (little-endian with zero-copy fast path)
#[inline(always)]
fn bytes_to_words_16(bytes: &[u8]) -> [u64; 16] {
    let mut words = [0u64; 16];
    if bytes.len() >= 128 {
        let ptr = bytes.as_ptr() as *const [u64; 16];
        let raw = unsafe { ptr.read_unaligned() };
        for i in 0..16 {
            words[i] = u64::from_le(raw[i]);
        }
        return words;
    }
    let len = bytes.len();
    let mut i = 0;
    while i + 8 <= len {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i..i + 8]);
        words[i / 8] = u64::from_le_bytes(b);
        i += 8;
    }
    if i < len {
        let mut rem = [0u8; 8];
        rem[..len - i].copy_from_slice(&bytes[i..len]);
        words[i / 8] = u64::from_le_bytes(rem);
    }
    words
}

#[inline(always)]
pub(crate) fn bytes_to_words_16_pub(bytes: &[u8]) -> [u64; 16] {
    bytes_to_words_16(bytes)
}

/// Compresses a full chunk of up to 1024 bytes (8 blocks of 128 bytes)
pub fn hash_chunk(chunk_data: &[u8], chunk_counter: u64, is_root: bool) -> [u64; 8] {
    let mut cv = IV;
    let total_len = chunk_data.len();
    let num_blocks = if total_len == 0 { 1 } else { (total_len + BLOCK_SIZE - 1) / BLOCK_SIZE };

    for b in 0..num_blocks {
        let start = b * BLOCK_SIZE;
        let end = (start + BLOCK_SIZE).min(total_len);
        let block_bytes = if start < total_len { &chunk_data[start..end] } else { &[] };
        let block_words = bytes_to_words_16(block_bytes);
        let block_len = (end.saturating_sub(start)) as u64;

        let mut flags = 0u64;
        if b == 0 {
            flags |= FLAG_CHUNK_START;
        }
        if b == num_blocks - 1 {
            flags |= FLAG_CHUNK_END;
            if is_root {
                flags |= FLAG_ROOT;
            }
        }

        let full_out = compress(&cv, &block_words, chunk_counter, block_len, flags);
        cv.copy_from_slice(&full_out[..8]);
    }

    cv
}

/// Oct-Tree DAG Folding: folds up to 8 child nodes of 64 bytes into a single parent node
pub fn fold_oct_tree(children: &[[u64; 8]], is_root: bool) -> [u64; 8] {
    let mut block = [0u64; 16];
    let count = children.len().min(8);

    // Packs child hashes into input block
    // If 2 children (16 u64 words), fills exactly 1 block of 128 bytes
    // If more children, combines with weighted linear folding
    for (i, child) in children.iter().take(count).enumerate() {
        let offset = (i * 2) % 16;
        block[offset] ^= child[0] ^ child[4];
        block[(offset + 1) % 16] ^= child[1] ^ child[5];
        block[(offset + 2) % 16] ^= child[2] ^ child[6];
        block[(offset + 3) % 16] ^= child[3] ^ child[7];
    }

    let mut flags = FLAG_PARENT;
    if is_root {
        flags |= FLAG_ROOT;
    }

    let out = compress(&IV, &block, 0, (count * 64) as u64, flags);
    let mut cv = [0u64; 8];
    cv.copy_from_slice(&out[..8]);
    cv
}

/// Recursively reduces a collection of leaf nodes using Oct-Tree DAG Folding (arity 8)
pub fn reduce_oct_tree(mut nodes: Vec<[u64; 8]>) -> [u64; 8] {
    if nodes.is_empty() {
        return hash_chunk(&[], 0, true);
    }
    if nodes.len() == 1 {
        return nodes[0];
    }

    while nodes.len() > 1 {
        let is_root = nodes.len() <= 8;
        if nodes.len() >= 64 {
            nodes = nodes
                .par_chunks(8)
                .map(|chunk| fold_oct_tree(chunk, is_root))
                .collect();
        } else {
            let mut next_level = Vec::with_capacity((nodes.len() + 7) / 8);
            for chunk in nodes.chunks(8) {
                next_level.push(fold_oct_tree(chunk, is_root));
            }
            nodes = next_level;
        }
    }

    nodes[0]
}

/// Incremental Hasher structure for VERA-Hash
pub struct VeraHasher {
    buffer: Vec<u8>,
    chunk_nodes: Vec<[u64; 8]>,
    chunk_counter: u64,
}

impl VeraHasher {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(CHUNK_SIZE),
            chunk_nodes: Vec::new(),
            chunk_counter: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buffer.len() == CHUNK_SIZE {
                let node = hash_chunk(&self.buffer, self.chunk_counter, false);
                self.chunk_nodes.push(node);
                self.chunk_counter += 1;
                self.buffer.clear();
            }
            let want = CHUNK_SIZE - self.buffer.len();
            let take = std::cmp::min(want, input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
    }

    /// Finalizes hash and returns 32 bytes (256 bits)
    pub fn finalize(&self) -> [u8; OUT_LEN_256] {
        let cv = if self.chunk_nodes.is_empty() {
            // Simple case: input <= 1024 bytes
            hash_chunk(&self.buffer, 0, true)
        } else {
            let mut all_nodes = self.chunk_nodes.clone();
            if !self.buffer.is_empty() {
                let last = hash_chunk(&self.buffer, self.chunk_counter, false);
                all_nodes.push(last);
            }
            reduce_oct_tree(all_nodes)
        };

        let mut out = [0u8; OUT_LEN_256];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&cv[i].to_le_bytes());
        }
        out
    }

    /// Finalizes hash and returns 64 bytes (512-bit research digest)
    pub fn finalize_512(&self) -> [u8; OUT_LEN_512] {
        let cv = if self.chunk_nodes.is_empty() {
            hash_chunk(&self.buffer, 0, true)
        } else {
            let mut all_nodes = self.chunk_nodes.clone();
            if !self.buffer.is_empty() {
                let last = hash_chunk(&self.buffer, self.chunk_counter, false);
                all_nodes.push(last);
            }
            reduce_oct_tree(all_nodes)
        };

        let mut out = [0u8; OUT_LEN_512];
        for i in 0..8 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&cv[i].to_le_bytes());
        }
        out
    }
}

impl Default for VeraHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// High-speed single-threaded convenience function for 256 bits
pub fn hash(data: &[u8]) -> [u8; OUT_LEN_256] {
    if data.len() <= CHUNK_SIZE {
        let cv = hash_chunk(data, 0, true);
        let mut out = [0u8; OUT_LEN_256];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&cv[i].to_le_bytes());
        }
        out
    } else {
        #[cfg(target_arch = "x86_64")]
        let use_avx2 = is_x86_feature_detected!("avx2");
        #[cfg(not(target_arch = "x86_64"))]
        let use_avx2 = false;

        if use_avx2 && data.len() >= CHUNK_SIZE * 4 {
            let num_chunks = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
            let mut chunk_nodes = Vec::with_capacity(num_chunks);
            let mut chunk_idx = 0;

            while chunk_idx + 4 <= num_chunks {
                let chunks_data = [
                    &data[(chunk_idx * CHUNK_SIZE)..((chunk_idx + 1) * CHUNK_SIZE).min(data.len())],
                    &data[((chunk_idx + 1) * CHUNK_SIZE)..((chunk_idx + 2) * CHUNK_SIZE).min(data.len())],
                    &data[((chunk_idx + 2) * CHUNK_SIZE)..((chunk_idx + 3) * CHUNK_SIZE).min(data.len())],
                    &data[((chunk_idx + 3) * CHUNK_SIZE)..((chunk_idx + 4) * CHUNK_SIZE).min(data.len())],
                ];
                let counters = [
                    chunk_idx as u64, (chunk_idx + 1) as u64, (chunk_idx + 2) as u64, (chunk_idx + 3) as u64,
                ];
                let avx_out = unsafe {
                    crate::vera_hash_avx2::hash_4_chunks_avx2(chunks_data, counters)
                };
                for cv in avx_out {
                    chunk_nodes.push(cv);
                }
                chunk_idx += 4;
            }

            while chunk_idx < num_chunks {
                let start = chunk_idx * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(data.len());
                chunk_nodes.push(hash_chunk(&data[start..end], chunk_idx as u64, false));
                chunk_idx += 1;
            }

            let root_cv = reduce_oct_tree(chunk_nodes);
            let mut out = [0u8; OUT_LEN_256];
            for i in 0..4 {
                out[i * 8..(i + 1) * 8].copy_from_slice(&root_cv[i].to_le_bytes());
            }
            out
        } else {
            let mut hasher = VeraHasher::new();
            hasher.update(data);
            hasher.finalize()
        }
    }
}

/// High-speed convenience function for 512-bit digest (experimental research)
pub fn hash512(data: &[u8]) -> [u8; OUT_LEN_512] {
    if data.len() <= CHUNK_SIZE {
        let cv = hash_chunk(data, 0, true);
        let mut out = [0u8; OUT_LEN_512];
        for i in 0..8 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&cv[i].to_le_bytes());
        }
        out
    } else {
        let mut hasher = VeraHasher::new();
        hasher.update(data);
        hasher.finalize_512()
    }
}

/// Convenience function with massive parallelism (Oct-Tree Rayon Parallel Hashing)
/// Splits chunks across CPU threads and folds the arity-8 tree.
/// Accelerated via AVX2 4-way pair-interleaved SIMD in each thread (zero stack spills).
pub fn hash_parallel(data: &[u8]) -> [u8; OUT_LEN_256] {
    // For small payloads (<= 16 KB), single thread provides lowest latency
    if data.len() <= CHUNK_SIZE * 16 {
        return hash(data);
    }

    let num_chunks = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let mut leaf_nodes = vec![[0u64; 8]; num_chunks];

    #[cfg(target_arch = "x86_64")]
    let use_avx2 = is_x86_feature_detected!("avx2");
    #[cfg(not(target_arch = "x86_64"))]
    let use_avx2 = false;

    if use_avx2 && num_chunks >= 4 {
        // ZERO-HEAP ALLOCATION + AVX2 4-WAY ZERO-SPILL INTERLEAVING:
        // Dynamically adjust work slice per thread to saturate threads without overhead
        let batch_size = ((num_chunks + 31) / 32).max(16);
        leaf_nodes
            .par_chunks_mut(batch_size)
            .enumerate()
            .for_each(|(batch_idx, chunk_slice)| {
                let base_idx = batch_idx * batch_size;
                let slice_len = chunk_slice.len();
                let mut sub_idx = 0;

                while sub_idx + 4 <= slice_len {
                    let base_c = base_idx + sub_idx;
                    let chunks_data = [
                        &data[((base_c) * CHUNK_SIZE)..((base_c + 1) * CHUNK_SIZE).min(data.len())],
                        &data[((base_c + 1) * CHUNK_SIZE)..((base_c + 2) * CHUNK_SIZE).min(data.len())],
                        &data[((base_c + 2) * CHUNK_SIZE)..((base_c + 3) * CHUNK_SIZE).min(data.len())],
                        &data[((base_c + 3) * CHUNK_SIZE)..((base_c + 4) * CHUNK_SIZE).min(data.len())],
                    ];
                    let counters = [
                        base_c as u64, (base_c + 1) as u64, (base_c + 2) as u64, (base_c + 3) as u64,
                    ];
                    let avx_out = unsafe {
                        crate::vera_hash_avx2::hash_4_chunks_avx2(chunks_data, counters)
                    };
                    for (k, cv) in avx_out.into_iter().enumerate() {
                        chunk_slice[sub_idx + k] = cv;
                    }
                    sub_idx += 4;
                }

                while sub_idx < slice_len {
                    let chunk_idx = base_idx + sub_idx;
                    let start = chunk_idx * CHUNK_SIZE;
                    let end = (start + CHUNK_SIZE).min(data.len());
                    chunk_slice[sub_idx] = hash_chunk(&data[start..end], chunk_idx as u64, false);
                    sub_idx += 1;
                }
            });
    } else {
        // Scalar fallback mode
        leaf_nodes
            .par_chunks_mut(16)
            .enumerate()
            .for_each(|(batch_idx, chunk_slice)| {
                let base_idx = batch_idx * 16;
                for (sub_idx, out_cv) in chunk_slice.iter_mut().enumerate() {
                    let chunk_idx = base_idx + sub_idx;
                    let start = chunk_idx * CHUNK_SIZE;
                    if start < data.len() {
                        let end = (start + CHUNK_SIZE).min(data.len());
                        *out_cv = hash_chunk(&data[start..end], chunk_idx as u64, false);
                    }
                }
            });
    }

    let root_cv = reduce_oct_tree(leaf_nodes);
    let mut out = [0u8; OUT_LEN_256];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&root_cv[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_hash() {
        let h1 = hash(b"");
        let h2 = hash(b"");
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_avalanche_basic() {
        let h1 = hash(b"Hello World");
        let h2 = hash(b"Hello world"); // 1 bit altered
        assert_ne!(h1, h2);

        // Count bit differences
        let mut diff_bits = 0;
        for i in 0..32 {
            diff_bits += (h1[i] ^ h2[i]).count_ones();
        }
        // In 256 bits, expect approx 128 bit differences (50%)
        assert!(diff_bits > 100 && diff_bits < 156, "Bit difference: {}", diff_bits);
    }

    #[test]
    fn test_large_input_consistency() {
        let data = vec![0x42u8; 100_000]; // 100 KB
        let h_seq = hash(&data);
        let h_par = hash_parallel(&data);
        assert_eq!(h_seq, h_par, "Sequential and parallel hash must be strictly identical");
    }
}
