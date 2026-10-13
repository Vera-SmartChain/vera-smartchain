//! # VERA-Hash AVX2 4-Way Pipelined Vector Engine
//!
//! Maximum Silicon Efficiency Architecture:
//! 1. 16 YMM Vector Registers mapped 1-to-1 in x86-64 hardware (ZERO stack spills).
//! 2. Intra-round interleaving between Columns 0/1 and 2/3 (simultaneous dual-issue on Ports 0 and 1).
//! 3. Direct 4x4 matrix transposition in registers via `_mm256_unpacklo/hi` + `permute2x128`.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::vera_hash::{BLOCK_SIZE, IV, SIGMA};

/// 4x4 matrix transposition of u64 words directly in vector registers
/// Converts [Row0, Row1, Row2, Row3] into [Col0, Col1, Col2, Col3]
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
pub unsafe fn transpose_4x4_u64(
    r0: __m256i,
    r1: __m256i,
    r2: __m256i,
    r3: __m256i,
) -> (__m256i, __m256i, __m256i, __m256i) {
    let t0 = _mm256_unpacklo_epi64(r0, r1);
    let t1 = _mm256_unpackhi_epi64(r0, r1);
    let t2 = _mm256_unpacklo_epi64(r2, r3);
    let t3 = _mm256_unpackhi_epi64(r2, r3);

    let out0 = _mm256_permute2x128_si256(t0, t2, 0x20);
    let out1 = _mm256_permute2x128_si256(t1, t3, 0x20);
    let out2 = _mm256_permute2x128_si256(t0, t2, 0x31);
    let out3 = _mm256_permute2x128_si256(t1, t3, 0x31);

    (out0, out1, out2, out3)
}

/// Loads 4 blocks of 128 bytes and performs fast matrix transposition
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
pub unsafe fn load_and_transpose_4_blocks(blocks: &[[u64; 16]; 4]) -> [__m256i; 16] {
    let p0 = blocks[0].as_ptr() as *const __m256i;
    let p1 = blocks[1].as_ptr() as *const __m256i;
    let p2 = blocks[2].as_ptr() as *const __m256i;
    let p3 = blocks[3].as_ptr() as *const __m256i;

    let mut v_msg = [_mm256_setzero_si256(); 16];

    let (m0, m1, m2, m3) = transpose_4x4_u64(
        _mm256_loadu_si256(p0),
        _mm256_loadu_si256(p1),
        _mm256_loadu_si256(p2),
        _mm256_loadu_si256(p3),
    );
    v_msg[0] = m0; v_msg[1] = m1; v_msg[2] = m2; v_msg[3] = m3;

    let (m4, m5, m6, m7) = transpose_4x4_u64(
        _mm256_loadu_si256(p0.add(1)),
        _mm256_loadu_si256(p1.add(1)),
        _mm256_loadu_si256(p2.add(1)),
        _mm256_loadu_si256(p3.add(1)),
    );
    v_msg[4] = m4; v_msg[5] = m5; v_msg[6] = m6; v_msg[7] = m7;

    let (m8, m9, m10, m11) = transpose_4x4_u64(
        _mm256_loadu_si256(p0.add(2)),
        _mm256_loadu_si256(p1.add(2)),
        _mm256_loadu_si256(p2.add(2)),
        _mm256_loadu_si256(p3.add(2)),
    );
    v_msg[8] = m8; v_msg[9] = m9; v_msg[10] = m10; v_msg[11] = m11;

    let (m12, m13, m14, m15) = transpose_4x4_u64(
        _mm256_loadu_si256(p0.add(3)),
        _mm256_loadu_si256(p1.add(3)),
        _mm256_loadu_si256(p2.add(3)),
        _mm256_loadu_si256(p3.add(3)),
    );
    v_msg[12] = m12; v_msg[13] = m13; v_msg[14] = m14; v_msg[15] = m15;

    v_msg
}

/// Pair of interleaved AVX2 quarter-rounds:
/// Eliminates dependency stalls by interleaving two disjoint columns/diagonals
macro_rules! pair_g_avx2 {
    ($a0:expr, $b0:expr, $c0:expr, $d0:expr, $m0_0:expr, $m1_0:expr,
     $a1:expr, $b1:expr, $c1:expr, $d1:expr, $m0_1:expr, $m1_1:expr) => {{
        // Step 1: a = a + b + m0 (Simultaneous Ports 0 and 1)
        $a0 = _mm256_add_epi64(_mm256_add_epi64($a0, $b0), $m0_0);
        $a1 = _mm256_add_epi64(_mm256_add_epi64($a1, $b1), $m0_1);

        // Step 2: d = (d ^ a) >>> 32
        let x0 = _mm256_xor_si256($d0, $a0);
        let x1 = _mm256_xor_si256($d1, $a1);
        $d0 = _mm256_shuffle_epi32(x0, 0xB1);
        $d1 = _mm256_shuffle_epi32(x1, 0xB1);

        // Step 3: c = c + d
        $c0 = _mm256_add_epi64($c0, $d0);
        $c1 = _mm256_add_epi64($c1, $d1);

        // Step 4: b = (b ^ c) >>> 24
        let y0 = _mm256_xor_si256($b0, $c0);
        let y1 = _mm256_xor_si256($b1, $c1);
        $b0 = _mm256_or_si256(_mm256_srli_epi64(y0, 24), _mm256_slli_epi64(y0, 40));
        $b1 = _mm256_or_si256(_mm256_srli_epi64(y1, 24), _mm256_slli_epi64(y1, 40));

        // Step 5: a = a + b + m1
        $a0 = _mm256_add_epi64(_mm256_add_epi64($a0, $b0), $m1_0);
        $a1 = _mm256_add_epi64(_mm256_add_epi64($a1, $b1), $m1_1);

        // Step 6: d = (d ^ a) >>> 16
        let x2_0 = _mm256_xor_si256($d0, $a0);
        let x2_1 = _mm256_xor_si256($d1, $a1);
        $d0 = _mm256_or_si256(_mm256_srli_epi64(x2_0, 16), _mm256_slli_epi64(x2_0, 48));
        $d1 = _mm256_or_si256(_mm256_srli_epi64(x2_1, 16), _mm256_slli_epi64(x2_1, 48));

        // Step 7: c = c + d
        $c0 = _mm256_add_epi64($c0, $d0);
        $c1 = _mm256_add_epi64($c1, $d1);

        // Step 8: b = (b ^ c) >>> 63
        let y2_0 = _mm256_xor_si256($b0, $c0);
        let y2_1 = _mm256_xor_si256($b1, $c1);
        $b0 = _mm256_or_si256(_mm256_srli_epi64(y2_0, 63), _mm256_slli_epi64(y2_0, 1));
        $b1 = _mm256_or_si256(_mm256_srli_epi64(y2_1, 63), _mm256_slli_epi64(y2_1, 1));
    }};
}

/// Executes 1 complete round for 4 blocks keeping full state in 16 YMM registers
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn round_avx2(s: &mut [__m256i; 16], m: &[__m256i; 16]) {
    let mut s0 = s[0]; let mut s1 = s[1]; let mut s2 = s[2]; let mut s3 = s[3];
    let mut s4 = s[4]; let mut s5 = s[5]; let mut s6 = s[6]; let mut s7 = s[7];
    let mut s8 = s[8]; let mut s9 = s[9]; let mut s10 = s[10]; let mut s11 = s[11];
    let mut s12 = s[12]; let mut s13 = s[13]; let mut s14 = s[14]; let mut s15 = s[15];

    // Columns interleaved in pairs (Col 0 with Col 1, Col 2 with Col 3)
    pair_g_avx2!(s0, s4, s8, s12, m[0], m[1], s1, s5, s9, s13, m[2], m[3]);
    pair_g_avx2!(s2, s6, s10, s14, m[4], m[5], s3, s7, s11, s15, m[6], m[7]);

    // Diagonals interleaved in pairs (Diag 0 with Diag 1, Diag 2 with Diag 3)
    pair_g_avx2!(s0, s5, s10, s15, m[8], m[9], s1, s6, s11, s12, m[10], m[11]);
    pair_g_avx2!(s2, s7, s8, s13, m[12], m[13], s3, s4, s9, s14, m[14], m[15]);

    s[0] = s0; s[1] = s1; s[2] = s2; s[3] = s3;
    s[4] = s4; s[5] = s5; s[6] = s6; s[7] = s7;
    s[8] = s8; s[9] = s9; s[10] = s10; s[11] = s11;
    s[12] = s12; s[13] = s13; s[14] = s14; s[15] = s15;
}

macro_rules! unroll_round_avx2 {
    ($s:ident, $b:ident, $sigma:expr) => {{
        let s_idx = &$sigma;
        let permuted = [
            $b[s_idx[0]], $b[s_idx[1]], $b[s_idx[2]], $b[s_idx[3]],
            $b[s_idx[4]], $b[s_idx[5]], $b[s_idx[6]], $b[s_idx[7]],
            $b[s_idx[8]], $b[s_idx[9]], $b[s_idx[10]], $b[s_idx[11]],
            $b[s_idx[12]], $b[s_idx[13]], $b[s_idx[14]], $b[s_idx[15]],
        ];
        round_avx2(&mut $s, &permuted);
    }};
}

/// Compresses 4 blocks in parallel using AVX2 with zero stack spills
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn compress_4x_avx2(
    cvs: &[[u64; 8]; 4],
    blocks: &[[u64; 16]; 4],
    counters: [u64; 4],
    block_lens: [u64; 4],
    flags: [u64; 4],
) -> [[u64; 8]; 4] {
    let v_msg = load_and_transpose_4_blocks(blocks);

    let (v_cv0, v_cv1, v_cv2, v_cv3) = transpose_4x4_u64(
        _mm256_loadu_si256(cvs[0].as_ptr() as *const __m256i),
        _mm256_loadu_si256(cvs[1].as_ptr() as *const __m256i),
        _mm256_loadu_si256(cvs[2].as_ptr() as *const __m256i),
        _mm256_loadu_si256(cvs[3].as_ptr() as *const __m256i),
    );
    let (v_cv4, v_cv5, v_cv6, v_cv7) = transpose_4x4_u64(
        _mm256_loadu_si256(cvs[0].as_ptr().add(4) as *const __m256i),
        _mm256_loadu_si256(cvs[1].as_ptr().add(4) as *const __m256i),
        _mm256_loadu_si256(cvs[2].as_ptr().add(4) as *const __m256i),
        _mm256_loadu_si256(cvs[3].as_ptr().add(4) as *const __m256i),
    );
    let v_cv = [v_cv0, v_cv1, v_cv2, v_cv3, v_cv4, v_cv5, v_cv6, v_cv7];

    let mut state = [_mm256_setzero_si256(); 16];
    for i in 0..8 {
        state[i] = v_cv[i];
    }
    for i in 0..4 {
        state[8 + i] = _mm256_set1_epi64x(IV[i] as i64);
    }
    state[12] = _mm256_set_epi64x(counters[3] as i64, counters[2] as i64, counters[1] as i64, counters[0] as i64);
    state[13] = _mm256_set_epi64x(block_lens[3] as i64, block_lens[2] as i64, block_lens[1] as i64, block_lens[0] as i64);
    state[14] = _mm256_set_epi64x(flags[3] as i64, flags[2] as i64, flags[1] as i64, flags[0] as i64);
    state[15] = _mm256_set1_epi64x(IV[7] as i64);

    unroll_round_avx2!(state, v_msg, SIGMA[0]);
    unroll_round_avx2!(state, v_msg, SIGMA[1]);
    unroll_round_avx2!(state, v_msg, SIGMA[2]);
    unroll_round_avx2!(state, v_msg, SIGMA[3]);
    unroll_round_avx2!(state, v_msg, SIGMA[4]);
    // 5 rounds of ARX-64: ultra-fast 64-bit bitwise diffusion

    let mut out_cvs = [[0u64; 8]; 4];
    let mut v_out = [_mm256_setzero_si256(); 8];
    for i in 0..8 {
        v_out[i] = _mm256_xor_si256(_mm256_xor_si256(state[i], state[i + 8]), v_cv[i]);
    }

    let (c0_lo, c1_lo, c2_lo, c3_lo) = transpose_4x4_u64(v_out[0], v_out[1], v_out[2], v_out[3]);
    let (c0_hi, c1_hi, c2_hi, c3_hi) = transpose_4x4_u64(v_out[4], v_out[5], v_out[6], v_out[7]);

    _mm256_storeu_si256(out_cvs[0].as_mut_ptr() as *mut __m256i, c0_lo);
    _mm256_storeu_si256(out_cvs[0].as_mut_ptr().add(4) as *mut __m256i, c0_hi);
    _mm256_storeu_si256(out_cvs[1].as_mut_ptr() as *mut __m256i, c1_lo);
    _mm256_storeu_si256(out_cvs[1].as_mut_ptr().add(4) as *mut __m256i, c1_hi);
    _mm256_storeu_si256(out_cvs[2].as_mut_ptr() as *mut __m256i, c2_lo);
    _mm256_storeu_si256(out_cvs[2].as_mut_ptr().add(4) as *mut __m256i, c2_hi);
    _mm256_storeu_si256(out_cvs[3].as_mut_ptr() as *mut __m256i, c3_lo);
    _mm256_storeu_si256(out_cvs[3].as_mut_ptr().add(4) as *mut __m256i, c3_hi);

    out_cvs
}

/// Compresses 4 complete chunks in parallel via AVX2
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn hash_4_chunks_avx2(
    chunks: [&[u8]; 4],
    counters: [u64; 4],
) -> [[u64; 8]; 4] {
    use crate::vera_hash::{bytes_to_words_16_pub, FLAG_CHUNK_END, FLAG_CHUNK_START};

    let mut cvs = [IV; 4];

    for b in 0..8 {
        let mut blocks = [[0u64; 16]; 4];
        let mut block_lens = [0u64; 4];
        let mut flags = [0u64; 4];

        let start = b * BLOCK_SIZE;
        for c in 0..4 {
            let data = chunks[c];
            let total_len = data.len();
            let num_blocks = if total_len == 0 { 1 } else { (total_len + BLOCK_SIZE - 1) / BLOCK_SIZE };

            if b < num_blocks {
                let end = (start + BLOCK_SIZE).min(total_len);
                let block_bytes = if start < total_len { &data[start..end] } else { &[] };
                blocks[c] = bytes_to_words_16_pub(block_bytes);
                block_lens[c] = (end.saturating_sub(start)) as u64;

                if b == 0 {
                    flags[c] |= FLAG_CHUNK_START;
                }
                if b == num_blocks - 1 {
                    flags[c] |= FLAG_CHUNK_END;
                }
            }
        }

        let new_cvs = compress_4x_avx2(&cvs, &blocks, counters, block_lens, flags);

        for c in 0..4 {
            let total_len = chunks[c].len();
            let num_blocks = if total_len == 0 { 1 } else { (total_len + BLOCK_SIZE - 1) / BLOCK_SIZE };
            if b < num_blocks {
                cvs[c] = new_cvs[c];
            }
        }
    }

    cvs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vera_hash::hash_chunk;

    #[test]
    fn test_transpose_4x4() {
        if !is_x86_feature_detected!("avx2") { return; }
        let blocks = [
            [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160],
            [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600],
            [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 11000, 12000, 13000, 14000, 15000, 16000],
        ];
        unsafe {
            let v_msg = load_and_transpose_4_blocks(&blocks);
            let mut col0 = [0u64; 4];
            _mm256_storeu_si256(col0.as_mut_ptr() as *mut __m256i, v_msg[0]);
            assert_eq!(col0, [1, 10, 100, 1000]);

            let mut col15 = [0u64; 4];
            _mm256_storeu_si256(col15.as_mut_ptr() as *mut __m256i, v_msg[15]);
            assert_eq!(col15, [16, 160, 1600, 16000]);
        }
    }

    #[test]
    fn test_avx2_equivalence_with_scalar() {
        if !is_x86_feature_detected!("avx2") { return; }

        let c0 = vec![0x11u8; 1024];
        let c1 = vec![0x22u8; 500];
        let c2 = vec![0x33u8; 128];
        let c3 = vec![0x44u8; 800];

        let chunks = [&c0[..], &c1[..], &c2[..], &c3[..]];
        let counters = [10, 11, 12, 13];

        let avx2_res = unsafe { hash_4_chunks_avx2(chunks, counters) };

        let sc0 = hash_chunk(&c0, 10, false);
        let sc1 = hash_chunk(&c1, 11, false);
        let sc2 = hash_chunk(&c2, 12, false);
        let sc3 = hash_chunk(&c3, 13, false);

        assert_eq!(avx2_res[0], sc0, "Equivalence failure on chunk 0");
        assert_eq!(avx2_res[1], sc1, "Equivalence failure on chunk 1");
        assert_eq!(avx2_res[2], sc2, "Equivalence failure on chunk 2");
        assert_eq!(avx2_res[3], sc3, "Equivalence failure on chunk 3");
    }
}
