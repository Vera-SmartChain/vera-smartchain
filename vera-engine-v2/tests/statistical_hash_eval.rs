//! # Statistical Sanity Evaluation Suite for VERA-Hash
//!
//! Note: These tests verify statistical pseudorandomness and distribution sanity
//! (e.g. avalanche, bit independence, entropy), NOT cryptographic security proofs.
//!
//! 1. Strict Avalanche Criterion (SAC) - (Webster & Tavares, 1985)
//! 2. Bit Independence Criterion (BIC)
//! 3. Shannon Entropy of Output Distribution (Shannon Entropy >= 7.999 bits/byte)
//! 4. Chi-Squared Goodness-of-Fit Test (\chi^2) against Uniform Distribution
//! 5. Statistical Consistency of Oct-Tree DAG Folding
//! 6. 1024 B Regression Test (all sizes 0 to 4096 bytes: hash(x) == VeraHasher(x))

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use vera_engine_v2::vera_hash::{hash as vera_hash, hash_parallel, hash512, VeraHasher};

/// 1. Strict Avalanche Criterion (SAC) - Statistical Sanity Check
/// When 1 single input bit is flipped, each output bit should have
/// probability ~0.5 of flipping (in 256 bits, expected mean ~128 bits).
#[test]
fn test_statistical_strict_avalanche_criterion() {
    let sample_count = 10_000;
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF_CAFE1337);

    let mut total_flipped_bits: u64 = 0;
    let mut min_flipped = 256usize;
    let mut max_flipped = 0usize;
    let mut flip_counts = vec![0u32; 257];

    for _ in 0..sample_count {
        let mut msg = [0u8; 64]; // 512-bit block
        rng.fill_bytes(&mut msg);

        let h1 = vera_hash(&msg);

        // Flip exactly 1 bit at random position (0..512)
        let bit_to_flip = (rng.next_u32() % 512) as usize;
        let mut msg_flipped = msg;
        msg_flipped[bit_to_flip / 8] ^= 1 << (bit_to_flip % 8);

        let h2 = vera_hash(&msg_flipped);

        // Compute Hamming distance between outputs
        let mut flipped = 0usize;
        for i in 0..32 {
            flipped += (h1[i] ^ h2[i]).count_ones() as usize;
        }

        total_flipped_bits += flipped as u64;
        min_flipped = min_flipped.min(flipped);
        max_flipped = max_flipped.max(flipped);
        flip_counts[flipped] += 1;
    }

    let mean_flipped = total_flipped_bits as f64 / sample_count as f64;
    let mean_percentage = (mean_flipped / 256.0) * 100.0;

    println!("\n=======================================================");
    println!(" [STATISTICAL SANITY] STRICT AVALANCHE CRITERION (SAC) ");
    println!(" Tested samples: {}", sample_count);
    println!(" Mean flipped bits: {:.4} of 256 ({:.3}%)", mean_flipped, mean_percentage);
    println!(" Observed range: [Min: {}, Max: {}]", min_flipped, max_flipped);
    println!("=======================================================");

    assert!(
        mean_percentage >= 49.5 && mean_percentage <= 50.5,
        "SAC Failed! Diffusion mean ({:.3}%) deviates from ideal 50.0%",
        mean_percentage
    );

    assert!(min_flipped > 70, "Minimum diffusion too low: {}", min_flipped);
    assert!(max_flipped < 186, "Maximum diffusion excessive: {}", max_flipped);
}

/// 2. Bit Independence Criterion (BIC) - Statistical Sanity Check
#[test]
fn test_statistical_bit_independence_criterion() {
    let sample_count = 5_000;
    let mut rng = StdRng::seed_from_u64(0x12345678_9ABCDEF0);

    let num_tracked_bits = 16;
    let mut pair_both_flipped = vec![vec![0u32; num_tracked_bits]; num_tracked_bits];

    for _ in 0..sample_count {
        let mut msg = [0u8; 64];
        rng.fill_bytes(&mut msg);

        let h1 = vera_hash(&msg);

        let bit_to_flip = (rng.next_u32() % 512) as usize;
        let mut msg_flipped = msg;
        msg_flipped[bit_to_flip / 8] ^= 1 << (bit_to_flip % 8);

        let h2 = vera_hash(&msg_flipped);

        let mut diff_bits = [false; 256];
        for byte_idx in 0..32 {
            let xor_val = h1[byte_idx] ^ h2[byte_idx];
            for b in 0..8 {
                diff_bits[byte_idx * 8 + b] = (xor_val & (1 << b)) != 0;
            }
        }

        for i in 0..num_tracked_bits {
            for j in 0..num_tracked_bits {
                if diff_bits[i] && diff_bits[j] {
                    pair_both_flipped[i][j] += 1;
                }
            }
        }
    }

    let mut max_deviation = 0.0f64;
    for i in 0..num_tracked_bits {
        for j in 0..num_tracked_bits {
            if i != j {
                let prob = pair_both_flipped[i][j] as f64 / sample_count as f64;
                let deviation = (prob - 0.25).abs();
                max_deviation = max_deviation.max(deviation);
            }
        }
    }

    println!("\n=======================================================");
    println!(" [STATISTICAL SANITY] BIT INDEPENDENCE CRITERION (BIC) ");
    println!(" Analyzed samples: {}", sample_count);
    println!(" Maximum deviation from theoretical independence (25.0%): {:.3}%", max_deviation * 100.0);
    println!("=======================================================");

    assert!(
        max_deviation < 0.035,
        "Improper correlation detected across output bits! Deviation: {:.3}%",
        max_deviation * 100.0
    );
}

/// 3. Shannon Entropy & Chi-Squared Test (\chi^2) - Statistical Sanity Check
#[test]
fn test_statistical_shannon_entropy_and_chi_squared() {
    let iterations = 20_000;
    let mut byte_frequencies = [0u64; 256];
    let total_bytes = iterations * 32;

    for i in 0..iterations {
        let seed = (i as u64).to_le_bytes();
        let h = vera_hash(&seed);
        for &byte in &h {
            byte_frequencies[byte as usize] += 1;
        }
    }

    let mut entropy = 0.0f64;
    for &count in &byte_frequencies {
        if count > 0 {
            let p = count as f64 / total_bytes as f64;
            entropy -= p * p.log2();
        }
    }

    let expected = total_bytes as f64 / 256.0;
    let mut chi_squared = 0.0f64;
    for &observed in &byte_frequencies {
        let diff = observed as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    println!("\n=======================================================");
    println!(" [STATISTICAL SANITY] SHANNON ENTROPY & CHI-SQUARED ");
    println!(" Total analyzed bytes: {}", total_bytes);
    println!(" Observed entropy: {:.6} bits/byte (Theoretical Max: 8.000000)", entropy);
    println!(" Chi-Squared statistic (degrees of freedom = 255): {:.2}", chi_squared);
    println!("=======================================================");

    assert!(
        entropy >= 7.9990,
        "Insufficient entropy: {:.6} < 7.9990",
        entropy
    );

    assert!(
        chi_squared < 320.0,
        "Chi-Squared uniformity test failed! Chi2 = {}",
        chi_squared
    );
}

/// 4. Consistency of Oct-Tree DAG Folding
#[test]
fn test_statistical_oct_tree_folding_invariants() {
    let sizes = [
        0, 1, 15, 64, 127, 128, 512, 1023, 1024, 1025,
        2048, 8192, 16384, 16385, 32768, 65536, 131072,
    ];

    for &size in &sizes {
        let payload = vec![0x37u8; size];
        let h_seq = vera_hash(&payload);
        let h_par = hash_parallel(&payload);
        let h_512 = hash512(&payload);

        assert_eq!(
            h_seq, h_par,
            "Consistency violation at payload size {} bytes!",
            size
        );

        assert_eq!(
            &h_seq[..], &h_512[..32],
            "Prefix inconsistency between 256-bit and 512-bit at payload size {} bytes!",
            size
        );
    }
}

/// 5. 1024 B Regression Test: hash(x) == VeraHasher(x) for all sizes from 0 to 4096 bytes
#[test]
fn test_verahash_1024b_regression_all_sizes_0_to_4096() {
    let mut rng = StdRng::seed_from_u64(0x1024_BEEF_C0DE);
    let mut max_buf = vec![0u8; 4096];
    rng.fill_bytes(&mut max_buf);

    for size in 0..=4096 {
        let slice = &max_buf[..size];
        let h_oneshot = vera_hash(slice);

        let mut hasher = VeraHasher::new();
        hasher.update(slice);
        let h_incremental = hasher.finalize();

        assert_eq!(
            h_oneshot, h_incremental,
            "Regression mismatch for size {} bytes! oneshot={:?}, incremental={:?}",
            size, h_oneshot, h_incremental
        );

        if size > 1 {
            let mid = size / 2;
            let mut chunked_hasher = VeraHasher::new();
            chunked_hasher.update(&slice[..mid]);
            chunked_hasher.update(&slice[mid..]);
            let h_chunked = chunked_hasher.finalize();
            assert_eq!(
                h_oneshot, h_chunked,
                "Chunked regression mismatch for size {} bytes (split at {})",
                size, mid
            );
        }
    }
}
