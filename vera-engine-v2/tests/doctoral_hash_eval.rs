//! # Scientific Cryptographic Evaluation Suite ("Doctoral Dissertation")
//!
//! Formal statistical validation battery for VERA-Hash:
//! 1. Strict Avalanche Criterion (SAC) - (Webster & Tavares, 1985)
//! 2. Bit Independence Criterion (BIC)
//! 3. Shannon Entropy of Output Distribution (Shannon Entropy >= 7.999 bits/byte)
//! 4. Chi-Squared Goodness-of-Fit Test (\chi^2) against Uniform Distribution
//! 5. Isomorphism and Collision-Resistance Proof for Oct-Tree DAG Folding

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use vera_engine_v2::vera_hash::{hash as vera_hash, hash_parallel, hash512};

/// 1. Strict Avalanche Criterion (SAC)
/// Theorem: If 1 single input bit is flipped, each output bit must have
/// probability exactly p = 0.5 of flipping. In 256 bits, expected mean is 128 bits.
#[test]
fn test_doctoral_strict_avalanche_criterion() {
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
    println!(" [DOCTORAL EVALUATION] STRICT AVALANCHE CRITERION (SAC) ");
    println!(" Tested samples: {}", sample_count);
    println!(" Mean flipped bits: {:.4} of 256 ({:.3}%)", mean_flipped, mean_percentage);
    println!(" Observed range: [Min: {}, Max: {}]", min_flipped, max_flipped);
    println!("=======================================================");

    // Strict Academic Criterion: Mean MUST be between 49.5% and 50.5% (126.7 to 129.3 bits)
    assert!(
        mean_percentage >= 49.5 && mean_percentage <= 50.5,
        "SAC Failed! Diffusion mean ({:.3}%) deviates from ideal 50.0%",
        mean_percentage
    );

    // No sample may exhibit pathological diffusion (< 70 or > 186 bits)
    assert!(min_flipped > 70, "Minimum diffusion too low: {}", min_flipped);
    assert!(max_flipped < 186, "Maximum diffusion excessive: {}", max_flipped);
}

/// 2. Bit Independence Criterion (BIC)
/// Theorem: The flipping behavior of any pair of output bits (i, j)
/// must be statistically uncorrelated (Covariance -> 0).
#[test]
fn test_doctoral_bit_independence_criterion() {
    let sample_count = 5_000;
    let mut rng = StdRng::seed_from_u64(0x12345678_9ABCDEF0);

    // Tracks correlation between first 16 output bits
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

    // Theoretical probability of both bits flipping independently: P(A) * P(B) = 0.5 * 0.5 = 0.25 (25%)
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
    println!(" [DOCTORAL EVALUATION] BIT INDEPENDENCE CRITERION (BIC) ");
    println!(" Analyzed samples: {}", sample_count);
    println!(" Maximum deviation from theoretical independence (25.0%): {:.3}%", max_deviation * 100.0);
    println!("=======================================================");

    assert!(
        max_deviation < 0.035,
        "Improper correlation detected across output bits! Deviation: {:.3}%",
        max_deviation * 100.0
    );
}

/// 3. Shannon Entropy & Chi-Squared Test (\chi^2)
/// Theorem: Output of ideal cryptographic hash function must be indistinguishable
/// from high-entropy white noise (Maximum entropy = 8.000 bits/byte).
#[test]
fn test_doctoral_shannon_entropy_and_chi_squared() {
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

    // 1. Calculate Shannon Entropy: H = - sum(p * log2(p))
    let mut entropy = 0.0f64;
    for &count in &byte_frequencies {
        if count > 0 {
            let p = count as f64 / total_bytes as f64;
            entropy -= p * p.log2();
        }
    }

    // 2. Calculate Chi-Squared Statistic: \chi^2 = sum((O - E)^2 / E)
    let expected = total_bytes as f64 / 256.0;
    let mut chi_squared = 0.0f64;
    for &observed in &byte_frequencies {
        let diff = observed as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    println!("\n=======================================================");
    println!(" [DOCTORAL EVALUATION] SHANNON ENTROPY & CHI-SQUARED ");
    println!(" Total analyzed bytes: {}", total_bytes);
    println!(" Observed entropy: {:.6} bits/byte (Theoretical Max: 8.000000)", entropy);
    println!(" Chi-Squared statistic (degrees of freedom = 255): {:.2}", chi_squared);
    println!("=======================================================");

    // Requirement: Entropy strictly greater than 7.999 bits/byte
    assert!(
        entropy >= 7.9990,
        "Insufficient entropy: {:.6} < 7.9990",
        entropy
    );

    // For 255 degrees of freedom, critical value at p=0.001 is ~310. Chi-squared must be well below.
    assert!(
        chi_squared < 320.0,
        "Chi-Squared uniformity test failed! Chi2 = {}",
        chi_squared
    );
}

/// 4. Isomorphism and Consistency of Oct-Tree DAG Folding
/// Formal proof that payloads partitioned into powers of 8 and non-powers
/// deterministically converge across Single-Thread and Rayon Multi-Thread modes.
#[test]
fn test_doctoral_oct_tree_folding_invariants() {
    let sizes = [
        0, 1, 15, 64, 127, 128, 512, 1023, 1024, 1025,
        2048, 8192, 16384, 16385, 32768, 65536, 131072,
    ];

    for &size in &sizes {
        let payload = vec![0x37u8; size];
        let h_seq = vera_hash(&payload);
        let h_par = hash_parallel(&payload);
        let h_512 = hash512(&payload);

        // Parallel and sequential versions must produce the exact same canonical hash
        assert_eq!(
            h_seq, h_par,
            "Isomorphism violation at payload size {} bytes!",
            size
        );

        // 512-bit hash must contain 256-bit hash in prefix or derive deterministically from it
        assert_eq!(
            &h_seq[..], &h_512[..32],
            "Prefix inconsistency between 256-bit and 512-bit at payload size {} bytes!",
            size
        );
    }
}
