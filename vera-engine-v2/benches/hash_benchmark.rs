use std::time::Instant;
use vera_engine_v2::vera_hash::{hash as vera_hash, hash_parallel as vera_hash_par};

fn run_bench_size(name: &str, size_bytes: usize, iterations: usize) {
    println!("\n=========================================================================================");
    println!(" [BENCHMARK] Payload: {} ({:.2} MB) | {} iterations", name, size_bytes as f64 / (1024.0 * 1024.0), iterations);
    println!("=========================================================================================");

    // Allocate and populate test buffer with non-trivial pattern
    let mut data = vec![0u8; size_bytes];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ((i * 31) ^ (i >> 3) ^ 0xA5) as u8;
    }

    // Warm-up
    let _ = blake3::hash(&data[..1024.min(size_bytes)]);
    let _ = vera_hash(&data[..1024.min(size_bytes)]);

    // 1. BLAKE3 (Single-Thread)
    let start_b3_single = Instant::now();
    for _ in 0..iterations {
        let h = blake3::hash(&data);
        std::hint::black_box(h);
    }
    let elapsed_b3_single = start_b3_single.elapsed();
    let total_gb = (size_bytes as f64 * iterations as f64) / (1024.0 * 1024.0 * 1024.0);
    let speed_b3_single = total_gb / elapsed_b3_single.as_secs_f64();

    // 2. VERA-HASH (Single-Thread ARX-64)
    let start_vh_single = Instant::now();
    for _ in 0..iterations {
        let h = vera_hash(&data);
        std::hint::black_box(h);
    }
    let elapsed_vh_single = start_vh_single.elapsed();
    let speed_vh_single = total_gb / elapsed_vh_single.as_secs_f64();

    // 3. BLAKE3 (Rayon Multi-Thread Parallel)
    let start_b3_par = Instant::now();
    for _ in 0..iterations {
        let mut hasher = blake3::Hasher::new();
        hasher.update_rayon(&data);
        let h = hasher.finalize();
        std::hint::black_box(h);
    }
    let elapsed_b3_par = start_b3_par.elapsed();
    let speed_b3_par = total_gb / elapsed_b3_par.as_secs_f64();

    // 4. VERA-HASH (Oct-Tree DAG Folding Multi-Thread Rayon)
    let start_vh_par = Instant::now();
    for _ in 0..iterations {
        let h = vera_hash_par(&data);
        std::hint::black_box(h);
    }
    let elapsed_vh_par = start_vh_par.elapsed();
    let speed_vh_par = total_gb / elapsed_vh_par.as_secs_f64();

    println!(" Single-Thread Mode:");
    println!("   - BLAKE3:    {:>8.3} GB/s  ({:.2?})", speed_b3_single, elapsed_b3_single / iterations as u32);
    println!("   - VERA-Hash: {:>8.3} GB/s  ({:.2?})  [Ratio: {:.2}x]", speed_vh_single, elapsed_vh_single / iterations as u32, speed_vh_single / speed_b3_single);
    println!();
    println!(" Multi-Thread Parallel Mode:");
    println!("   - BLAKE3 (Rayon):                   {:>8.3} GB/s  ({:.2?})", speed_b3_par, elapsed_b3_par / iterations as u32);
    println!("   - VERA-Hash (Oct-Tree DAG Folding): {:>8.3} GB/s  ({:.2?})  [Ratio: {:.2}x]", speed_vh_par, elapsed_vh_par / iterations as u32, speed_vh_par / speed_b3_par);
}

fn main() {
    println!("\n#########################################################################################");
    println!("#        HIGH-PERFORMANCE BENCHMARK: VERA-HASH (ARX-64) vs BLAKE3 (STATE-OF-THE-ART)    #");
    println!("#########################################################################################");
    println!(" Hardware detection: {} threads available in threadpool", rayon::current_num_threads());

    // 1 MB
    run_bench_size("1 Megabyte", 1024 * 1024, 100);

    // 10 MB
    run_bench_size("10 Megabytes", 10 * 1024 * 1024, 20);

    // 100 MB
    run_bench_size("100 Megabytes", 100 * 1024 * 1024, 5);

    println!("\n=========================================================================================");
    println!(" [CONCLUSION] Benchmark finished successfully!");
    println!("=========================================================================================\n");
}
