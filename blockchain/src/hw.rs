//! Hardware profile, detected once at start-up: the node sizes its parallelism and caches
//! from what the machine (or its container / systemd slice) actually gives it, instead of
//! fixed numbers. Same binary on a 1-vCPU VPS and on a 32-core server.

use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    /// Threads the node may use for parallel work (signature verification, ...).
    pub threads: usize,
    /// Where `threads` came from (for the start-up log).
    pub threads_source: &'static str,
    /// Memory the process may use, in bytes (cgroup limit if set, else physical RAM).
    pub memory_bytes: u64,
    /// SIMD level the hashing / curve libraries can pick at run time.
    pub simd: &'static str,
}

impl HardwareProfile {
    fn detect() -> Self {
        let (threads, threads_source) = match std::env::var("VERA_THREADS").ok().and_then(|v| v.parse::<usize>().ok()) {
            Some(n) if n > 0 => (n, "VERA_THREADS"),
            // available_parallelism() honours CPU affinity and cgroup CPU quotas on Linux,
            // so a systemd CPUQuota or a container limit is reflected here.
            _ => (std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1), "available_parallelism"),
        };
        Self {
            threads: threads.clamp(1, 64),
            threads_source,
            memory_bytes: detect_memory_bytes(),
            simd: detect_simd(),
        }
    }

    /// Entries of the signature-verification cache: ~1% of usable memory at ~48 bytes
    /// per entry, between 50k and 2M.
    pub fn signature_cache_entries(&self) -> usize {
        ((self.memory_bytes / 100 / 48) as usize).clamp(50_000, 2_000_000)
    }
}

pub fn profile() -> &'static HardwareProfile {
    static P: OnceLock<HardwareProfile> = OnceLock::new();
    P.get_or_init(HardwareProfile::detect)
}

fn detect_memory_bytes() -> u64 {
    // cgroup v2 limit (systemd MemoryMax / container), when set
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        if let Ok(v) = s.trim().parse::<u64>() {
            return v;
        }
    }
    if let Ok(s) = std::fs::read_to_string("/proc/self/cgroup") {
        for line in s.lines() {
            if let Some(path) = line.strip_prefix("0::") {
                let f = format!("/sys/fs/cgroup{}/memory.max", path);
                if let Ok(v) = std::fs::read_to_string(&f).map(|s| s.trim().to_string()) {
                    if let Ok(v) = v.parse::<u64>() {
                        return v;
                    }
                }
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                if let Some(kb) = rest.split_whitespace().next().and_then(|v| v.parse::<u64>().ok()) {
                    return kb * 1024;
                }
            }
        }
    }
    1 << 30 // unknown: assume 1 GiB
}

fn detect_simd() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx512f") {
            return "AVX-512";
        }
        if std::is_x86_feature_detected!("avx2") {
            return "AVX2";
        }
        if std::is_x86_feature_detected!("sse4.1") {
            return "SSE4.1";
        }
        return "baseline x86-64";
    }
    #[cfg(target_arch = "aarch64")]
    {
        return "NEON";
    }
    #[allow(unreachable_code)]
    "baseline"
}
