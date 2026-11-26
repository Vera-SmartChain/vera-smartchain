//! Operator visibility: which RPC calls were slow or refused (and who sent them), and a
//! watchdog that reports when the async runtime stops responding. Log output only; nothing
//! here touches consensus, execution or storage.

use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A call taking at least this long is logged even when it succeeds.
pub const SLOW_RPC: Duration = Duration::from_secs(1);
/// At most this many RPC lines per window; the rest are counted and summarized.
pub const RPC_LOG_LINES_PER_WINDOW: u32 = 60;
const RPC_LOG_WINDOW: Duration = Duration::from_secs(60);
/// The watchdog reports once the runtime has been silent for this long.
pub const STALL_THRESHOLD: Duration = Duration::from_secs(3);

/// Printable ASCII only and at most `max` characters, so text sent by a client cannot add
/// log lines or terminal control sequences.
pub fn clean(text: &str, max: usize) -> String {
    let mut out: String = text.chars().take(max).map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '?' }).collect();
    if text.chars().nth(max).is_some() {
        out.push_str("...");
    }
    out
}

/// Client address from the `X-Forwarded-For` header a reverse proxy sets, or `direct`.
/// It is only as trustworthy as whoever can reach the RPC port.
pub fn client_from_headers(request: &str) -> String {
    let head = request.split("\r\n\r\n").next().unwrap_or("");
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("x-forwarded-for") {
                let ip: String = value.trim().chars().take(64).filter(|c| c.is_ascii_hexdigit() || ".:, ".contains(*c)).collect();
                if !ip.is_empty() {
                    return ip;
                }
            }
        }
    }
    "direct".to_string()
}

/// What an expensive query asked for. Other methods get no parameters in the log (a signed
/// transaction or call data is not needed to find a slow caller).
pub fn describe_call(method: &str, params: &Value) -> String {
    let first = params.get(0);
    let field = |v: &Value| -> String {
        match v {
            Value::Null => "-".to_string(),
            Value::String(s) => clean(s, 66),
            Value::Array(a) => match a.first().and_then(Value::as_str) {
                Some(s) if a.len() == 1 => clean(s, 66),
                Some(s) => format!("{}(+{})", clean(s, 66), a.len() - 1),
                None => format!("[{} items]", a.len()),
            },
            other => clean(&other.to_string(), 66),
        }
    };
    match (method, first) {
        ("eth_getLogs", Some(f)) => format!(
            "from={} to={} blockHash={} address={} topic0={}",
            field(&f["fromBlock"]), field(&f["toBlock"]), field(&f["blockHash"]), field(&f["address"]), field(&f["topics"][0])
        ),
        ("vera_getRecentBlocks", Some(n)) => format!("limit={}", field(n)),
        _ => String::new(),
    }
}

/// Fixed-window limit for log lines.
pub struct LogBudget {
    state: Mutex<(Instant, u32, u64)>, // window start, lines printed, lines suppressed
    max: u32,
    window: Duration,
}

impl LogBudget {
    pub fn new(max: u32, window: Duration) -> Self {
        Self { state: Mutex::new((Instant::now(), 0, 0)), max, window }
    }

    /// `Some(n)`: print the line; `n` lines were suppressed in the window that just ended.
    pub fn admit(&self, now: Instant) -> Option<u64> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut ended = 0;
        if now.saturating_duration_since(s.0) >= self.window {
            ended = s.2;
            *s = (now, 0, 0);
        }
        if s.1 < self.max {
            s.1 += 1;
            Some(ended)
        } else {
            s.2 += 1;
            None
        }
    }
}

fn rpc_budget() -> &'static LogBudget {
    static BUDGET: std::sync::OnceLock<LogBudget> = std::sync::OnceLock::new();
    BUDGET.get_or_init(|| LogBudget::new(RPC_LOG_LINES_PER_WINDOW, RPC_LOG_WINDOW))
}

/// The log line for a finished call, or `None` when it was neither refused nor slow.
pub fn rpc_line(method: &str, detail: &str, client: &str, took: Duration, error: Option<(i32, &str)>) -> Option<String> {
    let method = clean(method, 64);
    let mut line = match error {
        Some((code, message)) => format!("⚠️ [RPC] method={} code={} error={}", method, code, clean(message, 200)),
        None if took >= SLOW_RPC => format!("🐢 [RPC] method={} slow", method),
        None => return None,
    };
    line.push_str(&format!(" | ms={} client={}", took.as_millis(), client));
    if !detail.is_empty() {
        line.push(' ');
        line.push_str(detail);
    }
    Some(line)
}

/// Prints the line for a refused or slow call, within the log budget.
pub fn log_rpc(method: &str, detail: &str, client: &str, took: Duration, error: Option<(i32, &str)>) {
    if let Some(line) = rpc_line(method, detail, client, took, error) {
        if let Some(suppressed) = rpc_budget().admit(Instant::now()) {
            if suppressed > 0 {
                eprintln!("⚠️ [RPC] {} more refused or slow calls were not logged (limit {} per minute)", suppressed, RPC_LOG_LINES_PER_WINDOW);
            }
            eprintln!("{}", line);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallEvent {
    /// No heartbeat for at least this long, and still none.
    Stalled(Duration),
    /// The runtime answers again after being silent for about this long.
    Recovered(Duration),
}

/// Watches the current tokio runtime from a plain OS thread: a task records a heartbeat and
/// the thread reports when it stops (blocking work on the workers, CPU or memory pressure).
/// Both end when the runtime is dropped.
pub fn spawn_stall_watchdog<F>(threshold: Duration, report: F)
where
    F: Fn(StallEvent) + Send + 'static,
{
    let start = Instant::now();
    let beat = Arc::new(AtomicU64::new(0));
    let alive = Arc::new(());
    let (beat_task, alive_task) = (Arc::clone(&beat), Arc::clone(&alive));
    let period = (threshold / 10).max(Duration::from_millis(10));
    tokio::spawn(async move {
        let _alive = alive_task;
        loop {
            beat_task.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
            tokio::time::sleep(period).await;
        }
    });
    std::thread::spawn(move || {
        let mut silent_since: Option<u64> = None;
        while Arc::strong_count(&alive) > 1 {
            std::thread::sleep(period);
            let last = beat.load(Ordering::Relaxed);
            let age = Duration::from_millis((start.elapsed().as_millis() as u64).saturating_sub(last));
            match silent_since {
                None if age >= threshold => {
                    silent_since = Some(last);
                    report(StallEvent::Stalled(age));
                }
                Some(since) if last > since => {
                    silent_since = None;
                    report(StallEvent::Recovered(Duration::from_millis(last - since)));
                }
                _ => {}
            }
        }
    });
}
