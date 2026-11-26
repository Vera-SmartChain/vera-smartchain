use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vera_blockchain::observe::*;

#[test]
fn client_text_cannot_forge_log_lines() {
    let line = rpc_line("eth_x\n✅ [TM] Block #9 COMMITTED", "", "direct", Duration::ZERO, Some((-32601, "the method a\r\n\u{1b}[2J does not exist"))).unwrap();
    assert!(!line.contains('\n') && !line.contains('\r') && !line.contains('\u{1b}'), "{line:?}");
    assert!(clean(&"a".repeat(500), 64).len() <= 67);
}

#[test]
fn client_address_comes_from_the_proxy_header_only() {
    let req = "POST / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n{\"x-forwarded-for\": \"1.1.1.1\"}";
    assert_eq!(client_from_headers(req), "203.0.113.7");
    assert_eq!(client_from_headers("POST / HTTP/1.1\r\n\r\nx-forwarded-for: 1.1.1.1"), "direct");
    assert_eq!(client_from_headers("{\"method\":\"eth_blockNumber\"}"), "direct");
    let hostile = client_from_headers("POST / HTTP/1.1\r\nx-forwarded-for: 1.2.3.4 <script>\r\n\r\n");
    assert!(hostile.starts_with("1.2.3.4") && !hostile.contains('<'), "{hostile}");
}

#[test]
fn only_refused_or_slow_calls_produce_a_line() {
    assert!(rpc_line("eth_blockNumber", "", "direct", Duration::from_millis(999), None).is_none());
    let slow = rpc_line("eth_getLogs", "from=0x0 to=latest", "203.0.113.7", Duration::from_millis(2500), None).unwrap();
    assert!(slow.contains("[RPC] method=eth_getLogs slow") && slow.contains("ms=2500") && slow.contains("client=203.0.113.7") && slow.contains("from=0x0"));
    let refused = rpc_line("eth_getLogs", "", "direct", Duration::ZERO, Some((-32005, "query takes too long"))).unwrap();
    // monitors match this prefix
    assert!(refused.starts_with("⚠️ [RPC] method=eth_getLogs code=-32005 error=query takes too long"));
}

#[test]
fn query_description_has_range_and_contract_but_no_payloads() {
    let d = describe_call("eth_getLogs", &json!([{"fromBlock":"0x0","toBlock":"latest","address":["0xaa","0xbb"],"topics":["0xcc"]}]));
    assert_eq!(d, "from=0x0 to=latest blockHash=- address=0xaa(+1) topic0=0xcc");
    assert_eq!(describe_call("eth_sendRawTransaction", &json!(["0xdeadbeef"])), "");
    assert_eq!(describe_call("eth_call", &json!([{"data":"0xdeadbeef"}])), "");
    // malformed parameters must not panic
    for p in [json!(null), json!([]), json!([5]), json!([{"topics": 7, "address": {}}]), json!({"a":1})] {
        let _ = describe_call("eth_getLogs", &p);
    }
}

#[test]
fn log_budget_caps_lines_and_counts_the_rest() {
    let b = LogBudget::new(3, Duration::from_secs(60));
    let t = Instant::now();
    assert_eq!((0..10).filter(|_| b.admit(t).is_some()).count(), 3);
    assert_eq!(b.admit(t + Duration::from_secs(61)), Some(7));
    assert_eq!(b.admit(t + Duration::from_secs(62)), Some(0));
}

fn watch(block_for: Duration) -> Vec<StallEvent> {
    // one worker, as on a single-vCPU server
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    rt.block_on(async move {
        spawn_stall_watchdog(Duration::from_millis(300), move |e| sink.lock().unwrap().push(e));
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            std::thread::sleep(block_for); // blocks the only worker
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
    });
    let events = seen.lock().unwrap().clone();
    events
}

#[test]
fn watchdog_reports_a_blocked_runtime_and_its_recovery() {
    let events = watch(Duration::from_millis(900));
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(matches!(events[0], StallEvent::Stalled(d) if d >= Duration::from_millis(300)), "{events:?}");
    assert!(matches!(events[1], StallEvent::Recovered(d) if d >= Duration::from_millis(800)), "{events:?}");
}

#[test]
fn watchdog_is_quiet_on_a_healthy_runtime() {
    assert!(watch(Duration::from_millis(20)).is_empty());
}
