//! RPC requests that walk block files must not stall the node.
//! `current_thread` matches a 1 vCPU server: one async worker serves RPC, P2P and consensus.
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use vera_blockchain::account::{EvmLog, ExecutionReceipt};
use vera_blockchain::genesis::GenesisConfig;
use vera_blockchain::node::{FullNode, SharedNode};
use vera_blockchain::rpc::{RpcHandler, RpcRequest, RpcResponse};

const BLOCKS: u64 = 600;
const RECEIPTS: usize = 100;

async fn call(node: &SharedNode, method: &str, params: Value) -> RpcResponse {
    let req = RpcRequest { jsonrpc: "2.0".into(), id: json!(1), method: method.into(), params };
    RpcHandler::handle(node, req).await
}

/// Starts `method` in another task and returns how long eth_blockNumber took meanwhile.
async fn latency_during(node: &SharedNode, method: &'static str, params: Value) -> (Duration, RpcResponse) {
    let n = node.clone();
    let slow = tokio::spawn(async move { call(&n, method, params).await });
    let started = Instant::now();
    tokio::task::yield_now().await; // let the slow request start
    call(node, "eth_blockNumber", json!([])).await;
    let latency = started.elapsed();
    (latency, slow.await.unwrap())
}

#[tokio::test(flavor = "current_thread")]
async fn rpc_block_scans_do_not_stall_the_node() {
    let dir = std::env::temp_dir().join(format!("vera_rpc_scan_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (genesis, key) = GenesisConfig::default_testnet();
    let mut node = FullNode::load_or_init(&dir, &genesis, Some(key)).unwrap();

    let template = node.storage.load_block(0).unwrap().unwrap();
    let log = EvmLog { address: [7u8; 32], topics: vec![[9u8; 32]; 2], data: vec![1u8; 128] };
    let receipt = ExecutionReceipt {
        tx_hash: [1u8; 32], success: true, gas_used: 21_000,
        state_root: [0u8; 32], trace_root: [0u8; 32], logs: vec![log],
    };
    let mut hashes = vec![template.hash()];
    for h in 1..=BLOCKS {
        let mut block = template.clone();
        block.header.height = h;
        block.receipts = vec![receipt.clone(); RECEIPTS];
        node.storage.save_block(&block).unwrap();
        hashes.push(block.hash());
    }
    node.height = BLOCKS;
    node.latest_block_hash = hashes[BLOCKS as usize];
    let node: SharedNode = Arc::new(tokio::sync::RwLock::new(node));

    let mut failures: Vec<String> = Vec::new();
    let mut check = |ok: bool, what: String| if !ok { failures.push(what) };
    let limit = Duration::from_millis(100);
    let full = json!([{ "fromBlock": "0x0", "toBlock": "latest" }]);
    let unknown = format!("0x{}", "ab".repeat(32));

    // 1. A full-range eth_getLogs
    let (lat, _) = latency_during(&node, "eth_getLogs", full.clone()).await;
    check(lat < limit, format!("eth_blockNumber waited {lat:?} behind eth_getLogs"));
    // 2. A block hash that does not exist (eth_getBlockByHash, then eth_getLogs)
    let (lat, res) = latency_during(&node, "eth_getBlockByHash", json!([unknown, false])).await;
    check(lat < limit, format!("eth_blockNumber waited {lat:?} behind eth_getBlockByHash"));
    check(res.result == Some(Value::Null), "unknown block hash must return null".into());
    let (lat, res) = latency_during(&node, "eth_getLogs", json!([{ "blockHash": unknown }])).await;
    check(lat < limit, format!("eth_blockNumber waited {lat:?} behind eth_getLogs(blockHash)"));
    check(res.result == Some(json!([])), "logs of an unknown block hash must be empty".into());
    // 3. The node lock is free while a scan runs, so a block can still be committed
    let n = node.clone();
    let p = full.clone();
    let slow = tokio::spawn(async move { call(&n, "eth_getLogs", p).await });
    tokio::task::yield_now().await;
    let started = Instant::now();
    drop(node.write().await);
    check(started.elapsed() < limit, format!("write lock waited {:?}", started.elapsed()));
    // 4. A second large scan is refused while the first one runs
    if !slow.is_finished() {
        let second = call(&node, "eth_getLogs", full.clone()).await;
        check(second.error.as_ref().map(|e| e.code) == Some(-32005), format!("second scan: {:?}", second.error));
        // small ranges still work meanwhile
        let small = call(&node, "eth_getLogs", json!([{ "fromBlock": "0x1", "toBlock": "0x2" }])).await;
        check(small.error.is_none(), format!("small range during a scan: {:?}", small.error));
        // the explorer's home page request
        let recent = call(&node, "vera_getRecentBlocks", json!([25])).await;
        check(recent.error.is_none(), format!("recent blocks during a scan: {:?}", recent.error));
    }
    let _ = slow.await.unwrap();

    // 5. Results are unchanged
    let res = call(&node, "eth_getLogs", json!([{ "fromBlock": "0xa", "toBlock": "0xc" }])).await;
    check(res.result.as_ref().and_then(|r| r.as_array()).map(|a| a.len()) == Some(3 * RECEIPTS), "3 blocks of logs".into());
    let old = format!("0x{}", hex::encode(hashes[5]));
    let res = call(&node, "eth_getBlockByHash", json!([old, false])).await;
    check(res.result.as_ref().map(|r| r["number"] == "0x5") == Some(true), "old block by hash".into());
    let res = call(&node, "eth_getLogs", json!([{ "blockHash": old }])).await;
    check(res.result.as_ref().and_then(|r| r.as_array()).map(|a| a.len()) == Some(RECEIPTS), "logs by old block hash".into());
    let genesis_hash = format!("0x{}", hex::encode(hashes[0]));
    let res = call(&node, "eth_getBlockByHash", json!([genesis_hash, false])).await;
    check(res.result == Some(Value::Null), "genesis by hash keeps returning null".into());
    // 6. Too many matching logs
    let res = call(&node, "eth_getLogs", json!([{ "fromBlock": "0x1", "toBlock": "0x96" }])).await;
    check(res.error.as_ref().map(|e| e.code == -32005 && e.message.contains("10000")) == Some(true), format!("result limit: {:?}", res.error));
    // 7. Recent blocks are capped
    let res = call(&node, "vera_getRecentBlocks", json!([1_000_000])).await;
    check(res.result.as_ref().and_then(|r| r.as_array()).map(|a| a.len()) == Some(100), "recent blocks cap".into());
    // 8. Unknown methods use the wording ethers.js recognises
    let res = call(&node, "eth_newFilter", json!([{}])).await;
    let err = res.error.unwrap();
    check(err.code == -32601 && err.message == "the method eth_newFilter does not exist/is not available", err.message.clone());

    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "{failures:#?}");
}
