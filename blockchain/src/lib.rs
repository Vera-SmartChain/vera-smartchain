// ========================================================
// VERA BLOCKCHAIN & CONSENSUS ENGINE
// Verifiability, State Transitions, and Distributed Network Module
// ========================================================

/// Node release version, reported by web3_clientVersion, `vera_node` and `vera_cli`.
pub const NODE_VERSION: &str = "0.2.9.1-testnet";

pub mod account;
pub mod bisection;
pub mod block;
pub mod consensus;
pub mod csmt;
pub mod genesis;
pub mod identity;
pub mod network;
pub mod node;
pub mod p2p;
pub mod rpc;
pub mod state_transition;
pub mod storage;
pub mod tendermint;
pub mod tm_driver;
pub mod hw;
pub mod transaction;

pub use ed25519_dalek;
pub mod evm;
pub mod chain_hash;
pub use chain_hash::{hash256, ChainHasher};
pub mod validator_application;

