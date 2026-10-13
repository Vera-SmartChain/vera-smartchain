//! # VERA Engine v2: AI-Native Execution Engine
//!
//! Computation representation designed to be generated, parsed,
//! optimized, and verified by AI systems, with direct x86-64 execution.

pub mod graph;
pub mod canonical;
pub mod multi_agent;
pub mod vera_hash;
pub mod vera_hash_avx2;
pub mod tensor_hypercube;
pub mod salience_engine;
pub mod generative_digest;
pub mod vera_pack;
pub mod vera_compact;
pub mod vera_dict;

#[cfg(windows)]
pub mod jit_x86;

// Convenient top-level re-exports
pub use graph::{ComputationGraph, Node, NodeId, Op};
pub use canonical::{canonical_hash, normalize};
pub use multi_agent::{simulate_multi_agent_pipeline, generate_json_schema, VerificationResult};
pub use vera_hash::{VeraHasher, hash as vera_hash_256, hash512 as vera_hash_512, hash_parallel as vera_hash_parallel};
pub use tensor_hypercube::contract_hypercube;
pub use salience_engine::{hash_with_salience, detect_chunk_salience, BlockSalience};
pub use generative_digest::{generative_state_digest, GenerativeIdentity};
pub use vera_pack::{vera_pack, vera_unpack, OP_VERA_PACK, OP_VERA_UNPACK};
pub use vera_compact::{vera_compact, vera_expand, VeraCompressionMode, OP_VERA_COMPACT, OP_VERA_EXPAND};
pub use vera_dict::{VeraSessionCompressor, VeraSessionDecompressor, OP_VERA_DICT_INIT, OP_VERA_DICT_PACK};

#[cfg(windows)]
pub use jit_x86::JitFunction;
