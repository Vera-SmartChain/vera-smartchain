//! VIP-001: native document registry and governance-pegged fees.
//!
//! Active once `FeeParams` exist in state. The block executors write the default
//! parameters at the first block whose height reaches the chain's registry activation
//! height (`activate_if_due`). Before that, nothing in this module changes execution.
//!
//! Every malformed payload or failed check returns `Err`, so the whole transaction is
//! rejected and nothing is charged or written (fail-hard).

use crate::account::{Address, EvmLog};
use crate::chain_hash::hash256;
use crate::csmt::CSMT;

/// System address of the registry (no private key). Its 20-byte EVM form is 0x…1100.
pub const REGISTRY_SYSTEM_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x00,
];

/// CSMT key of this record: `hash256(b"VREG1/params")`. It is a hash, not an address, so no account
/// can ever sit on it (a transfer to a fixed low address could create an `Account` there and
/// break `load_state` for every later block). The test below pins the value.
pub const FEE_PARAMS_KEY: Address = [
    0x61, 0x1e, 0xc0, 0x5a, 0x5b, 0x84, 0x1a, 0xa6,
    0x5d, 0x18, 0xb6, 0x30, 0xcf, 0x96, 0x09, 0x0b,
    0x0a, 0xa1, 0xfe, 0xb6, 0x0f, 0x69, 0xcf, 0x91,
    0x4b, 0x61, 0xad, 0x42, 0xd9, 0x03, 0x86, 0x3d,
];

pub const MAGIC: &[u8; 5] = b"VREG1";

pub const OP_REGISTER: u8 = 0x01;
pub const OP_REGISTER_BATCH: u8 = 0x02;
pub const OP_REVOKE: u8 = 0x03;
pub const OP_SET_FEE: u8 = 0x10;
pub const OP_SET_ISSUER: u8 = 0x11;
pub const OP_REMOVE_ISSUER: u8 = 0x12;
pub const OP_SET_GAS_PRICE: u8 = 0x13;
pub const OP_SET_REGISTRAR: u8 = 0x14;

/// Hard ceilings, fixed per release. 100 VERA per document; 10^15 wei per gas
/// (21 VERA for a simple transfer).
pub const MAX_FEE_PER_ITEM_WEI: u128 = 100_000_000_000_000_000_000;
pub const MAX_MIN_GAS_PRICE_WEI: u64 = 1_000_000_000_000_000;
/// Minimum time between two changes of the same fee parameter (block timestamps).
pub const FEE_CHANGE_MIN_INTERVAL_SECS: u64 = 604_800;
pub const MAX_ISSUER_NAME_BYTES: usize = 96;

/// Initial parameters (reference price 1 VERA = R$ 1, set on 2026-11-17):
/// R$ 0.005 per 21,000-gas transfer and R$ 0.05 per document.
pub const DEFAULT_MIN_GAS_PRICE_WEI: u64 = 238_095_238_095;
pub const DEFAULT_FEE_PER_ITEM_WEI: u128 = 50_000_000_000_000_000;
pub const DEFAULT_MAX_BATCH_LEAVES: u32 = 10_000;

// ---------------------------------------------------------------------------------------
// Fixed-order binary encoding
// ---------------------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("registry: length overflow")?;
        if end > self.buf.len() {
            return Err(format!("registry: truncated payload (need {} bytes at offset {}, have {})", n, self.pos, self.buf.len()));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> Result<u128, String> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn b32(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn opt_b32(&mut self) -> Result<Option<[u8; 32]>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.b32()?)),
            f => Err(format!("registry: invalid option flag {}", f)),
        }
    }
    fn opt_u64(&mut self) -> Result<Option<u64>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            f => Err(format!("registry: invalid option flag {}", f)),
        }
    }
    fn end(&self) -> Result<(), String> {
        if self.pos != self.buf.len() {
            return Err(format!("registry: {} trailing bytes", self.buf.len() - self.pos));
        }
        Ok(())
    }
}

fn put_opt_b32(out: &mut Vec<u8>, v: &Option<[u8; 32]>) {
    match v {
        None => out.push(0),
        Some(b) => {
            out.push(1);
            out.extend_from_slice(b);
        }
    }
}

fn put_opt_u64(out: &mut Vec<u8>, v: &Option<u64>) {
    match v {
        None => out.push(0),
        Some(x) => {
            out.push(1);
            out.extend_from_slice(&x.to_le_bytes());
        }
    }
}

// ---------------------------------------------------------------------------------------
// State records
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeParams {
    pub min_gas_price_wei: u64,
    pub fee_per_item_wei: u128,
    pub last_gas_change_ts: u64,
    pub last_item_change_ts: u64,
    pub max_batch_leaves: u32,
    /// Address allowed to attest issuers. None = the governance address.
    pub registrar: Option<Address>,
}

impl Default for FeeParams {
    fn default() -> Self {
        Self {
            min_gas_price_wei: DEFAULT_MIN_GAS_PRICE_WEI,
            fee_per_item_wei: DEFAULT_FEE_PER_ITEM_WEI,
            last_gas_change_ts: 0,
            last_item_change_ts: 0,
            max_batch_leaves: DEFAULT_MAX_BATCH_LEAVES,
            registrar: None,
        }
    }
}

impl FeeParams {
    const VERSION: u8 = 1;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![Self::VERSION];
        out.extend_from_slice(&self.min_gas_price_wei.to_le_bytes());
        out.extend_from_slice(&self.fee_per_item_wei.to_le_bytes());
        out.extend_from_slice(&self.last_gas_change_ts.to_le_bytes());
        out.extend_from_slice(&self.last_item_change_ts.to_le_bytes());
        out.extend_from_slice(&self.max_batch_leaves.to_le_bytes());
        put_opt_b32(&mut out, &self.registrar);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(b);
        let v = r.u8()?;
        if v != Self::VERSION {
            return Err(format!("registry: unknown FeeParams version {}", v));
        }
        let p = Self {
            min_gas_price_wei: r.u64()?,
            fee_per_item_wei: r.u128()?,
            last_gas_change_ts: r.u64()?,
            last_item_change_ts: r.u64()?,
            max_batch_leaves: r.u32()?,
            registrar: r.opt_b32()?,
        };
        r.end()?;
        Ok(p)
    }
}

/// An attestation request carried by `SET_ISSUER`: the registrar states that an address
/// belongs to organization `issuer_id` from `valid_from_ts` to `valid_until_ts`.
/// The stored result is an `IssuerState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerRecord {
    pub issuer_id: [u8; 32],
    pub display_name: String,
    pub valid_from_ts: u64,
    pub valid_until_ts: u64,
}

/// Most attestation windows kept per issuer address.
pub const MAX_ISSUER_WINDOWS: usize = 32;

/// What the registry stores for an issuer address: its organization, the display name and
/// every attestation window it ever had, oldest first. Windows never overlap and past
/// windows never change, so a record verified once stays verified, and a record made while
/// the address was not attested never becomes verified later (no retroactive attestation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerState {
    pub issuer_id: [u8; 32],
    pub display_name: String,
    pub windows: Vec<(u64, u64)>,
}

impl IssuerState {
    const VERSION: u8 = 1;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![Self::VERSION];
        out.extend_from_slice(&self.issuer_id);
        out.push(self.display_name.len() as u8);
        out.extend_from_slice(self.display_name.as_bytes());
        out.push(self.windows.len() as u8);
        for (f, u) in &self.windows {
            out.extend_from_slice(&f.to_le_bytes());
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(b);
        let v = r.u8()?;
        if v != Self::VERSION {
            return Err(format!("registry: unknown IssuerState version {}", v));
        }
        let issuer_id = r.b32()?;
        let len = r.u8()? as usize;
        let name = std::str::from_utf8(r.take(len)?).map_err(|e| format!("registry: issuer name not UTF-8: {}", e))?.to_string();
        let n = r.u8()? as usize;
        let mut windows = Vec::with_capacity(n);
        for _ in 0..n {
            windows.push((r.u64()?, r.u64()?));
        }
        r.end()?;
        Ok(Self { issuer_id, display_name: name, windows })
    }

    /// True when a record made at `ts` counts as issued by this organization.
    pub fn covers(&self, ts: u64) -> bool {
        self.windows.iter().any(|&(f, u)| f <= ts && ts <= u)
    }

    /// True when the address is attested at `ts` or has a window starting later.
    pub fn is_current(&self, ts: u64) -> bool {
        self.windows.last().map_or(false, |&(_, u)| u >= ts)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocRecord {
    pub kind: u16,
    /// 0 = a single document; N >= 1 = Merkle root of a batch of N documents.
    pub leaf_count: u32,
    pub parent: Option<[u8; 32]>,
    pub height: u64,
    pub timestamp: u64,
    pub revoked_at: Option<u64>,
}

impl DocRecord {
    const VERSION: u8 = 1;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![Self::VERSION];
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&self.leaf_count.to_le_bytes());
        put_opt_b32(&mut out, &self.parent);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        put_opt_u64(&mut out, &self.revoked_at);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(b);
        let v = r.u8()?;
        if v != Self::VERSION {
            return Err(format!("registry: unknown DocRecord version {}", v));
        }
        let rec = Self {
            kind: r.u16()?,
            leaf_count: r.u32()?,
            parent: r.opt_b32()?,
            height: r.u64()?,
            timestamp: r.u64()?,
            revoked_at: r.opt_u64()?,
        };
        r.end()?;
        Ok(rec)
    }
}

pub fn issuer_key(addr: &Address) -> Address {
    let mut pre = b"VREG1/issuer".to_vec();
    pre.extend_from_slice(addr);
    hash256(&pre)
}

pub fn doc_key(registrant: &Address, doc_hash: &[u8; 32]) -> Address {
    let mut pre = b"VREG1/doc".to_vec();
    pre.extend_from_slice(registrant);
    pre.extend_from_slice(doc_hash);
    hash256(&pre)
}

/// Leaf hash of a batch: H(leaf_index_le_u32 || doc_hash). A verifier must reject any
/// leaf with `leaf_index >= leaf_count` of the registered batch.
pub fn batch_leaf_hash(leaf_index: u32, doc_hash: &[u8; 32]) -> [u8; 32] {
    let mut pre = leaf_index.to_le_bytes().to_vec();
    pre.extend_from_slice(doc_hash);
    hash256(&pre)
}

pub fn load_params(csmt: &CSMT) -> Result<Option<FeeParams>, String> {
    match csmt.get(&FEE_PARAMS_KEY) {
        Some(b) => FeeParams::from_bytes(b).map(Some),
        None => Ok(None),
    }
}

pub fn load_issuer(csmt: &CSMT, addr: &Address) -> Result<Option<IssuerState>, String> {
    match csmt.get(&issuer_key(addr)) {
        Some(b) => IssuerState::from_bytes(b).map(Some),
        None => Ok(None),
    }
}

pub fn load_doc(csmt: &CSMT, registrant: &Address, doc_hash: &[u8; 32]) -> Result<Option<DocRecord>, String> {
    match csmt.get(&doc_key(registrant, doc_hash)) {
        Some(b) => DocRecord::from_bytes(b).map(Some),
        None => Ok(None),
    }
}

/// Activation: writes the default `FeeParams` at the first executed block whose height
/// reaches `activation`. Must run before the block's transactions, on every executor.
/// Parameters that apply to a block at `height`: the stored ones, or the defaults when
/// that block is the first one at or above the activation height (it writes them before
/// its transactions). Mempool admission, mempool pruning and the RPC must use this with
/// `height = tip + 1`. Reading only the stored params would quote the old 1 gwei price
/// right up to activation, so every pending tx would be invalid in the activation block,
/// that block would never be built (no empty blocks) and the chain would stall.
pub fn effective_params(csmt: &CSMT, height: u64, activation: Option<u64>) -> Result<Option<FeeParams>, String> {
    match load_params(csmt)? {
        Some(p) => Ok(Some(p)),
        None if activation.map_or(false, |a| height >= a) => Ok(Some(FeeParams::default())),
        None => Ok(None),
    }
}

pub fn activate_if_due(csmt: &mut CSMT, height: u64, activation: Option<u64>) {
    if let Some(a) = activation {
        if height >= a && csmt.get(&FEE_PARAMS_KEY).is_none() {
            csmt.insert(FEE_PARAMS_KEY, FeeParams::default().to_bytes());
        }
    }
}

// ---------------------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryOp {
    Register { kind: u16, doc_hash: [u8; 32], parent: Option<[u8; 32]> },
    RegisterBatch { kind: u16, merkle_root: [u8; 32], leaf_count: u32 },
    Revoke { doc_hash: [u8; 32] },
    SetFee { fee_per_item_wei: u128 },
    SetGasPrice { min_gas_price_wei: u64 },
    SetIssuer { addr: Address, record: IssuerRecord },
    RemoveIssuer { addr: Address },
    SetRegistrar { addr: Address },
}

impl RegistryOp {
    pub fn parse(program: &[u8]) -> Result<Self, String> {
        if program.len() < MAGIC.len() + 1 || &program[..MAGIC.len()] != MAGIC {
            return Err("registry: payload must start with VREG1".to_string());
        }
        let mut r = Reader::new(&program[MAGIC.len()..]);
        let op = match r.u8()? {
            OP_REGISTER => RegistryOp::Register { kind: r.u16()?, doc_hash: r.b32()?, parent: r.opt_b32()? },
            OP_REGISTER_BATCH => RegistryOp::RegisterBatch { kind: r.u16()?, merkle_root: r.b32()?, leaf_count: r.u32()? },
            OP_REVOKE => RegistryOp::Revoke { doc_hash: r.b32()? },
            OP_SET_FEE => RegistryOp::SetFee { fee_per_item_wei: r.u128()? },
            OP_SET_GAS_PRICE => RegistryOp::SetGasPrice { min_gas_price_wei: r.u64()? },
            OP_SET_ISSUER => {
                let addr = r.b32()?;
                let issuer_id = r.b32()?;
                let valid_from_ts = r.u64()?;
                let valid_until_ts = r.u64()?;
                let len = r.u8()? as usize;
                let name = std::str::from_utf8(r.take(len)?).map_err(|e| format!("registry: issuer name not UTF-8: {}", e))?.to_string();
                RegistryOp::SetIssuer { addr, record: IssuerRecord { issuer_id, display_name: name, valid_from_ts, valid_until_ts } }
            }
            OP_REMOVE_ISSUER => RegistryOp::RemoveIssuer { addr: r.b32()? },
            OP_SET_REGISTRAR => RegistryOp::SetRegistrar { addr: r.b32()? },
            other => return Err(format!("registry: unknown opcode 0x{:02x}", other)),
        };
        r.end()?;
        Ok(op)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        match self {
            RegistryOp::Register { kind, doc_hash, parent } => {
                out.push(OP_REGISTER);
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(doc_hash);
                put_opt_b32(&mut out, parent);
            }
            RegistryOp::RegisterBatch { kind, merkle_root, leaf_count } => {
                out.push(OP_REGISTER_BATCH);
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(merkle_root);
                out.extend_from_slice(&leaf_count.to_le_bytes());
            }
            RegistryOp::Revoke { doc_hash } => {
                out.push(OP_REVOKE);
                out.extend_from_slice(doc_hash);
            }
            RegistryOp::SetFee { fee_per_item_wei } => {
                out.push(OP_SET_FEE);
                out.extend_from_slice(&fee_per_item_wei.to_le_bytes());
            }
            RegistryOp::SetGasPrice { min_gas_price_wei } => {
                out.push(OP_SET_GAS_PRICE);
                out.extend_from_slice(&min_gas_price_wei.to_le_bytes());
            }
            RegistryOp::SetIssuer { addr, record } => {
                out.push(OP_SET_ISSUER);
                out.extend_from_slice(addr);
                out.extend_from_slice(&record.issuer_id);
                out.extend_from_slice(&record.valid_from_ts.to_le_bytes());
                out.extend_from_slice(&record.valid_until_ts.to_le_bytes());
                out.push(record.display_name.len() as u8);
                out.extend_from_slice(record.display_name.as_bytes());
            }
            RegistryOp::RemoveIssuer { addr } => {
                out.push(OP_REMOVE_ISSUER);
                out.extend_from_slice(addr);
            }
            RegistryOp::SetRegistrar { addr } => {
                out.push(OP_SET_REGISTRAR);
                out.extend_from_slice(addr);
            }
        }
        out
    }

    /// Number of documents charged at `fee_per_item_wei`.
    pub fn items_charged(&self) -> u32 {
        match self {
            RegistryOp::Register { .. } | RegistryOp::Revoke { .. } => 1,
            RegistryOp::RegisterBatch { leaf_count, .. } => *leaf_count,
            _ => 0,
        }
    }

    fn topic(&self) -> [u8; 32] {
        let name: &[u8] = match self {
            RegistryOp::Register { .. } => b"VREG1.Register",
            RegistryOp::RegisterBatch { .. } => b"VREG1.RegisterBatch",
            RegistryOp::Revoke { .. } => b"VREG1.Revoke",
            RegistryOp::SetFee { .. } => b"VREG1.SetFee",
            RegistryOp::SetGasPrice { .. } => b"VREG1.SetGasPrice",
            RegistryOp::SetIssuer { .. } => b"VREG1.SetIssuer",
            RegistryOp::RemoveIssuer { .. } => b"VREG1.RemoveIssuer",
            RegistryOp::SetRegistrar { .. } => b"VREG1.SetRegistrar",
        };
        hash256(name)
    }
}

/// Registry fee of `op` under `params` (added to the gas fee, split 70/15/15).
pub fn registry_fee(op: &RegistryOp, params: &FeeParams) -> u128 {
    params.fee_per_item_wei.saturating_mul(op.items_charged() as u128)
}

fn check_fee_change(current: u128, new: u128, ceiling: u128, last_ts: u64, now_ts: u64, what: &str) -> Result<(), String> {
    if new == 0 {
        return Err(format!("registry: {} must be greater than zero", what));
    }
    if new > ceiling {
        return Err(format!("registry: {} {} above ceiling {}", what, new, ceiling));
    }
    if new < current / 2 || new > current.saturating_mul(2) {
        return Err(format!("registry: {} change {} -> {} exceeds 2x bound", what, current, new));
    }
    if last_ts != 0 && now_ts < last_ts.saturating_add(FEE_CHANGE_MIN_INTERVAL_SECS) {
        return Err(format!(
            "registry: {} changed at {}, next change allowed from {}",
            what, last_ts, last_ts.saturating_add(FEE_CHANGE_MIN_INTERVAL_SECS)
        ));
    }
    Ok(())
}

/// Context of one registry transaction.
pub struct ApplyCtx {
    pub sender: Address,
    pub governance: Option<Address>,
    pub height: u64,
    pub timestamp: u64,
    /// The op comes from a proposal approved by validator vote (VIP-003).
    pub by_vote: bool,
    /// VIP-003 is active: the governance key can no longer change fees or the registrar.
    pub key_retired: bool,
    /// VIP-003 emergency pause: new registrations are refused.
    pub registrations_paused: bool,
}

/// Validates and applies `op`. On `Err` nothing has been written. Returns the receipt logs.
fn not_gov(ctx: &ApplyCtx, what: &str) -> String {
    if ctx.key_retired {
        format!("registry: only a validator vote (VIP-003) can {}", what)
    } else {
        format!("registry: only governance can {}", what)
    }
}

pub fn apply(csmt: &mut CSMT, op: &RegistryOp, params: &FeeParams, ctx: &ApplyCtx) -> Result<Vec<EvmLog>, String> {
    // Fees and the registrar: the governance key until VIP-003, a validator vote after.
    let is_gov = ctx.by_vote || (!ctx.key_retired && ctx.governance.map_or(false, |g| g == ctx.sender));
    let registrar = params.registrar.or(ctx.governance);
    if ctx.registrations_paused && matches!(op, RegistryOp::Register { .. } | RegistryOp::RegisterBatch { .. }) {
        return Err("registry: new registrations are paused (VIP-003 emergency pause)".to_string());
    }
    let is_registrar = registrar.map_or(false, |r| r == ctx.sender);

    let mut data = Vec::new();
    match op {
        RegistryOp::Register { kind, doc_hash, parent } => {
            let key = doc_key(&ctx.sender, doc_hash);
            if csmt.get(&key).is_some() {
                return Err(format!("registry: document 0x{} already registered by this sender", hex::encode(doc_hash)));
            }
            let rec = DocRecord { kind: *kind, leaf_count: 0, parent: *parent, height: ctx.height, timestamp: ctx.timestamp, revoked_at: None };
            csmt.insert(key, rec.to_bytes());
            data.extend_from_slice(doc_hash);
        }
        RegistryOp::RegisterBatch { kind, merkle_root, leaf_count } => {
            if *leaf_count == 0 || *leaf_count > params.max_batch_leaves {
                return Err(format!("registry: batch leaf_count {} outside 1..={}", leaf_count, params.max_batch_leaves));
            }
            let key = doc_key(&ctx.sender, merkle_root);
            if csmt.get(&key).is_some() {
                return Err(format!("registry: batch root 0x{} already registered by this sender", hex::encode(merkle_root)));
            }
            let rec = DocRecord { kind: *kind, leaf_count: *leaf_count, parent: None, height: ctx.height, timestamp: ctx.timestamp, revoked_at: None };
            csmt.insert(key, rec.to_bytes());
            data.extend_from_slice(merkle_root);
            data.extend_from_slice(&leaf_count.to_le_bytes());
        }
        RegistryOp::Revoke { doc_hash } => {
            let key = doc_key(&ctx.sender, doc_hash);
            let mut rec = match csmt.get(&key) {
                Some(b) => DocRecord::from_bytes(b)?,
                None => return Err(format!("registry: document 0x{} not registered by this sender", hex::encode(doc_hash))),
            };
            if rec.revoked_at.is_some() {
                return Err(format!("registry: document 0x{} already revoked", hex::encode(doc_hash)));
            }
            rec.revoked_at = Some(ctx.timestamp);
            csmt.insert(key, rec.to_bytes());
            data.extend_from_slice(doc_hash);
        }
        RegistryOp::SetFee { fee_per_item_wei } => {
            if !is_gov {
                return Err(not_gov(ctx, "change the document fee"));
            }
            check_fee_change(params.fee_per_item_wei, *fee_per_item_wei, MAX_FEE_PER_ITEM_WEI, params.last_item_change_ts, ctx.timestamp, "fee_per_item_wei")?;
            let mut p = params.clone();
            p.fee_per_item_wei = *fee_per_item_wei;
            p.last_item_change_ts = ctx.timestamp;
            csmt.insert(FEE_PARAMS_KEY, p.to_bytes());
            data.extend_from_slice(&fee_per_item_wei.to_le_bytes());
        }
        RegistryOp::SetGasPrice { min_gas_price_wei } => {
            if !is_gov {
                return Err(not_gov(ctx, "change the minimum gas price"));
            }
            check_fee_change(
                params.min_gas_price_wei as u128,
                *min_gas_price_wei as u128,
                MAX_MIN_GAS_PRICE_WEI as u128,
                params.last_gas_change_ts,
                ctx.timestamp,
                "min_gas_price_wei",
            )?;
            let mut p = params.clone();
            p.min_gas_price_wei = *min_gas_price_wei;
            p.last_gas_change_ts = ctx.timestamp;
            csmt.insert(FEE_PARAMS_KEY, p.to_bytes());
            data.extend_from_slice(&min_gas_price_wei.to_le_bytes());
        }
        RegistryOp::SetIssuer { addr, record } => {
            if !is_registrar {
                return Err("registry: only the registrar can attest issuers".to_string());
            }
            if record.display_name.is_empty() || record.display_name.len() > MAX_ISSUER_NAME_BYTES {
                return Err(format!("registry: issuer name must be 1..={} bytes", MAX_ISSUER_NAME_BYTES));
            }
            // No retroactive attestation: a window starts no earlier than this block.
            let now = ctx.timestamp;
            let from = record.valid_from_ts.max(now);
            if record.valid_until_ts < from {
                return Err("registry: issuer valid_until must be at or after the block time and valid_from".to_string());
            }
            let state = match csmt.get(&issuer_key(addr)) {
                None => IssuerState {
                    issuer_id: record.issuer_id,
                    display_name: record.display_name.clone(),
                    windows: vec![(from, record.valid_until_ts)],
                },
                Some(b) => {
                    let mut st = IssuerState::from_bytes(b)?;
                    if st.issuer_id != record.issuer_id {
                        return Err("registry: an attested address cannot change organization; attest a new address".to_string());
                    }
                    st.display_name = record.display_name.clone();
                    match st.windows.last().copied() {
                        // Current window (started or scheduled): renew or reschedule it. A
                        // started window keeps its start; its end cannot move into the past
                        // because valid_until >= from >= now.
                        Some((lf, lu)) if lu >= now => {
                            let start = if lf <= now { lf } else { from };
                            *st.windows.last_mut().unwrap() = (start, record.valid_until_ts);
                        }
                        // Expired or removed: a new window, from now on.
                        _ => {
                            if st.windows.len() >= MAX_ISSUER_WINDOWS {
                                return Err(format!("registry: issuer already has {} attestation windows", MAX_ISSUER_WINDOWS));
                            }
                            st.windows.push((from, record.valid_until_ts));
                        }
                    }
                    st
                }
            };
            csmt.insert(issuer_key(addr), state.to_bytes());
            data.extend_from_slice(addr);
        }
        RegistryOp::RemoveIssuer { addr } => {
            if !is_registrar {
                return Err("registry: only the registrar can remove issuers".to_string());
            }
            // Ends the attestation now: records made before stay verified.
            let mut st = match csmt.get(&issuer_key(addr)) {
                Some(b) => IssuerState::from_bytes(b)?,
                None => return Err(format!("registry: address 0x{} is not an attested issuer", hex::encode(addr))),
            };
            let now = ctx.timestamp;
            if !st.is_current(now) {
                return Err(format!("registry: address 0x{} has no current attestation", hex::encode(addr)));
            }
            let (lf, _) = *st.windows.last().unwrap();
            if lf > now {
                st.windows.pop(); // scheduled, never started: drop it
            } else {
                st.windows.last_mut().unwrap().1 = now;
            }
            csmt.insert(issuer_key(addr), st.to_bytes());
            data.extend_from_slice(addr);
        }
        RegistryOp::SetRegistrar { addr } => {
            if !is_gov {
                return Err(not_gov(ctx, "appoint the registrar"));
            }
            let mut p = params.clone();
            p.registrar = Some(*addr);
            csmt.insert(FEE_PARAMS_KEY, p.to_bytes());
            data.extend_from_slice(addr);
        }
    }

    Ok(vec![EvmLog { address: REGISTRY_SYSTEM_ADDRESS, topics: vec![op.topic(), ctx.sender], data }])
}

#[cfg(test)]
mod reserved_key_tests {
    #[test]
    fn state_key_is_the_domain_separated_hash() {
        assert_eq!(super::FEE_PARAMS_KEY, crate::chain_hash::hash256(b"VREG1/params"));
    }
}
