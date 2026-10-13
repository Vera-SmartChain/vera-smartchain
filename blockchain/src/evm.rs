use revm::{
    context::{Context, TxEnv},
    context::result::ExecutionResult,
    primitives::{hardfork::SpecId, TxKind, U256, Address as EvmAddress, Bytes, B256, StorageKey, StorageValue},
    state::AccountInfo,
    bytecode::Bytecode,
    Database,
    ExecuteEvm, MainBuilder, MainContext,
};
use std::collections::BTreeMap;
use std::convert::Infallible;
use crate::account::{Account, Address as VeraAddress};
use crate::csmt::CSMT;

#[derive(Debug, Clone)]
pub struct EvmExecutionOutput {
    pub success: bool,
    pub gas_used: u64,
    pub output: Vec<u8>,
    pub created_address: Option<VeraAddress>,
    pub revert_reason: Option<String>,
    pub logs: Vec<crate::account::EvmLog>,
}

pub struct CsmtDatabase<'a> {
    pub csmt: &'a mut CSMT,
}

impl<'a> CsmtDatabase<'a> {
    pub fn new(csmt: &'a mut CSMT) -> Self {
        Self { csmt }
    }

    pub fn to_vera_addr(addr: &EvmAddress) -> VeraAddress {
        let mut v = [0u8; 32];
        v[12..32].copy_from_slice(addr.as_slice());
        v
    }

    pub fn to_evm_addr(addr: &VeraAddress) -> EvmAddress {
        EvmAddress::from_slice(&addr[12..32])
    }

    pub fn storage_slot_key(addr: &VeraAddress, slot: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(7 + 32 + 32);
        data.extend_from_slice(b"storage");
        data.extend_from_slice(addr);
        data.extend_from_slice(slot);
        vera_engine_v2::vera_hash_256(&data)
    }

    pub fn code_key(code_hash: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(b"code");
        data.extend_from_slice(code_hash);
        vera_engine_v2::vera_hash_256(&data)
    }
}

impl<'a> Database for CsmtDatabase<'a> {
    type Error = Infallible;

    fn basic(&mut self, address: EvmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let v_addr = Self::to_vera_addr(&address);
        if let Some(bytes) = self.csmt.get(&v_addr) {
            if let Ok(acc) = Account::from_bytes(&bytes) {
                let code = if acc.code_hash != [0u8; 32] {
                    let c_key = Self::code_key(&acc.code_hash);
                    self.csmt.get(&c_key).map(|raw| Bytecode::new_raw(Bytes::copy_from_slice(&raw)))
                } else {
                    None
                };

                let mut info = AccountInfo::default();
                info.balance = U256::from(acc.balance);
                info.nonce = acc.nonce;
                info.code_hash = B256::from(acc.code_hash);
                info.code = code;
                return Ok(Some(info));
            }
        }
        Ok(None)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let c_key = Self::code_key(code_hash.as_slice().try_into().unwrap());
        if let Some(raw) = self.csmt.get(&c_key) {
            return Ok(Bytecode::new_raw(Bytes::copy_from_slice(&raw)));
        }
        Ok(Bytecode::default())
    }

    fn storage(&mut self, address: EvmAddress, index: StorageKey) -> Result<StorageValue, Self::Error> {
        let v_addr = Self::to_vera_addr(&address);
        let slot_bytes: [u8; 32] = index.to_be_bytes();
        let s_key = Self::storage_slot_key(&v_addr, &slot_bytes);
        if let Some(val_bytes) = self.csmt.get(&s_key) {
            if val_bytes.len() == 32 {
                return Ok(StorageValue::from_be_slice(&val_bytes));
            }
        }
        Ok(StorageValue::ZERO)
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

/// Executes real EVM transaction (deploy or call) over deterministic CSMT tree
pub fn execute_evm(
    csmt: &mut CSMT,
    from: VeraAddress,
    to: Option<VeraAddress>,
    value: u128,
    data: Vec<u8>,
    gas_limit: u64,
    gas_price: u64,
    nonce: u64,
    block_height: u64,
    block_timestamp: u64,
    chain_id: u64,
    is_static: bool,
) -> Result<EvmExecutionOutput, String> {
    let caller = CsmtDatabase::to_evm_addr(&from);
    let kind = match to {
        Some(t) => TxKind::Call(CsmtDatabase::to_evm_addr(&t)),
        None => TxKind::Create,
    };

    let effective_gas_price = if is_static { 0 } else { gas_price.max(1_000_000_000) as u128 };
    let effective_nonce = if is_static && nonce == 0 {
        let v_addr = CsmtDatabase::to_vera_addr(&caller);
        csmt.get(&v_addr).and_then(|b| Account::from_bytes(&b).ok()).map(|a| a.nonce).unwrap_or(0)
    } else {
        nonce
    };

    let tx_env = TxEnv::builder()
        .caller(caller)
        .kind(kind)
        .value(U256::from(value))
        .data(Bytes::from(data))
        .gas_limit(gas_limit.max(21_000))
        .gas_price(effective_gas_price)
        .nonce(effective_nonce)
        .chain_id(Some(chain_id))
        .build()
        .map_err(|e| format!("Failed to build EVM TxEnv: {:?}", e))?;

    let db = CsmtDatabase::new(csmt);

    let ctx = Context::mainnet()
        .modify_cfg_chained(|cfg| {
            cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN);
            cfg.chain_id = chain_id;
        })
        .modify_block_chained(|b| {
            b.number = U256::from(block_height);
            b.timestamp = U256::from(block_timestamp);
        })
        .with_db(db);

    let mut evm = ctx.build_mainnet();

    let result_and_state = evm
        .transact(tx_env)
        .map_err(|e| format!("EVM execution error: {:?}", e))?;

    let result = result_and_state.result;
    let state = result_and_state.state;

    match result {
        ExecutionResult::Success { gas, output, logs, .. } => {
            let gas_used = gas.tx_gas_used();
            let output_bytes = output.data().to_vec();
            let created_address = output.address().map(|a| CsmtDatabase::to_vera_addr(a));
            let evm_logs: Vec<crate::account::EvmLog> = logs.into_iter().map(|l| {
                let v_addr = CsmtDatabase::to_vera_addr(&l.address);
                let topics = l.topics().iter().map(|t| *t.as_ref()).collect();
                crate::account::EvmLog {
                    address: v_addr,
                    topics,
                    data: l.data.data.to_vec(),
                }
            }).collect();

            if !is_static {
                // Apply state mutations to CSMT in strictly deterministic order
                // Sort accounts by address lexicographically for inviolable determinism
                let mut sorted_accounts: BTreeMap<VeraAddress, _> = BTreeMap::new();
                for (addr, account) in state {
                    let v_addr = CsmtDatabase::to_vera_addr(&addr);
                    sorted_accounts.insert(v_addr, account);
                }

                for (v_addr, account) in sorted_accounts {
                    // Load existing account or create new
                    let mut current = if let Some(raw) = csmt.get(&v_addr) {
                        Account::from_bytes(&raw).unwrap_or_else(|_| Account::new(0))
                    } else {
                        Account::new(0)
                    };

                    current.balance = account.info.balance.to::<u128>();
                    current.nonce = account.info.nonce;

                    if let Some(code) = account.info.code {
                        if !code.is_empty() {
                            let code_bytes = code.original_bytes();
                            let c_hash = vera_engine_v2::vera_hash_256(&code_bytes);
                            current.code_hash = c_hash;
                            let c_key = CsmtDatabase::code_key(&c_hash);
                            csmt.insert(c_key, code_bytes.to_vec());
                        }
                    }

                    // Sort storage slots lexicographically
                    let mut sorted_storage: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
                    for (slot, slot_val) in account.storage {
                        let slot_bytes: [u8; 32] = slot.to_be_bytes();
                        let val_bytes: [u8; 32] = slot_val.present_value.to_be_bytes();
                        sorted_storage.insert(slot_bytes, val_bytes);
                    }

                    for (slot_bytes, val_bytes) in sorted_storage {
                        let s_key = CsmtDatabase::storage_slot_key(&v_addr, &slot_bytes);
                        csmt.insert(s_key, val_bytes.to_vec());
                    }

                    csmt.insert(v_addr, current.to_bytes());
                }
            }

            Ok(EvmExecutionOutput {
                success: true,
                gas_used,
                output: output_bytes,
                created_address,
                revert_reason: None,
                logs: evm_logs,
            })
        }
        ExecutionResult::Revert { gas, output, .. } => {
            let gas_used = gas.tx_gas_used();
            let revert_str = decode_revert_reason(&output).unwrap_or_else(|| {
                String::from_utf8(output.to_vec()).unwrap_or_else(|_| hex::encode(&output))
            });
            Ok(EvmExecutionOutput {
                success: false,
                gas_used,
                output: output.to_vec(),
                created_address: None,
                revert_reason: Some(revert_str),
                logs: Vec::new(),
            })
        }
        ExecutionResult::Halt { reason, gas, .. } => {
            let gas_used = gas.tx_gas_used();
            if is_static {
                Err(format!("EVM Halted: {:?} (Gas used: {})", reason, gas_used))
            } else {
                Ok(EvmExecutionOutput {
                    success: false,
                    gas_used,
                    output: Vec::new(),
                    created_address: None,
                    revert_reason: Some(format!("{:?}", reason)),
                    logs: Vec::new(),
                })
            }
        }
    }
}

pub fn decode_revert_reason(output: &[u8]) -> Option<String> {
    if output.len() >= 68 && output.starts_with(&[0x08, 0xc3, 0x79, 0xa0]) {
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&output[60..68]);
        let str_len = u64::from_be_bytes(len_bytes) as usize;
        if 68 + str_len <= output.len() {
            if let Ok(s) = std::str::from_utf8(&output[68..68 + str_len]) {
                return Some(s.to_string());
            }
        }
    } else if output.len() >= 36 && output.starts_with(&[0x4e, 0x48, 0x7b, 0x71]) {
        let code = output.last().copied().unwrap_or(0);
        return Some(format!("Panic(0x{:02x})", code));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_contract_deployment_and_storage() {
        let mut csmt = CSMT::new();
        let mut caller = [0u8; 32];
        caller[31] = 0x01; // 0x00...01

        // Fund initial balance for caller to pay gas
        let caller_acc = Account::new(100_000_000_000_000_000_000); // 100 VERA
        csmt.insert(caller, caller_acc.to_bytes());

        // EVM bytecode that stores 42 at storage slot 0:
        // PUSH1 0x2a (42) PUSH1 0x00 SSTORE
        // PUSH1 0x00 PUSH1 0x00 RETURN
        // hex: 602a60005560006000f3
        let deploy_bytecode = hex::decode("602a60005560006000f3").unwrap();

        let res = execute_evm(
            &mut csmt,
            caller,
            None, // Deploy!
            0,
            deploy_bytecode,
            100_000,
            1_000_000_000,
            0,
            1,
            1700000000,
            8372,
            false,
        ).expect("Deploy failed");

        assert!(res.success, "Deploy must succeed");
        let contract_addr = res.created_address.expect("Contract address must be returned");
        println!("\n========================================================");
        println!("✅ REAL EVM: Contract deployed successfully!");
        println!("✅ Contract address: 0x{}", hex::encode(contract_addr));
        println!("✅ Gas consumed by EVM: {}", res.gas_used);

        // Verify that slot 0 of the contract contains value 42 (0x2a) saved in CSMT
        let slot0 = [0u8; 32];
        let s_key = CsmtDatabase::storage_slot_key(&contract_addr, &slot0);
        let val_bytes = csmt.get(&s_key).expect("Slot 0 must exist in CSMT");
        assert_eq!(val_bytes[31], 0x2a, "Value in slot 0 must be 42");
        println!("✅ Storage slot 0 verified in CSMT with value 42 (0x2a)!");
        println!("========================================================\n");
    }
}
