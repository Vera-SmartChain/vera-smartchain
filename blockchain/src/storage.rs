use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::block::Block;
use crate::csmt::CSMT;
use crate::transaction::Transaction;
use crate::consensus::ValidatorSet;

#[derive(Clone)]
pub struct PersistentStorage {
    pub base_dir: PathBuf,
    pub blocks_dir: PathBuf,
    pub state_dir: PathBuf,
    pub mempool_dir: PathBuf,
}

impl PersistentStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let base_dir = path.as_ref().to_path_buf();
        let blocks_dir = base_dir.join("blocks");
        let state_dir = base_dir.join("state");
        let mempool_dir = base_dir.join("mempool");

        fs::create_dir_all(&blocks_dir).map_err(|e| format!("Error creating blocks_dir: {}", e))?;
        fs::create_dir_all(&state_dir).map_err(|e| format!("Error creating state_dir: {}", e))?;
        fs::create_dir_all(&mempool_dir).map_err(|e| format!("Error creating mempool_dir: {}", e))?;

        Ok(Self {
            base_dir,
            blocks_dir,
            state_dir,
            mempool_dir,
        })
    }

    fn atomic_write<P: AsRef<Path>>(target_path: P, data: &[u8]) -> Result<(), String> {
        let path = target_path.as_ref();
        let tmp_path = path.with_extension("tmp");
        {
            let mut file = File::create(&tmp_path).map_err(|e| format!("Error creating tmp file: {}", e))?;
            file.write_all(data).map_err(|e| format!("Error writing data: {}", e))?;
            file.flush().map_err(|e| format!("Error flushing file: {}", e))?;
        }
        fs::rename(&tmp_path, path).map_err(|e| format!("Error renaming tmp to target: {}", e))?;
        Ok(())
    }

    /// Saves a block persisted to disk
    pub fn save_block(&self, block: &Block) -> Result<(), String> {
        let block_filename = format!("{:012}.blk", block.header.height);
        let block_path = self.blocks_dir.join(block_filename);
        let block_bytes = block.to_bytes();
        Self::atomic_write(&block_path, &block_bytes)?;

        // Update highest height pointer
        let latest_path = self.blocks_dir.join("latest_height.txt");
        Self::atomic_write(&latest_path, block.header.height.to_string().as_bytes())?;

        // Map block hash to height
        let hash_filename = format!("{}.hash", hex::encode(block.hash()));
        let hash_path = self.blocks_dir.join(hash_filename);
        Self::atomic_write(&hash_path, block.header.height.to_string().as_bytes())?;

        Ok(())
    }

    /// Loads block by height
    pub fn load_block(&self, height: u64) -> Result<Option<Block>, String> {
        let block_filename = format!("{:012}.blk", height);
        let block_path = self.blocks_dir.join(block_filename);
        if !block_path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&block_path).map_err(|e| format!("Error reading block: {}", e))?;
        let block = Block::from_bytes(&bytes)?;
        Ok(Some(block))
    }

    /// Gets highest persisted block height
    pub fn get_latest_block_height(&self) -> Result<Option<u64>, String> {
        let latest_path = self.blocks_dir.join("latest_height.txt");
        if !latest_path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(&latest_path).map_err(|e| format!("Error reading latest_height: {}", e))?;
        let height = text.trim().parse::<u64>().map_err(|e| format!("Invalid height format: {}", e))?;
        Ok(Some(height))
    }

    /// Saves active ValidatorSet to disk
    pub fn save_validators(&self, val_set: &ValidatorSet) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(val_set)
            .map_err(|e| format!("Error serializing ValidatorSet: {}", e))?;
        let path = self.state_dir.join("validators.json");
        Self::atomic_write(&path, &json)?;
        Ok(())
    }

    /// Loads persisted ValidatorSet from disk
    pub fn load_validators(&self) -> Result<Option<ValidatorSet>, String> {
        let path = self.state_dir.join("validators.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|e| format!("Error reading validators.json: {}", e))?;
        let val_set: ValidatorSet = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Error deserializing ValidatorSet: {}", e))?;
        Ok(Some(val_set))
    }

    /// Saves CSMT snapshot to disk serializing (key, value) pairs
    pub fn save_state(&self, csmt: &CSMT) -> Result<(), String> {
        let entries: Vec<(String, String)> = csmt
            .to_key_values()
            .into_iter()
            .map(|(k, v)| (hex::encode(k), hex::encode(v)))
            .collect();
        let state_bytes = serde_json::to_vec_pretty(&entries)
            .map_err(|e| format!("Error serializing CSMT: {}", e))?;
        let state_file = self.state_dir.join("current_state.json");
        Self::atomic_write(&state_file, &state_bytes)?;
        Ok(())
    }

    /// Loads CSMT snapshot from disk reconstructing deterministic tree
    pub fn load_state(&self) -> Result<Option<CSMT>, String> {
        let state_file = self.state_dir.join("current_state.json");
        if !state_file.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&state_file).map_err(|e| format!("Error reading state: {}", e))?;
        let entries_hex: Vec<(String, String)> = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Error deserializing CSMT: {}", e))?;

        let mut entries = Vec::with_capacity(entries_hex.len());
        for (k_hex, v_hex) in entries_hex {
            let k_bytes = hex::decode(&k_hex).map_err(|e| format!("Invalid hex key: {}", e))?;
            let v_bytes = hex::decode(&v_hex).map_err(|e| format!("Invalid hex value: {}", e))?;
            if k_bytes.len() != 32 {
                return Err("Key must be 32 bytes".to_string());
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&k_bytes);
            entries.push((k, v_bytes));
        }

        let csmt = CSMT::from_key_values(&entries);
        Ok(Some(csmt))
    }

    /// Appends atomic incremental deltas to binary log (O(Δ) I/O, eliminating Write Amplification)
    pub fn append_state_deltas(&self, deltas: &[([u8; 32], Vec<u8>)]) -> Result<(), String> {
        if deltas.is_empty() {
            return Ok(());
        }
        let delta_log_path = self.state_dir.join("deltas.log");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&delta_log_path)
            .map_err(|e| format!("Error opening deltas.log: {}", e))?;

        let mut buffer = Vec::new();
        for (key, val) in deltas {
            buffer.extend_from_slice(key);
            buffer.extend_from_slice(&(val.len() as u32).to_le_bytes());
            buffer.extend_from_slice(val);
        }

        file.write_all(&buffer)
            .map_err(|e| format!("Error writing binary deltas: {}", e))?;
        file.flush()
            .map_err(|e| format!("Error flushing deltas: {}", e))?;
        Ok(())
    }

    /// Saves mempool transactions for crash resilience
    pub fn save_mempool(&self, txs: &[Transaction]) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(txs).map_err(|e| format!("Error serializing mempool: {}", e))?;
        let mempool_file = self.mempool_dir.join("mempool.json");
        Self::atomic_write(&mempool_file, &json)?;
        Ok(())
    }

    /// Recovers mempool transactions after restart
    pub fn load_mempool(&self) -> Result<Vec<Transaction>, String> {
        let mempool_file = self.mempool_dir.join("mempool.json");
        if !mempool_file.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&mempool_file).map_err(|e| format!("Error reading mempool: {}", e))?;
        let txs: Vec<Transaction> = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Error parsing mempool: {}", e))?;
        Ok(txs)
    }
}
