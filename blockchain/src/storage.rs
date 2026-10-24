use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::block::Block;

/// Persisted tx-hash index (append-only), so start-up does not re-read every block.
pub const TX_INDEX_FILE: &str = "tx_index.log";
const TX_INDEX_RECORD: usize = 44;
use crate::csmt::CSMT;
use crate::transaction::Transaction;
use crate::consensus::ValidatorSet;

/// Incremental state: `current_state.json` is a full snapshot taken at the height in
/// `state_height`; `state_deltas.log` holds, per block after it, the accounts it changed.
const DELTA_LOG_FILE: &str = "state_deltas.log";
const SNAPSHOT_META_FILE: &str = "state_height";
const DELTA_MAGIC: &[u8; 4] = b"VDL1";

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
            // Durable before the rename publishes it (flush alone only reaches the OS cache).
            file.sync_all().map_err(|e| format!("Error syncing file: {}", e))?;
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
        // The snapshot is the state after the latest saved block: callers save the block
        // first. Deltas up to that height are now redundant.
        let height = self.get_latest_block_height()?.unwrap_or(0);
        self.write_snapshot_height(height)?;
        let log = self.state_dir.join(DELTA_LOG_FILE);
        if log.exists() {
            File::create(&log).and_then(|f| f.sync_all()).map_err(|e| format!("Error resetting {}: {}", DELTA_LOG_FILE, e))?;
        }
        Ok(())
    }

    fn write_snapshot_height(&self, height: u64) -> Result<(), String> {
        Self::atomic_write(self.state_dir.join(SNAPSHOT_META_FILE), height.to_string().as_bytes())
    }

    fn read_snapshot_height(&self) -> Option<u64> {
        fs::read_to_string(self.state_dir.join(SNAPSHOT_META_FILE)).ok()?.trim().parse().ok()
    }

    /// Size of the delta log (the node takes a full snapshot when it grows too much).
    pub fn delta_log_bytes(&self) -> u64 {
        fs::metadata(self.state_dir.join(DELTA_LOG_FILE)).map(|m| m.len()).unwrap_or(0)
    }

    /// Appends the accounts changed by block `height` (absolute new values) and fsyncs.
    /// Record: "VDL1" | height u64 | count u32 | count × (key 32 | len u32 | value) | blake3.
    /// Written BEFORE the block itself, so the state on disk is never ahead of the blocks.
    /// Appends the tx-hash index entries of one block: tx_hash 32 | height u64 LE |
    /// position u32 LE per tx. Not fsynced: the index is rebuilt from the blocks for any
    /// height it misses (see `load_tx_index`), so a crash only costs a short rebuild.
    pub fn append_tx_index(&self, height: u64, hashes: &[[u8; 32]]) -> Result<(), String> {
        let mut rec = Vec::with_capacity(hashes.len() * TX_INDEX_RECORD);
        for (idx, h) in hashes.iter().enumerate() {
            rec.extend_from_slice(h);
            rec.extend_from_slice(&height.to_le_bytes());
            rec.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.blocks_dir.join(TX_INDEX_FILE))
            .map_err(|e| format!("Error opening {}: {}", TX_INDEX_FILE, e))?;
        file.write_all(&rec).map_err(|e| format!("Error writing tx index: {}", e))
    }

    /// The persisted tx-hash index, keeping only heights <= `max_height`, and the highest
    /// height it fully covers (entries of the last height in the file may be torn, so that
    /// height counts as not covered and is rebuilt). A torn tail record is ignored.
    pub fn load_tx_index(&self, max_height: u64) -> (std::collections::HashMap<[u8; 32], (u64, usize)>, u64) {
        let mut index = std::collections::HashMap::new();
        let bytes = match fs::read(self.blocks_dir.join(TX_INDEX_FILE)) {
            Ok(b) => b,
            Err(_) => return (index, 0),
        };
        let mut last = 0u64;
        for rec in bytes.chunks_exact(TX_INDEX_RECORD) {
            let mut h = [0u8; 32];
            h.copy_from_slice(&rec[..32]);
            let height = u64::from_le_bytes(rec[32..40].try_into().unwrap());
            let idx = u32::from_le_bytes(rec[40..44].try_into().unwrap()) as usize;
            if height <= max_height {
                index.insert(h, (height, idx));
                last = last.max(height);
            }
        }
        (index, last.saturating_sub(1))
    }

    pub fn append_state_delta(&self, height: u64, deltas: &[([u8; 32], Vec<u8>)]) -> Result<(), String> {
        let mut rec = Vec::with_capacity(48 + deltas.iter().map(|(_, v)| 36 + v.len()).sum::<usize>());
        rec.extend_from_slice(DELTA_MAGIC);
        rec.extend_from_slice(&height.to_le_bytes());
        rec.extend_from_slice(&(deltas.len() as u32).to_le_bytes());
        for (key, val) in deltas {
            rec.extend_from_slice(key);
            rec.extend_from_slice(&(val.len() as u32).to_le_bytes());
            rec.extend_from_slice(val);
        }
        let checksum = crate::chain_hash::hash256(&rec);
        rec.extend_from_slice(&checksum);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.state_dir.join(DELTA_LOG_FILE))
            .map_err(|e| format!("Error opening {}: {}", DELTA_LOG_FILE, e))?;
        file.write_all(&rec).map_err(|e| format!("Error writing state delta: {}", e))?;
        file.sync_data().map_err(|e| format!("Error syncing state delta: {}", e))?;
        Ok(())
    }

    /// Delta records with snapshot_height < height <= max_height, in order. Stops at the first
    /// torn or corrupt record (a crash in the middle of an append).
    fn read_state_deltas(&self, after: u64, max_height: u64) -> Vec<(u64, Vec<([u8; 32], Vec<u8>)>)> {
        let data = match fs::read(self.state_dir.join(DELTA_LOG_FILE)) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        let mut i = 0usize;
        let rd = |d: &[u8], at: usize, n: usize| -> Option<Vec<u8>> { d.get(at..at + n).map(|s| s.to_vec()) };
        while i < data.len() {
            let start = i;
            if rd(&data, i, 4).as_deref() != Some(&DELTA_MAGIC[..]) {
                break;
            }
            i += 4;
            let height = match rd(&data, i, 8) { Some(b) => u64::from_le_bytes(b.try_into().unwrap()), None => break };
            i += 8;
            let count = match rd(&data, i, 4) { Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize, None => break };
            i += 4;
            let mut entries = Vec::with_capacity(count);
            let mut ok = true;
            for _ in 0..count {
                let key = match rd(&data, i, 32) { Some(b) => b, None => { ok = false; break } };
                i += 32;
                let len = match rd(&data, i, 4) { Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize, None => { ok = false; break } };
                i += 4;
                let val = match rd(&data, i, len) { Some(b) => b, None => { ok = false; break } };
                i += len;
                let mut k = [0u8; 32];
                k.copy_from_slice(&key);
                entries.push((k, val));
            }
            if !ok {
                break;
            }
            let checksum = match rd(&data, i, 32) { Some(b) => b, None => break };
            if crate::chain_hash::hash256(&data[start..i])[..] != checksum[..] {
                break;
            }
            i += 32;
            if height > after && height <= max_height {
                out.push((height, entries));
            }
        }
        out
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

        let mut csmt = CSMT::from_key_values(&entries);
        let latest = self.get_latest_block_height()?.unwrap_or(0);
        match self.read_snapshot_height() {
            // Data written before incremental state: the snapshot IS the latest state.
            None => self.write_snapshot_height(latest)?,
            Some(snapshot_height) => {
                for (_h, entries) in self.read_state_deltas(snapshot_height, latest) {
                    for (k, v) in entries {
                        csmt.insert(k, v);
                    }
                }
                csmt.compact();
            }
        }
        Ok(Some(csmt))
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
