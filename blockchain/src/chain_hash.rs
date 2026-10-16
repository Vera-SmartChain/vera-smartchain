//! Cryptographic hashing module for Vera SmartChain consensus and state transitions.
//! Backed by BLAKE3 for provable security and ultra-high throughput.

pub fn hash256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[derive(Clone, Debug)]
pub struct ChainHasher {
    hasher: blake3::Hasher,
}

impl ChainHasher {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.hasher.update(data);
        self
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

impl Default for ChainHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_official_empty_vector() {
        let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        assert_eq!(hex::encode(hash256(b"")), expected);

        let mut h = ChainHasher::new();
        assert_eq!(hex::encode(h.finalize()), expected);
    }

    #[test]
    fn test_blake3_incremental_matches_oneshot() {
        let data = b"Vera SmartChain Consensus Engine with BLAKE3";
        let oneshot = hash256(data);

        let mut hasher = ChainHasher::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..]);
        let incremental = hasher.finalize();

        assert_eq!(oneshot, incremental);
    }
}
