# ⚖️ Running a Validator on VERA SmartChain

This guide details the complete operational instructions, security standards, and deployment procedures for running a validator node on the **VERA SmartChain**.

---

## 🏛️ Consensus Model & Economic Rules

VERA SmartChain utilizes a high-performance **Byzantine Fault Tolerant Proof-of-Stake (BFT-PoS)** consensus engine:
- **Block Authorship:** Rotates deterministically across the active validator set.
- **Commit Rule:** A block is finalized when it collects Ed25519 cryptographic signatures representing at least **2/3 + 1** of active network stake.
- **State Authenticity:** State transitions and receipts are authenticated using **BLAKE3** cryptographic hashing and Compact Sparse Merkle Trees (CSMT).
- **Minimum Stake Requirement:**
  - **Mainnet Baseline:** `10,000 VERA` (`10000000000000000000000` wei) minimum bonded stake required to propose and validate blocks.
  - **Testnet-1 Environment:** Configured to `32 VERA` (`32000000000000000000` wei) with a 5-block unbonding window to streamline developer onboarding, node operator testing, and automated integration pipelines.
- **Liveness Slashing:** Validators that fail to vote for 10 consecutive rounds (`max_missed_blocks = 10`) are automatically jailed and removed from the active consensus schedule until unjailed by governance.

---

## 💧 Obtaining Testnet Stake & Allowlist Access

Because the public testnet faucet distributes 1.0 VERA per 24 hours per address (to protect public testnet liquidity against automated exhaustion), new testnet validators receive their initial staking balance through authorized onboarding:

1. **Generate your Validator Keys:**
   ```bash
   ./vera_cli keygen
   ```
   Save the private key (`/etc/vera/validator_key.hex`, mode `0600`, owned by service user `vera`). Note your public key (`0x...` or 32-byte hex) and derived on-chain address (`0x...`).

2. **Request Validator Allowlist & Staking Allocation:**
   - Submit your validator address and public key to the VERA Testnet Governance:
     - **Email:** `governance@verachain.cloud` or via official Discord / Telegram validator onboarding channels.
   - The Testnet Governance Account (`0xd12949512c92d3e70be1789b3f086044c4483205a20f29b34b066396c00f0ea5`) executes:
     - Allowlist transaction: `allow:<VALIDATOR_ADDRESS>`
     - Initial staking grant (32+ VERA) directly to your validator address.

3. **Bond Your Validator Stake:**
   Once funded and allowlisted, submit your on-chain bond transaction using `vera_cli`:
   ```bash
   # Syntax: ./vera_cli stake <private_key_hex> <amount_wei>
   ./vera_cli stake <YOUR_PRIVATE_KEY_HEX> 32000000000000000000
   ```
   The transaction will be committed in the next block, dynamically adding your node to the active validator set.

---

## 🖥️ System Requirements

| Resource | Minimum | Recommended Production |
| :--- | :--- | :--- |
| **CPU** | 4 Cores x86-64 | 8 Cores (AMD EPYC or Intel Xeon) |
| **RAM** | 4 GB | 8 GB DDR4/DDR5 |
| **Disk** | 40 GB NVMe SSD | 200 GB NVMe PCIe 4.0 |
| **Network**| 50 Mbps symmetric | 1 Gbps symmetric unmetered |
| **OS** | Ubuntu 22.04 / 24.04 LTS | Ubuntu 24.04 LTS Minimal |

---

## 🚀 Installation & Service Configuration

### 1. Install Release Package

Download and verify the official release package:
```bash
mkdir -p /var/lib/vera/releases && cd /var/lib/vera/releases
# Download release package (v0.2.1-testnet)
RELEASE_URL="https://github.com/Vera-SmartChain/vera-node-releases/releases/download/v0.2.1-testnet"
for f in install.sh SHA256SUMS SHA256SUMS.sig vera-release.pub testnet-genesis.json vera_node vera_cli vera-node.service; do
    curl -LO "${RELEASE_URL}/${f}"
done

# Cryptographically verify the release
gpg --import vera-release.pub
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS

# Run automated installer
sudo bash install.sh
```

### 2. Configure Systemd Service (`/etc/systemd/system/vera-validator.service`)

```ini
[Unit]
Description=VERA SmartChain Validator Node
After=network.target

[Service]
Type=simple
User=vera
Group=vera
WorkingDirectory=/var/lib/vera
ExecStart=/usr/local/bin/vera_node \
  --validator \
  --key-file /etc/vera/validator_key.hex \
  --genesis /etc/vera/testnet-genesis.json \
  --data-dir /var/lib/vera/data \
  --rpc-port 8545 \
  --p2p-port 26656 \
  --seed-peers 2.25.216.206:26656,31.97.93.163:26656
Restart=always
RestartSec=3
LimitNOFILE=65535

# Security Sandboxing
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/vera /var/log/vera

[Install]
WantedBy=multi-user.target
```

### 3. Start & Monitor Node

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vera-validator

# Check service status
sudo systemctl status vera-validator

# Follow live consensus logs
journalctl -u vera-validator -f
```

---

## 🔍 Validation & Health Checks

Verify your node's synchronization and block production:

```bash
# Check block height
curl -s http://127.0.0.1:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Query validator set and active stakes
./vera_cli query-validators http://127.0.0.1:8545
```
