# ⚖️ Running a Validator on VERA SmartChain

This document provides the complete, deterministic guide for deploying, onboarding, and operating a validator node on the **VERA SmartChain**.

---

## 🏛️ Consensus Model & Economic Specifications

VERA SmartChain operates using an energy-efficient **Byzantine Fault Tolerant Proof-of-Stake (BFT-PoS)** consensus architecture:
- **Block Authorship:** Rotates deterministically across active validators.
- **Commit Rule:** Blocks are irreversibly committed upon collecting Ed25519 signatures from at least **2/3 + 1** of active network stake.
- **State Authenticity:** State transitions and receipts are verified through **BLAKE3** hashing and Compact Sparse Merkle Tree (CSMT) cryptographic proofs.
- **Minimum Bonded Stake:** `32 VERA` (`32000000000000000000` wei) on Testnet-1 with a 5-block unbonding period.
- **Liveness Slashing:** A validator missing 10 consecutive blocks (`max_missed_blocks = 10`) is automatically jailed and incurs a 1% slash.

---

## 🖥️ Server Requirements

- **Operating System:** Ubuntu 24.04 LTS x86_64
- **Compute:** 2 vCPU
- **Memory:** 4 GB RAM
- **Storage:** 40 GB NVMe / SSD
- **Network:** Public IPv4, root or sudo privileges

---

## 🚀 Deterministic Onboarding Guide (Steps 1–9)

### Step 1: Server Preparation & Firewall
Install required system packages, enforce the security firewall, and synchronize system time:
```bash
sudo apt update && sudo apt install -y chrony wget gnupg ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 26656/tcp
sudo ufw --force enable
chronyc tracking
```
Expected output from `chronyc tracking`:
```text
Leap status     : Normal
```
> **Security Requirement:** No inbound port other than SSH (22) and 26656 is needed; never expose 8545.
> **LXC Container Note:** Inside an LXC container, system clock synchronization is managed by the host. Ensure the host system synchronizes time using NTP or chrony, as the VERA wire protocol strictly terminates peer handshakes with clock drift exceeding 30 seconds.

---

### Step 2: Install Regular Node
Download the release bundle, verify cryptographic signatures, and run the automated installer:
```bash
mkdir -p ~/vera-testnet && cd ~/vera-testnet
RELEASE_URL="https://github.com/Vera-SmartChain/vera-node-releases/releases/download/v0.2.8.1-testnet"
for f in install.sh SHA256SUMS SHA256SUMS.sig vera-release.pub testnet-genesis.json vera_node vera_cli vera-node.service vera-validator.service; do
    wget -q --show-progress "${RELEASE_URL}/${f}"
done
gpg --import vera-release.pub
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
chmod +x install.sh && sudo ./install.sh
sudo systemctl enable --now vera-node
```

---

### Step 3: Wait for Synchronization
Compare local block height against the remote network RPC until synchronized:
```bash
vera_cli syncwait
```
Expected output:
```text
SYNCED at block #N
```

---

### Step 4: Generate Validator Key
Generate a dedicated Ed25519 keypair for block signing:
```bash
sudo vera_cli keygen --out /etc/vera/validator_key.hex
```
Expected output:
```text
Address:    0x...
Public Key: 0x...
```
The private key is recorded to `/etc/vera/validator_key.hex` with permissions `0600` (owned by `vera:vera`) and is never printed to logs or standard output. The command terminates with non-zero exit code if the file already exists.

---

### Step 5: Apply for Validator Onboarding
Generate the cryptographically signed Ed25519 application block:
```bash
sudo vera_cli apply-validator --key-file /etc/vera/validator_key.hex --operator "@your_github_username"
```
Expected output:
```text
-----BEGIN VERA VALIDATOR APPLICATION-----
chain_id: vera-testnet-1
address: 0x...
public_key: 0x...
operator: @your_github_username
timestamp: 179...
signature: 0x...
-----END VERA VALIDATOR APPLICATION-----
```
Submit the application block by creating a GitHub issue:
- Web: [Validator Application Form](https://github.com/Vera-SmartChain/vera-node-releases/issues/new?template=validator-application.yml)
- CLI:
```bash
gh issue create --repo Vera-SmartChain/vera-node-releases --title "Validator Application: @your_github_username" --body "<application_block>"
```

---

### Step 6: Governance Authorization
Network governance validates the application on Node 1 via `sudo vera-approve-validator '<block>'`. The tool validates signature authenticity, confirms chain ID, checks that timestamp is within 7 days, executes on-chain allowlisting, and funds 33 VERA (32 VERA bond + 1 VERA gas) from treasury.

Expected response on your GitHub issue:
```text
Hello @your_github_username! Your validator application for address 0x... has been approved and funded with 33 VERA.
- Allowlist TX: 0x...
- Funding TX:   0x...
Proceed to Step 7 (enable validator service) and Step 8 (stake 32 VERA).
```

---

### Step 7: Enable Validator Service
Switch service units and verify synchronization:
```bash
sudo systemctl disable --now vera-node && sudo systemctl enable --now vera-validator
vera_cli syncwait
```
Expected output:
```text
SYNCED at block #N
```

---

### Step 8: Bond Stake
Bond 32 VERA into the active consensus set:
```bash
sudo vera_cli stake --key-file /etc/vera/validator_key.hex 32000000000000000000
```
Expected output:
```text
🔒 Staking Transaction Broadcast!
TX Hash: "0x..."
```

---

### Step 9: Confirm Active Validator Status
Verify your node's status in the active validator set:
```bash
sudo vera_cli validator-status --key-file /etc/vera/validator_key.hex
```
Expected output:
```text
Validator:     0x...
Status:        ACTIVE stake=32 VERA jailed=false
Missed Blocks: 0
Active Peers:  1

ACTIVE stake=32 VERA jailed=false
```

---

## 🔧 Operational Procedures

### Unjailing After Downtime
A validator missing 10 consecutive blocks enters jailed status and is slashed 1% (stake reduced to 31.68 VERA). To restore active status, top up the minimum 32 VERA stake and unjail:
```bash
sudo vera_cli stake --key-file /etc/vera/validator_key.hex 500000000000000000
sudo vera_cli unjail --key-file /etc/vera/validator_key.hex
```
Expected output:
```text
⚖️ Unjail Transaction Broadcast!
TX Hash: "0x..."
```

### Voluntary Exit (Unstaking)
To unbond your stake and exit the validator set:
```bash
sudo vera_cli unstake --key-file /etc/vera/validator_key.hex 32000000000000000000
```
The unbonding queue releases bonded funds after 5 blocks. After the 5th block, stop the service:
```bash
sudo systemctl disable --now vera-validator
```

### Upgrading Node Binary
Download and cryptographically verify the new release bundle, then execute:
```bash
sudo ./install.sh
sudo systemctl restart vera-validator
```
The installer automatically records the new binary hash into `/etc/vera/expected_binary_sha256`.
