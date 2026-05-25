# Post-Quantum Crypto Defender

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

Open-source Rust tools and libraries to protect Web3 applications (wallets, signatures, smart contracts) against **classical exploits** and **future quantum computing attacks**.

## Problem

- Quantum computers (via Shor's algorithm) threaten current elliptic curve cryptography (ECDSA, EdDSA)
- "Harvest Now, Decrypt Later" attacks are already a realistic threat
- Most protocols lack crypto-agility and easy migration paths
- Solana has adopted Falcon-512 (SIMD-0461) but no production tooling exists

## Solution

We are building practical, hybrid post-quantum tools focused on Solana and Ethereum ecosystems:

- **Hybrid signature schemes** (ed25519 + Falcon-512 for Solana, secp256k1 + Dilithium for Ethereum)
- **Key migration and rotation tools** (CLI-based)
- **Crypto-agility libraries** (pluggable post-quantum algorithms)

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Rust (performance + memory safety) |
| Hybrid Signatures | `falconed` (ed25519 + Falcon-512) |
| CLI | `clap` with derive macros |
| Encoding | `hex` |

## Quick Demo

**Run these commands:**

```bash
# Clone the repository
git clone https://github.com/pissapisa500-debug/post-quantum-web3-security.git
cd post-quantum-web3-security

# Generate hybrid keys (ed25519 + Falcon-512)
cargo run --release -- generate --output mykey

# Sign a message
cargo run --release -- sign --key mykey.sk --message "Transfer 100 SOL"

# Verify the signature (replace with your actual signature hex)
cargo run --release -- verify --pubkey mykey.pk --message "Transfer 100 SOL" --signature "YOUR_HEX_SIGNATURE"
```

**Expected output:**

```
🔐 Generating hybrid keys (Ed25519 + Falcon-512)...
✅ Private key saved to: mykey.sk
✅ Public key saved to: mykey.pk

📊 Key sizes:
   Private key: 1313 bytes
   Public key:  929 bytes

✍️ Signing message...
✅ Signature (hex): <730-byte signature>

🔍 Verifying signature...
✅ Signature is VALID
```
