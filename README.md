# Post-Quantum Crypto Defender

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.80+-orange.svg)](https://www.rust-lang.org/)
[![GitHub Stars](https://img.shields.io/github/stars/pissapisa500-debug/post-quantum-web3-security)](https://github.com/pissapisa500-debug/post-quantum-web3-security)
[![GitHub Actions](https://github.com/pissapisa500-debug/post-quantum-web3-security/actions/workflows/rust.yml/badge.svg)](https://github.com/pissapisa500-debug/post-quantum-web3-security/actions)

**Protecting Web3 applications from current and future quantum threats.**

Open-source Rust library and CLI tools for **hybrid post-quantum cryptography**, focused primarily on **Solana** and **Aptos** ecosystems.

---

## 🎯 The Problem

- Quantum computers (Shor's algorithm) will break current signature schemes (Ed25519, secp256k1)
- "Harvest Now, Decrypt Later" attacks are already a real threat
- Solana has started adopting Falcon-512, but developers lack convenient migration tools
- Aptos ecosystem has no production-ready post-quantum tooling

## ✅ Our Solution

We are building **practical hybrid cryptographic tools** that combine classical and post-quantum algorithms (Falcon-512, Dilithium).

### Key Features
- Hybrid signatures (Ed25519 + Falcon-512)
- Secure key generation and management (1313/929/730 bytes)
- Message signing & verification via CLI
- Open-source (MIT license), ready for integration

---

## 🛠 Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Rust 1.80+ |
| Hybrid Signatures | `falconed` (Ed25519 + Falcon-512) |
| CLI | `clap` with derive macros |
| CI/CD | GitHub Actions (fmt, clippy, test, build) |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/pissapisa500-debug/post-quantum-web3-security.git
cd post-quantum-web3-security

# Build the project
cargo build --release

# Generate hybrid keys
cargo run --release -- generate --output mykey

# Sign a message
cargo run --release -- sign --key mykey.sk --message "Transfer 100 SOL"

# Verify signature (replace with your actual signature hex)
cargo run --release -- verify --pubkey mykey.pk --message "Transfer 100 SOL" --signature "YOUR_HEX_SIGNATURE"
