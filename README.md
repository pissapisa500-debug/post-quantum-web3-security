# pq-web3-security

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.80+-000.svg)](https://www.rust-lang.org/)
[![CI Status](https://github.com/pissapisa500-debug/post-quantum-web3-security/actions/workflows/ci.yml/badge.svg)](https://github.com/pissapisa500-debug/post-quantum-web3-security/actions)

**Protecting Web3 applications from current and future quantum threats.**

Open-source Rust library and CLI tools for **hybrid post-quantum cryptography**, focused on **Solana** and **Aptos** ecosystems.

---

## 🎯 The Problem

Quantum computers pose a serious long-term threat to blockchain security:
- Shor's algorithm can break Ed25519 and secp256k1 signatures
- "Harvest Now, Decrypt Later" attacks are already happening
- Solana is adopting Falcon-512, but developers lack easy-to-use tools
- Aptos ecosystem lacks production-ready post-quantum solutions

---

## ✅ Our Solution

We build **practical hybrid cryptographic tools** combining classical and post-quantum algorithms (Falcon-512, Dilithium, etc.) to ensure **crypto-agility** and long-term security.

### Key Features
- Hybrid signatures (Ed25519 + Falcon-512)
- Secure key generation and management
- Message & transaction signing / verification
- CLI tool for easy testing and integration
- High performance and memory safety (Rust)

---

## 🛠 Tech Stack

- **Language**: Rust 1.80+
- **Cryptography**: `pqcrypto-falcon`, `ed25519-dalek`, custom hybrid scheme
- **CLI**: Clap
- **CI/CD**: GitHub Actions (fmt, clippy, tests, build)

---

## 🚀 Quick Start

```bash
git clone https://github.com/pissapisa500-debug/post-quantum-web3-security.git
cd post-quantum-web3-security

cargo build --release

# Generate hybrid keypair
cargo run --release -- generate --output mykey

# Sign a message
cargo run --release -- sign --key mykey.sk --message "Hello from post-quantum world"

# Verify signature
cargo run --release -- verify --pubkey mykey.pk --message "Hello from post-quantum world" --signature <signature_hex>