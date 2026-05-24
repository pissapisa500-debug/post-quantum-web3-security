# Post-Quantum Crypto Defender for Web3

Open-source tools and libraries to protect Web3 applications (wallets, signatures, smart contracts) against **classical exploits** and **future quantum computing attacks**.

## Problem
- Quantum computers (via Shor's algorithm) threaten current elliptic curve cryptography (ECDSA, EdDSA).
- "Harvest Now, Decrypt Later" attacks are already a realistic threat.
- Most protocols lack crypto-agility and easy migration paths.

## Solution
We are building practical, hybrid post-quantum tools focused on Ethereum and L2 ecosystems:
- Hybrid signature schemes (`secp256k1 + Dilithium / ML-KEM`)
- Key migration and rotation tools
- Wallet security audit helpers
- Crypto-agility libraries

## Tech Stack
- **Language**: Rust (performance + memory safety)
- **Cryptography**: `pqcrypto` + `ethers.rs`
- **Target**: Ethereum + L2s

## Roadmap
See [ROADMAP.md](ROADMAP.md)

## Getting Started
```bash
git clone https://github.com/pissapisa500-debug/post-quantum-web3-security.git
cd post-quantum-web3-security
cargo build

## Getting Started
```bash
git clone https://github.com/pissapisa500-debug/post-quantum-web3-security.git
cd post-quantum-web3-security
cargo build
