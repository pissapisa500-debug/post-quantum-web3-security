# Post-Quantum Crypto Defender for Web3

Open-source tools and libraries to protect Web3 applications (wallets, signatures, smart contracts) against classical exploits and future quantum computing attacks.

## Problem
- Quantum computers (via Shor's algorithm) threaten current elliptic curve cryptography (ECDSA, EdDSA).
- "Harvest Now, Decrypt Later" attacks are already a real risk.
- Many protocols lack crypto-agility and easy migration paths.

## Solution
We are building practical, hybrid post-quantum tools focused on Ethereum and L2 ecosystems:
- Hybrid signature schemes (secp256k1 + NIST PQC: Dilithium, ML-KEM etc.)
- Key migration and rotation tools
- Wallet security audit helpers
- Crypto-agility libraries

## Roadmap (first 3-6 months)

**Milestone 1** (4 weeks) — Research & Skeleton
- Deep dive into NIST PQC standards
- Initial hybrid implementation (Rust preferred)
- Basic documentation

**Milestone 2** (8 weeks) — Core Library
- Working hybrid signature module
- Tests on Ethereum testnet
- Simple CLI tool for key conversion

**Milestone 3** (12 weeks) — First Release
- Open-source v0.1
- Examples for wallet integration
- Community feedback and security audit preparation
## Tech Stack
- **Language**: Rust (focus on performance and security)
- **Cryptography**: pqcrypto + ethers.rs
- **Target**: Ethereum + L2s

## Getting Started

```bash
git clone https://github.com/pissapisa500-debug/post-quantum-web3-security.git
cd post-quantum-web3-security
cargo build
## Team
Two independent pseudonymous developers with experience in cryptography and blockchain development. Full team will be expanded after initial funding.

## How to contribute / contact
Open issues and PRs are welcome.
