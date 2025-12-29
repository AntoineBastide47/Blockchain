# Blockchain

A minimal, safe blockchain implementation in Rust. Designed as a pedagogical exercise demonstrating core consensus and networking concepts.

## Features

- **Immutable data structures**: Blocks and transactions enforced immutable by Rust's type system
- **Schnorr signatures**: secp256k1 cryptography via k256
- **SHA3-256 hashing**: Domain-separated hashing with chain-id replay protection
- **Binary codec**: Deterministic little-endian serialization with bounds checking
- **Async networking**: Tokio-based P2P with pluggable transport abstraction
- **Concurrent mempool**: Lock-free transaction pool via DashMap

## Project Structure

```
src/
├── core/           # Block, transaction, blockchain state, validation
├── network/        # P2P server, transport abstraction, RPC messages
├── crypto/         # Key pair generation, signing, address derivation
├── types/          # Hash, Address, Bytes, binary encoding
└── utils/          # Logging

blockchain_derive/  # Procedural macros (BinaryCodec, Error)
```

## Requirements

- Rust 1.84+ (edition 2024)

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run
```

## Test

```bash
cargo test
```

## Check (format + lint + test)

```bash
./check
```

## Architecture

### Data Structures (can be subject to future changes)

| Type | Size | Notes |
|------|------|-------|
| Header | 88 bytes | Copy, contains version/height/timestamp/hashes |
| Hash | 32 bytes | Copy, SHA3-256 output |
| Address | 20 bytes | Copy, derived from public key |
| PublicKey | 52 bytes | Copy, secp256k1 verifying key + cached address |

### Consensus

- Height-based chain selection (no fork tracking)
- Block validation: height linearity, hash continuity, signature verification
- Validator signs blocks with Schnorr signature

### Limits (can be and will be subject to future changes)

| Resource | Limit |
|----------|-------|
| Transaction pool | 100,000 transactions |
| Block size | 20,000 transactions |
| Vector decode | 1,000,000 elements |
| Bytes decode | 8 MiB |

## Dependencies

| Crate | Purpose |
|-------|---------|
| tokio | Async runtime |
| sha3 | SHA3-256 hashing |
| k256 | secp256k1 Schnorr signatures |
| dashmap | Concurrent hash map |

## Status

Implemented:
- Wire format with canonical encoding
- Block/transaction hashing and signing
- Block production and broadcasting
- Transaction pool with deduplication
- In-memory storage backend

Not implemented:
- State model (accounts/UTXO)
- Transaction fees and ordering
- Disk persistence
- Chain reorg logic
- Smart contracts

See `checklist.md` for an idea of what still needs to be done.

## License

See LICENSE file.
