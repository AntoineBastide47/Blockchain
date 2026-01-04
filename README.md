# Blockchain

Minimal, safety-first blockchain in Rust, focused on pedagogy and clarity across consensus, networking, and VM layers.

> [!NOTE]
> Edition 2024; tuned for Rust 1.84+. Node identities live at `~/.blockchain/{chain_id}/{node_name}/identity.key`, encrypted via Argon2id + XChaCha20-Poly1305; passphrase comes from `NODE_PASSPHRASE` or an interactive prompt.

## Highlights
- Deterministic binary codec for all hashes/keys/blocks/txs
- SHA3-256 hashing with chain-id separation
- Schnorr signatures on `k256`
- libp2p transport (Noise + Yamux) plus local in-memory transport for tests
- Lock-free mempool with fixed caps, plus register-based VM with hashed state keys

## Quickstart

| Action | Command |
| --- | --- |
| Build (release) | `cargo build --release` |
| Run node | `cargo run` |
| Test | `cargo test` |
| Format + lint + test | `./check` |

## CLI Usage
- `cargo run <listen_addr> [--name <id>] [--peer <addr>] [--validator]`
- `listen_addr`: e.g., `127.0.0.1:3000`
- `--name`: optional node identifier (also used for key storage path)
- `--peer`: optional peer to connect on startup
- `--validator`: start with a fresh validator key (in-memory)
- Passphrase: `NODE_PASSPHRASE` env var or interactive prompt

## Repo Map
```
src/
├── core/           # Blocks, txs, validation, blockchain state
├── network/        # P2P server, transport abstraction, RPC messages
├── crypto/         # Keys, signing, address derivation
├── types/          # Hash, Address, Bytes, binary encoding
└── utils/          # Logging helpers

blockchain_derive/  # Procedural macros (BinaryCodec, Error)
```

## Architecture

### Data Structures

| Type | Size | Notes |
| --- | --- | --- |
| Header | 152 bytes | Version, height, timestamp, previous/data/merkle/state hashes |
| Hash | 32 bytes | SHA3-256 output |
| Address | 20 bytes | Derived from public key |
| PublicKey | 52 bytes | secp256k1 verifying key + cached address |

> [!WARNING]
> Sizes and layouts may evolve as the consensus/state model firms up.

### Consensus & Chain
- Height-only chain selection (no fork tracking yet)
- Block validation covers height continuity, parent hash, state_root, and Schnorr signatures
- Domain-separated hashing for replay protection

### Networking
- libp2p RPC over request-response with identify; 16 MiB message cap
- Encrypted identity key material on disk; single-process lock per node directory

### Limits

| Resource | Limit |
| --- | --- |
| Transaction pool | 100,000 transactions |
| Block size | 20,000 transactions |
| Vector decode | 1,000,000 elements |
| Bytes decode | 8 MiB |

### Virtual Machine
- 256-register bytecode VM with string pool
- Per-tx overlay state merged into block overlay; state_root covers all writes
- Host calls stubbed (no externals yet)

### Dependencies

| Crate | Purpose |
| --- | --- |
| tokio | Async runtime |
| sha3 | SHA3-256 hashing |
| k256 | secp256k1 Schnorr signatures |
| dashmap | Concurrent hash map (mempool) |
| libp2p | Networking transport and protocols |
| argon2, chacha20poly1305, zeroize | Encrypted identity key storage |

## Status

**Implemented**
- Canonical wire format with deterministic hashes and signatures
- Block production/broadcasting with signed validator blocks
- Transaction pool with deduplication and hard caps
- In-memory storage backend
- Minimal register-based VM
- Encrypted on-disk node identity with single-process locking

**Missing / TODO**
- State model (accounts vs UTXO) and fee rules
- Stateful tx/block validation and block size/gas limits
- Persistence and recovery
- Fork tracking and reorg handling
- Full sync/handshake protocol and fee-aware mempool

See `checklist.md` for detailed progress.

## License

See `LICENSE`.

## References
The following references include a collection of articles and videos that have served as the foundation for building the blockchain (the list will evolve over time):
- Core blockchain functionality: [Create a modular blockchain from scratch](https://www.youtube.com/playlist?list=PL0xRBLFXXsP6-hxQmCDcl_BHJMm0mhxx7) (by [Anthony GG](https://www.youtube.com/@anthonygg_))

> [!IMPORTANT]
> These resources are guides. They provide insights but may not result in an identical blockchain implementation. Concrete example: the playlist above is written in Go with a stack-based VM; this project is in Rust and uses a register-based VM.
