# Blockchain

Minimal, safety-first blockchain in Rust, focused on pedagogy and clarity across consensus, networking, and VM layers.

> [!NOTE]
> Edition 2024; tuned for Rust 1.84+.
> Node identities live at `~/.blockchain/{chain_id}/{node_name}/identity.key`, encrypted via Argon2id + XChaCha20-Poly1305.

## Highlights
- Deterministic binary codec for all hashes/keys/blocks/txs
- SHA3-256 hashing with chain-id separation
- Schnorr signatures on `k256`
- libp2p transport (Noise + Yamux) plus local in-memory transport for tests
- Concurrent mempool with fixed caps/eviction (DashMap + heap), plus register-based VM with hashed state keys

## Quickstart

| Action               | Command                                                   |
|----------------------|-----------------------------------------------------------|
| Build (release)      | `cargo build --release`                                   |
| Run node             | `cargo run -- <listen_addr>`                              |
| Compile assembly     | `cargo run --bin assembler -- program.asm -o program.bin` |
| Test                 | `cargo test`                                              |
| Format + lint + test | `./check`                                                 |

## CLI Usage
- `cargo run <listen_addr> [--name <id>] [--peer <addr>] [--validator]`
- `listen_addr`: e.g., `127.0.0.1:3000`
- `--name`: optional node identifier (also used for key storage path)
- `--peer`: optional peer to connect on startup
- `--validator`: start block production with a validator key on disk
- Passphrase: `NODE_PASSPHRASE` env var or interactive prompt (used to decrypt node keys)

## Recommended git `pre-commit` hook
It is recommended to set your git pre-commit to the following code to reduce CI failures:  
```bash
#!/bin/sh
set -e

echo "[pre-commit] Formatting + Linting + Running Tests"
./check

echo "[pre-commit] Staging format changes"
git add -u

exit 0
```
<details>

<summary>Full command to set it</summary>

```bash
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
set -e

echo "[pre-commit] Formatting + Linting + Running Tests"
./check

echo "[pre-commit] Staging format changes"
git add -u

exit 0
EOF

chmod +x .git/hooks/pre-commit
```

</details>

## Repo Map
```
src/
├── bin/                # Assembler CLI
├── core/               # Blocks, transactions, blockchain orchestration, validator rules
├── crypto/             # Schnorr keys + encrypted disk persistence
├── network/            # P2P server, libp2p transport, message framing, RPC types
├── storage/            # In-memory block store, sparse Merkle state, tx pool
├── types/              # Hash/Bytes, deterministic binary codec, Merkle helpers
├── utils/              # Logging and test helpers
└── virtual_machine/    # 256-register VM, assembler, ISA, gas metering

blockchain_derive/  # Procedural macros (BinaryCodec, Error)
```

## Architecture

### Node pipeline
- Transport: libp2p (Noise + Yamux) with request/response RPC and identify; 16 MiB message cap.
- Server: gossips transactions/blocks, maintains tx pool, and syncs via status + block range RPCs.
- Storage: in-memory block/index storage plus sparse Merkle tree for state and read-only views.
- Execution: register-based VM executes transaction bytecode in per-tx overlays; block overlay merged into canonical SMT.
- Validation: `BlockValidator` checks heights, parents, signatures, nonces/balances, gas limit; applies blocks into storage.

### Data Structures

| Type      | Size      | Notes                                                    |
|-----------|-----------|----------------------------------------------------------|
| Header    | 128 bytes | Version, height, timestamp, previous/merkle/state hashes |
| Hash      | 32 bytes  | SHA3-256 output                                          |
| Address   | 32 bytes  | Domain-separated SHA3 of verifying key                   |
| PublicKey | 64 bytes  | secp256k1 Schnorr verifying key (cached address)         |

> [!WARNING]
> Sizes and layouts may evolve as the consensus/state model firms up.

### Consensus & Chain
- Height-only chain selection (no fork tracking yet)
- Block validation covers height continuity, parent hash, state_root, and Schnorr signatures
- Domain-separated hashing for replay protection

### Networking
- libp2p RPC over request-response with identify; bidirectional address learning for peers
- Encrypted identity key material on disk; single-process lock per node directory

### Limits

| Resource         | Limit                |
|------------------|----------------------|
| Transaction pool | 100,000 transactions |
| RPC payload      | 16 MiB               |
| Transaction size | 100,000 B            |
| Block size       | 2,000,000 B          |
| Transaction gas  | 1,000,000 gas        |
| Block gas        | 20,000,000 gas       |

### Virtual Machine
- 256-register bytecode VM with string/hash/boolean/int types and a string pool
- Host calls: `len`, `slice`, `concat`, `compare`, `hash`
- Per-tx overlay state merged into block overlay; state_root covers all writes (sparse Merkle backing store)

### Dependencies

| Crate                             | Purpose                            |
|-----------------------------------|------------------------------------|
| tokio                             | Async runtime                      |
| sha3                              | SHA3-256 hashing                   |
| k256                              | secp256k1 Schnorr signatures       |
| dashmap                           | Concurrent hash map (mempool)      |
| libp2p                            | Networking transport and protocols |
| argon2, chacha20poly1305, zeroize | Encrypted identity key storage     |

## Status

**Implemented**
- Deterministic binary codec and chain-separated hashing/signing
- Block production/broadcasting with signed validator blocks and genesis bootstrap
- Transaction pool with deduplication and hard caps
- In-memory block store backed by sparse Merkle tree state + read-only views
- Register-based VM, assembler CLI, and host functions (`len`, `slice`, `concat`, `compare`, `hash`)
- Encrypted on-disk node identity + validator keys with single-process locking
- libp2p transport (Noise + Yamux) with request/response RPC and tests using local in-memory transport

**Missing / TODO**
- Disk persistence and fast recovery (blocks/state)
- Economic rules (fees/gas pricing), fork choice, and reorg handling
- Robust mempool policies and gossip; stronger sync/handshake and block request caps
- Storage pruning/snapshotting and production-ready database backend

## License

See `LICENSE`.

## References
The following references include a collection of articles and videos that have served as the foundation for building the blockchain (the list will evolve over time):
- Core blockchain functionality: [Create a modular blockchain from scratch](https://www.youtube.com/playlist?list=PL0xRBLFXXsP6-hxQmCDcl_BHJMm0mhxx7) (by [Anthony GG](https://www.youtube.com/@anthonygg_))

> [!IMPORTANT]
> These resources are guides. They provide insights but may not result in an identical blockchain implementation. Concrete example: the playlist above is written in Go with a stack-based VM; this project is in Rust and uses a register-based VM.
