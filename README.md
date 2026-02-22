# Blockchain

Minimal, safety-first blockchain in Rust, focused on efficiency, pedagogy and clarity across consensus, networking, and VM layers.

## Highlights
- Deterministic binary codec for all hashes/keys/blocks/txs
- SHA3-256 hashing with chain-id separation
- Schnorr signatures on `k256`
- libp2p transport (Noise + Yamux) plus local in-memory transport for tests
- Concurrent mempool with fixed caps/eviction (DashMap + heap) plus a register-based VM
- Header-first sync with snapshot bootstrap + block replay fallback
- RocksDB-backed chain/state storage with sparse Merkle state, receipts, snapshots, and block-body pruning

## Quickstart

| Action                 | Command                                                                               |
|------------------------|---------------------------------------------------------------------------------------|
| Build (release)        | `cargo build --release`                                                               |
| Run node               | `cargo run -- 127.0.0.1:3000`                                                         |
| Run validator demo     | `cargo run -- 127.0.0.1:3001 --peer 127.0.0.1:3000 --validator`                       |
| Assemble to `.bin`     | `cargo run --bin assembler -- output example_contracts/factorial.asm`                 |
| Audit assembly         | `cargo run --bin assembler -- audit example_contracts/factorial.asm`                  |
| Predict Contract Costs | `cargo run --bin assembler -- predict example_contracts/factorial.asm 'factorial(5)'` |
| Format + lint + test   | `./check`                                                                             |

## CLI Usage
- `cargo run -- <listen_addr> [--name <id>] [--peer <addr>] [--validator]`
- `listen_addr`: e.g., `127.0.0.1:3000`
- `--name`: optional node identifier (also used for key storage path)
- `--peer`: optional peer to connect on startup
- `--validator`: start block production with a validator key on disk
- Passphrase: `NODE_PASSPHRASE` env var or interactive prompt (used to decrypt node keys)

> [!NOTE]
> Current demo behavior: when started with `--validator`, the node auto-deploys `./example_contracts/factorial.asm` and repeatedly submits invoke transactions.

### Assembler CLI
- `cargo run --bin assembler -- [build|output|audit|predict] <input.asm> [options]`
- `build` (default): compile and print summary
- `output [file]`: write bytecode (`<input>.bin` by default)
- `audit [file]`: write audit listing (`<input>.audit.txt` by default)
- `predict [gas_price] [func(args)...]`: estimate gas usage/cost for public calls

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
├── bin/                # CLI tools (assembler + VM benchmark harness)
├── core/               # Blocks, transactions, blockchain orchestration, validator rules
├── crypto/             # Schnorr keys + encrypted disk persistence
├── network/            # P2P server, libp2p transport, message framing, sync state machine
├── storage/            # RocksDB storage, SMT-backed state, snapshots/pruning, tx pool
├── types/              # Hash/Bytes, deterministic binary codec, Merkle helpers
├── utils/              # Logging and test helpers
└── virtual_machine/    # 256-register VM, assembler, ISA, gas metering

blockchain_derive/  # Procedural macros (BinaryCodec, Error)
```

## Architecture

### Node pipeline
- Transport: libp2p (Noise + Yamux) with request/response RPC and identify; 16 MiB message cap.
- Server: gossips transactions/blocks, maintains a mempool, and runs header-first sync via status/headers/blocks/snapshot RPCs.
- Storage: RocksDB column families for headers/blocks/meta/state/snapshots/receipts, with an SMT-backed state cache and read-only state views.
- Execution: transactions run in per-tx overlays, merged into a block overlay; receipts and `receipt_root` are computed during block build/apply.
- Validation: `BlockValidator` checks height/parent linkage, signatures, nonces/balances, block gas, timestamps, and receipt roots.

### Data Structures

| Type      | Size                     | Notes                                                            |
|-----------|--------------------------|------------------------------------------------------------------|
| Header    | 160 bytes (in memory)    | 156 bytes encoded; includes `gas_used`, `merkle_root`, `state_root`, `receipt_root` |
| Hash      | 32 bytes                 | SHA3-256 output                                                  |
| Address   | 32 bytes                 | Domain-separated SHA3 of verifying key                           |
| PublicKey | 32 bytes (encoded)       | Schnorr verifying key; address is cached in memory               |

> [!WARNING]
> Sizes and layouts may evolve as the consensus/state model firms up.

### Consensus & Chain
- Height-only chain selection (no fork tracking yet)
- Validator nodes attempt block production every 6 seconds (`BLOCK_TIME`)
- Block validation covers height continuity, parent hash, signatures, timestamps, `state_root`, and `receipt_root`
- Block rewards are currently a placeholder staking formula plus collected priority fees
- Domain-separated hashing for replay protection

### Networking
- libp2p RPC over request-response with identify; bidirectional address learning for peers
- Header-first sync with snapshot bootstrap (when far behind) and block replay batches
- Encrypted identity key material on disk; single-process lock per node directory

### Limits

|  Resource            | Limit                            |
|----------------------|----------------------------------|
| Transaction pool     | 100,000 transactions             |
| RPC payload          | 16 MiB                           |
| Header sync batch    | 500 headers                      |
| Block sync batch     | 100 blocks                       |
| Transaction size     | 100,000 B                        |
| Block size           | 2,000,000 B                      |
| Block gas            | 30,000,000 gas                   |
| Snapshot interval    | 1,000 blocks (default)           |
| Block body retention | 30 blocks (snapshot blocks kept) |

### Virtual Machine
- 256-register bytecode VM with typed values (`Int`, `Bool`, `Ref`); `r0` is hardwired to zero
- Variable-length ISA with arithmetic, branching, calls/returns, calldata, memory (`MEM_*`), state (`LOAD/STORE/DELETE_STATE`), and `SHA3`
- Host calls: `caller`, `len`, `concat`, `compare`, `slice`
- Deploy/runtime split programs (`DeployProgram`) plus typed call payloads (`ExecuteProgram`), bytecode format version `0.5.0`
- Per-tx overlay state merged into block overlay; state_root covers all writes (sparse Merkle backing store)

### Dependencies

| Crate                             | Purpose                            |
|-----------------------------------|------------------------------------|
| tokio                             | Async runtime                      |
| sha3                              | SHA3-256 hashing                   |
| k256                              | secp256k1 Schnorr signatures       |
| dashmap                           | Concurrent hash map (mempool)      |
| libp2p                            | Networking transport and protocols |
| rocksdb, sparse-merkle-tree       | Persistent storage + state root    |
| argon2, chacha20poly1305, zeroize | Encrypted identity key storage     |

## Status

**Implemented**
- Deterministic binary codec and chain-separated hashing/signing
- Block production/broadcasting with signed validator blocks, receipts, and genesis bootstrap
- Transaction pool with deduplication, nonce ordering, capacity cap, and eviction by priority fee
- RocksDB-backed persistent storage (headers/blocks/meta/state/snapshots/receipts) with SMT-backed state roots
- Header-first sync + snapshot import/export + block replay + post-sync state-root verification
- Register-based VM, assembler CLI (`build/output/audit/predict`), gas profiling, and VM benchmark binary
- VM host functions (`caller`, `len`, `concat`, `compare`, `slice`) plus `SHA3` opcode
- Encrypted on-disk node identity + validator keys with single-process locking
- libp2p transport (Noise + Yamux) with request/response RPC and tests using local in-memory transport

**Missing / TODO**
- Fork choice / reorg handling and stronger finality semantics
- Real staking/economic rules (current validator reward logic is placeholder)
- More robust mempool policy/replacement rules and production gossip controls
- Snapshot chunking/proofs/streaming (current snapshot RPC sends full state response)

## License

See `LICENSE`.

## References
The following references include a collection of articles and videos that have served as the foundation for building the blockchain (the list will evolve over time):
- Core blockchain functionality: [Create a modular blockchain from scratch](https://www.youtube.com/playlist?list=PL0xRBLFXXsP6-hxQmCDcl_BHJMm0mhxx7) (by [Anthony GG](https://www.youtube.com/@anthonygg_))

> [!IMPORTANT]
> These resources are guides. They provide insights but may not result in an identical blockchain implementation. Concrete example: the playlist above is written in Go with a stack-based VM; this project is in Rust and uses a register-based VM.
