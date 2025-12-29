# Implementation Checklist Status

Only items that are complete or partially complete in this codebase are marked.

## Status legend
- ✅ Completed
- 🟡 Partially completed
- ❌ Not done

## Checklist

1. **Freeze the wire format**
   - ✅ Canonical byte encoding via `BinaryCodec` for core types (`Hash`, `PublicKey`, `Signature`, `Header`, `Transaction`, `Block`, RPC messages).  
   - ✅ `usize` avoided on the wire; fixed-width ints used.  
   - 🟡 Decode bounds cover vector length and total bytes; still no per-field bespoke limits. Encode short-circuits oversize vectors instead of panicking.  
   - 🟡 Roundtrip tests cover many types plus RPC/Message payloads; still not exhaustive for all network messages.

2. **Define the state model**
   - ❌ Accounts vs UTXO not chosen.  
   - ❌ State keys/values and update rules not defined.  
   - ❌ Genesis state not defined (only a structural genesis block).

3. **Define transaction rules**
   - ❌ Full fields (nonce/recipient/amount/fee/gas params) not defined; only signer, signature, payload.  
   - 🟡 Stateless validation: signature check with chain-id/domain separation present; size/format bounds still minimal.  
   - 🟡 Safety/efficiency tweaks: encode/decode bounds in place and mempool caps added, but still no fee model.  
   - ❌ Stateful validation (nonce/balance/fee affordability) not implemented.  
   - ✅ Deterministic transaction hash (TxID) implemented.

4. **Define block rules**
   - ✅ Header fields and hashing rule defined.  
   - 🟡 Block validity: parent tip/height/+1/uniqueness/signatures/data hash checked and chain-id bound; no timestamp bounds; merkle root unused.  
   - ❌ Block size/gas constraints (`max_txs`, `max_bytes`, `block_gas_limit`) not defined/enforced.  
   - ✅ Deterministic block hash.

5. **Implement the state transition function**
   - ❌ `apply_tx` not implemented.  
   - ❌ `apply_block` (stateful) not implemented.  
   - ❌ No-state/IO/clock/rand constraints unaddressed.  
   - ❌ No fixed-vector unit tests for state transitions.

6. **Implement persistence**
   - 🟡 KV-like storage in-memory for headers/blocks/tip; no durable store.  
   - 🟡 Tip updates are in-memory mutex-protected; no atomic durable writes with state.  
   - ❌ Startup recovery/rebuild not implemented.

7. **Implement chain selection**
   - 🟡 Best-chain rule implicit height-only at tip; no explicit policy.  
   - ❌ Competing tips/fork tracking not stored.  
   - ❌ Reorg logic not implemented.

8. **Implement mempool**
   - 🟡 Admission: signature check only; no minimal stateful checks.  
   - 🟡 Hard caps: count enforced; block-building capped to 20,000 txs; no byte-level cap.  
   - ❌ Fee-based ordering/index not present.  
   - 🟡 Evict/reject under pressure: rejects when full by count, not fee-aware.  
   - ✅ No VM execution in mempool.

9. **Implement block production**
   - 🟡 Block template assembly: takes mempool insertion order; no fee/gas-based selection; no size/gas limits.  
   - ❌ Execute `apply_block` (stateful) not present; invalid txs not state-checked.  
   - ✅ Blocks are signed (validator key).  
   - ✅ Blocks broadcast.  
   - ❌ Block limits (gas/bytes): TODO

10. **Implement networking**
    - 🟡 Message types limited to tx/block; no handshake/version/getheaders/etc.  
    - 🟡 DoS bounds: vector-length cap only; no max message size per type, rate limits, or timeouts.  
    - 🟡 Validate before storing: decode + basic stateless checks; minimal.  
    - ❌ Networking state is coupled with consensus/state logic.

11. **Implement sync**
    - ❌ No header-first sync.  
    - ❌ No block fetch/apply sync pipeline.  
    - ❌ No reorg handling during sync.

12. **Implement observability and safety**
    - 🟡 Errors and logging present.  
    - ❌ Panics remain on oversize encode; unwraps in some code/tests.  
    - 🟡 Structured errors for some components; not universal.  
    - ✅ Logging is deterministic (no consensus-dependent randomness).  
    - ❌ No fuzzing of decode/handlers.

13. **Minimum acceptance tests**
    - 🟡 Unit tests for serialization/storage/validator/txpool/local transport.  
    - ❌ Single-node persistence/restart tests missing.  
    - ❌ Two-node propagation/sync tests missing.  
    - ❌ Fork/reorg tests missing.  
    - ❌ Spam/mempool pressure tests missing.

14. **Only then: implement the VM**
    - ❌ Gas schedule/op semantics not defined.  
    - ❌ Interpreter not implemented.  
    - ❌ Metering/limits not integrated.  
    - ❌ State access model not defined.
