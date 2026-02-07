use crate::types::hash::Hash;

/// Execution context passed to the VM during contract execution.
///
/// Contains chain and contract identifiers used to namespace storage keys,
/// as well as gas metering configuration.
pub struct ExecContext {
    /// Chain identifier for storage key derivation.
    pub chain_id: u64,
    /// Contract identifier for storage key derivation.
    pub contract_id: Hash,
}

/// Call stack frame storing return address and destination register.
#[derive(Clone, Debug)]
pub(super) struct CallFrame {
    /// Return address (bytecode offset to resume after call).
    pub(super) return_addr: usize,
    /// Destination register for return value.
    pub(super) dst_reg: u8,
}
