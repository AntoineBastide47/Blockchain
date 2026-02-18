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
    /// Address of the account that initiated the current transaction.
    pub caller: Hash,
}
