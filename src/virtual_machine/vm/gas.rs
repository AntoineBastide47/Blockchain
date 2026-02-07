/// Categories of gas consumption for profiling and debugging.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GasCategory {
    /// Intrinsic cost of the transaction
    Intrinsic,
    /// Initial contract deployment cost (base + bytecode size).
    Deploy,
    /// Base cost for executing opcodes.
    OpcodeBase,
    /// Cost for deriving state storage keys.
    StateKeyDerivation,
    /// Cost for writing to state storage.
    StateStore,
    /// Cost for reading from state storage.
    StateRead,
    /// Cost for heap allocations (strings, hashes).
    HeapAllocation,
    /// Cost for function call overhead (arguments, stack depth).
    CallOverhead,
    /// Cost for host function execution.
    HostFunction,
    /// Cost for memory interactions.
    Memory,
}

impl GasCategory {
    pub const fn as_str(&self) -> &'static str {
        match self {
            GasCategory::Intrinsic => "Intrinsic",
            GasCategory::Deploy => "Deployment",
            GasCategory::OpcodeBase => "Opcode Base",
            GasCategory::StateKeyDerivation => "State Key Derivation",
            GasCategory::StateStore => "State Store",
            GasCategory::StateRead => "State Read",
            GasCategory::HeapAllocation => "Heap Allocation",
            GasCategory::CallOverhead => "Call Overhead",
            GasCategory::HostFunction => "Host Function",
            GasCategory::Memory => "Memory",
        }
    }
}

/// Gas consumption profile for debugging and optimization.
///
/// Tracks how gas is distributed across different execution categories,
/// enabling developers to identify expensive operations in their contracts.
#[derive(Clone, Debug, Default)]
pub struct GasProfile {
    intrinsic: u64,
    deploy: u64,
    opcode_base: u64,
    state_key_derivation: u64,
    state_store: u64,
    state_read: u64,
    heap_allocation: u64,
    call_overhead: u64,
    host_function: u64,
    memory: u64,
}

impl GasProfile {
    /// Creates a new empty gas profile.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds gas to the specified category.
    pub fn add(&mut self, category: GasCategory, amount: u64) {
        match category {
            GasCategory::Intrinsic => self.intrinsic = self.intrinsic.saturating_add(amount),
            GasCategory::Deploy => self.deploy = self.deploy.saturating_add(amount),
            GasCategory::OpcodeBase => self.opcode_base = self.opcode_base.saturating_add(amount),
            GasCategory::StateKeyDerivation => {
                self.state_key_derivation = self.state_key_derivation.saturating_add(amount)
            }
            GasCategory::StateStore => self.state_store = self.state_store.saturating_add(amount),
            GasCategory::StateRead => self.state_read = self.state_read.saturating_add(amount),
            GasCategory::HeapAllocation => {
                self.heap_allocation = self.heap_allocation.saturating_add(amount)
            }
            GasCategory::CallOverhead => {
                self.call_overhead = self.call_overhead.saturating_add(amount)
            }
            GasCategory::HostFunction => {
                self.host_function = self.host_function.saturating_add(amount)
            }
            GasCategory::Memory => self.memory = self.memory.saturating_add(amount),
        }
    }

    /// Returns the total gas across all categories.
    pub fn total(&self) -> u64 {
        self.deploy
            .saturating_add(self.intrinsic)
            .saturating_add(self.opcode_base)
            .saturating_add(self.state_key_derivation)
            .saturating_add(self.state_store)
            .saturating_add(self.state_read)
            .saturating_add(self.heap_allocation)
            .saturating_add(self.call_overhead)
            .saturating_add(self.host_function)
            .saturating_add(self.memory)
    }

    /// Returns an iterator over all categories and their gas costs.
    pub fn iter(&self) -> impl Iterator<Item = (GasCategory, u64)> {
        [
            (GasCategory::Intrinsic, self.intrinsic),
            (GasCategory::Deploy, self.deploy),
            (GasCategory::OpcodeBase, self.opcode_base),
            (GasCategory::StateKeyDerivation, self.state_key_derivation),
            (GasCategory::StateStore, self.state_store),
            (GasCategory::StateRead, self.state_read),
            (GasCategory::HeapAllocation, self.heap_allocation),
            (GasCategory::CallOverhead, self.call_overhead),
            (GasCategory::HostFunction, self.host_function),
            (GasCategory::Memory, self.memory),
        ]
        .into_iter()
    }
}

/// Maximum cumulative gas allowed for all transactions in a block.
pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;
