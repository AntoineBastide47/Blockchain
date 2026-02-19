/// Number of gas categories tracked by [`GasProfile`].
const GAS_CATEGORY_COUNT: usize = 10;

/// Categories of gas consumption for profiling and debugging.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasCategory {
    /// Intrinsic cost of the transaction
    Intrinsic = 0,
    /// Initial contract deployment cost (base + bytecode size).
    Deploy = 1,
    /// Base cost for executing opcodes.
    OpcodeBase = 2,
    /// Cost for deriving state storage keys.
    StateKeyDerivation = 3,
    /// Cost for writing to state storage.
    StateStore = 4,
    /// Cost for reading from state storage.
    StateRead = 5,
    /// Cost for heap allocations (strings, hashes).
    HeapAllocation = 6,
    /// Cost for function call overhead (arguments, stack depth).
    CallOverhead = 7,
    /// Cost for host function execution.
    HostFunction = 8,
    /// Cost for memory interactions.
    Memory = 9,
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

    /// All categories in discriminant order.
    const ALL: [GasCategory; GAS_CATEGORY_COUNT] = [
        GasCategory::Intrinsic,
        GasCategory::Deploy,
        GasCategory::OpcodeBase,
        GasCategory::StateKeyDerivation,
        GasCategory::StateStore,
        GasCategory::StateRead,
        GasCategory::HeapAllocation,
        GasCategory::CallOverhead,
        GasCategory::HostFunction,
        GasCategory::Memory,
    ];
}

/// Gas consumption profile for debugging and optimization.
///
/// Tracks how gas is distributed across different execution categories,
/// enabling developers to identify expensive operations in their contracts.
/// Backed by a flat array indexed by [`GasCategory`] discriminant for
/// branch-free accumulation on the hot path.
#[derive(Clone, Debug)]
pub struct GasProfile {
    counts: [u64; GAS_CATEGORY_COUNT],
}

impl Default for GasProfile {
    fn default() -> Self {
        Self {
            counts: [0; GAS_CATEGORY_COUNT],
        }
    }
}

impl GasProfile {
    /// Creates a new empty gas profile.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds gas to the specified category.
    #[inline(always)]
    pub fn add(&mut self, category: GasCategory, amount: u64) {
        let slot = &mut self.counts[category as usize];
        *slot = slot.saturating_add(amount);
    }

    /// Returns the total gas across all categories.
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(0u64, |acc, &v| acc.saturating_add(v))
    }

    /// Returns an iterator over all categories and their gas costs.
    pub fn iter(&self) -> impl Iterator<Item = (GasCategory, u64)> {
        GasCategory::ALL.into_iter().zip(self.counts)
    }
}

/// Maximum cumulative gas allowed for all transactions in a block.
pub const BLOCK_GAS_LIMIT: u64 = 30_000_000;
