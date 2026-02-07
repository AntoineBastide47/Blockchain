use super::WORD_SIZE;
use crate::types::encoding::{Decode, Encode};
use crate::virtual_machine::errors::VMError;
use std::ops::{Index, IndexMut, RangeBounds};

/// Unified memory for the VM, combining constant and execution regions.
///
/// Memory layout: `[const region][execution region]`
/// - **Const region**: Interned string literals and other constant data loaded from the program.
/// - **Execution region**: Dynamic memory allocated during transaction execution.
///
/// The `exec_offset` marks the boundary between const and execution memory. Indexing
/// operations (`[]`) access only the execution region for memory instructions.
pub(super) struct Heap {
    /// Raw memory buffer containing both const and execution regions.
    pub(super) memory: Vec<u8>,
    /// Byte offset where execution memory begins (equals const region size).
    pub(super) exec_offset: usize,
}

impl Heap {
    /// Creates a new heap with the given const memory.
    ///
    /// The execution region starts empty, immediately after the const region.
    pub(super) fn new(memory: Vec<u8>) -> Self {
        Self {
            exec_offset: memory.len(),
            memory,
        }
    }

    /// Appends an item to memory with length-prefix encoding.
    ///
    /// Returns the byte offset where the item was stored.
    pub(super) fn append(&mut self, item: Vec<u8>) -> u32 {
        let index = self.memory.len();
        item.encode(&mut self.memory);
        index as u32
    }

    /// Returns a reference to the raw [`Vec<u8>`] stored at the given index.
    /// Includes the length prefix.
    pub(super) fn get_raw_ref(&self, reference: u32) -> Result<&[u8], VMError> {
        let reference = reference as usize;
        self.memory
            .get(reference)
            .ok_or(VMError::ReferenceOutOfBounds {
                reference,
                max: self.memory.len() - 1,
            })?;
        let data: [u8; WORD_SIZE] = self.memory[reference..reference + WORD_SIZE]
            .try_into()
            .unwrap();
        let size = usize::from_le_bytes(data);

        let bound = reference + WORD_SIZE + size;
        if bound > self.memory.len() {
            return Err(VMError::MemoryOOBRead {
                got: bound,
                max: self.memory.len(),
            });
        }

        Ok(&self.memory[reference..bound])
    }

    /// Returns just the data bytes stored at the given index (without length prefix).
    pub(super) fn get_data(&self, reference: u32) -> Result<&[u8], VMError> {
        let raw = self.get_raw_ref(reference)?;
        Ok(&raw[WORD_SIZE..])
    }

    /// Returns the size of the execution memory region in bytes.
    pub(super) fn len(&self) -> usize {
        self.memory.len().saturating_sub(self.exec_offset)
    }

    /// Resizes the total memory buffer to `new_len`, filling new bytes with `value`.
    pub(super) fn resize(&mut self, new_len: usize, value: u8) {
        self.memory.resize(new_len, value);
    }

    /// Copies bytes within the memory buffer from `src` range to `dest` offset.
    pub(super) fn copy_within<R: RangeBounds<usize>>(&mut self, src: R, dest: usize) {
        self.memory.copy_within(src, dest);
    }

    /// Retrieves a string by its reference index.
    pub(super) fn get_string(&self, id: u32) -> Result<String, VMError> {
        let mut bytes = self.get_raw_ref(id)?;
        String::decode(&mut bytes).map_err(|_| VMError::InvalidUtf8 { string_ref: id })
    }

    /// Returns a slice of the execution memory (memory after exec_offset).
    #[cfg(test)]
    pub(super) fn exec_memory(&self) -> &[u8] {
        &self.memory[self.exec_offset..]
    }
}

/// Indexes into the execution memory region (not the const region).
impl<T> Index<T> for Heap
where
    [u8]: Index<T>,
{
    type Output = <[u8] as Index<T>>::Output;

    fn index(&self, index: T) -> &Self::Output {
        &self.memory[self.exec_offset..][index]
    }
}

/// Mutably indexes into the execution memory region (not the const region).
impl<T> IndexMut<T> for Heap
where
    [u8]: IndexMut<T>,
{
    fn index_mut(&mut self, index: T) -> &mut Self::Output {
        &mut self.memory[self.exec_offset..][index]
    }
}
