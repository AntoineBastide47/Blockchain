//! Fixed-capacity array with optional elements.
//!
//! Provides a stack-allocated array that tracks which slots contain values,
//! supporting indexed and sequential insertion/removal without heap allocation.

/// Fixed-capacity array storing up to `N` elements of type `T`.
///
/// Unlike `Vec`, this array is stack-allocated with compile-time capacity.
/// Slots can be empty (`None`) or occupied (`Some(T)`), allowing sparse storage
/// and indexed insertion at arbitrary positions within bounds.
#[derive(Clone)]
pub struct Array<T: Sized + Eq + PartialEq + Clone, const N: usize> {
    /// Number of elements currently stored (tracks highest occupied index + 1).
    len: usize,
    /// Fixed-size backing storage with optional slots.
    data: [Option<T>; N],
}

impl<T: Sized + Eq + PartialEq + Clone, const N: usize> Array<T, N> {
    /// Creates an empty array with all slots initialized to `None`.
    pub fn new() -> Array<T, N> {
        Self {
            len: 0,
            data: std::array::from_fn(|_| None),
        }
    }

    /// Returns the current logical length (highest occupied index + 1).
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns the maximum capacity `N`.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns `true` if the array contains the given element.
    pub fn contains(&self, element: T) -> bool {
        for it in &self.data {
            if let Some(el) = it
                && *el == element
            {
                return true;
            }
        }
        false
    }

    /// Appends a value at the next available index.
    ///
    /// No-op if the array is at capacity.
    pub fn insert_value(&mut self, value: T) {
        if self.len == N {
            return;
        }
        self.data[self.len] = Some(value);
        self.len += 1;
    }

    /// Inserts a value at the specified index, updating length accordingly.
    ///
    /// No-op if `index >= N`. Overwrites any existing value at that index.
    pub fn insert_at(&mut self, index: usize, value: T) {
        if index >= N {
            return;
        }
        self.data[index] = Some(value);
        self.len = index + 1;
    }

    /// Removes and returns the last element, or `None` if empty.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }

        self.len -= 1;
        self.data[self.len].take()
    }

    /// Removes the first occurrence of `value` and returns it.
    ///
    /// Shifts subsequent elements left to fill the gap.
    pub fn remove_value(&mut self, value: &T) -> Option<T> {
        for i in 0..self.len {
            if self.data[i].as_ref() == Some(value) {
                return self.remove_at(i);
            }
        }
        None
    }

    /// Removes the element at `index`, shifting subsequent elements left.
    fn remove_at(&mut self, index: usize) -> Option<T> {
        let removed = self.data[index].take();

        for i in index..self.len - 1 {
            self.data[i] = self.data[i + 1].take();
        }

        self.len -= 1;
        self.data[self.len] = None;

        removed
    }
}
