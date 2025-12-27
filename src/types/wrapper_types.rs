//! Common type aliases used across the codebase.

use std::future::Future;
use std::pin::Pin;

/// A boxed, pinned, send-safe future.
///
/// Used for trait objects that return futures, enabling async trait methods
/// without the `async-trait` crate overhead.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
