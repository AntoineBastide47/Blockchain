//! Simple logging module.

use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};

/// Log level for filtering messages.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Level::Trace => write!(f, "TRACE"),
            Level::Debug => write!(f, "DEBUG"),
            Level::Info => write!(f, "INFO"),
            Level::Warn => write!(f, "WARN"),
            Level::Error => write!(f, "ERROR"),
        }
    }
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Initialize the logger with the given level.
pub fn init(level: Level) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Returns true if the given level should be logged.
#[inline]
pub fn enabled(level: Level) -> bool {
    level as u8 >= LOG_LEVEL.load(Ordering::Relaxed)
}

/// Internal logging function.
#[doc(hidden)]
pub fn log(level: Level, message: &str) {
    if enabled(level) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let hours = (secs / 3600) % 24;
        let mins = (secs / 60) % 60;
        let s = secs % 60;
        let millis = now.subsec_millis();
        eprintln!(
            "{:02}:{:02}:{:02}.{:03} [{:5}] {}",
            hours, mins, s, millis, level, message
        );
    }
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        if $crate::utils::log::enabled($crate::utils::log::Level::Trace) {
            $crate::utils::log::log($crate::utils::log::Level::Trace, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::utils::log::enabled($crate::utils::log::Level::Debug) {
            $crate::utils::log::log($crate::utils::log::Level::Debug, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::utils::log::enabled($crate::utils::log::Level::Info) {
            $crate::utils::log::log($crate::utils::log::Level::Info, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        if $crate::utils::log::enabled($crate::utils::log::Level::Warn) {
            $crate::utils::log::log($crate::utils::log::Level::Warn, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        if $crate::utils::log::enabled($crate::utils::log::Level::Error) {
            $crate::utils::log::log($crate::utils::log::Level::Error, &format!($($arg)*));
        }
    };
}
