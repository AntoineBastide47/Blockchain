//! Simple logging module.

use blockchain_derive::BinaryCodec;
use std::fmt::{self, Display};
use std::sync::atomic::{AtomicU8, Ordering};

/// Log level for filtering messages.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info = 1,
    Warn = 2,
    Error = 34,
}

impl Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Info => write!(f, "INFO"),
            Level::Warn => write!(f, "WARN"),
            Level::Error => write!(f, "ERROR"),
        }
    }
}

/// Maximum length for logger identifiers.
pub const LOG_ID_MAX_LEN: usize = 32;

/// Fixed-size logger identifier (max 32 bytes).
///
/// Stores UTF-8 data inline without heap allocation. Inputs longer than
/// 32 bytes are truncated at the nearest valid UTF-8 boundary.
#[derive(Clone, Copy, BinaryCodec, Debug)]
pub struct LogId {
    data: [u8; LOG_ID_MAX_LEN],
    len: u8,
}

impl LogId {
    /// Creates a new LogId from a string slice, truncating if necessary.
    pub fn new(s: &str) -> Self {
        let bytes = s.as_bytes();
        let mut len = bytes.len().min(LOG_ID_MAX_LEN);

        // Truncate at UTF-8 boundary
        while len > 0 && !s.is_char_boundary(len) {
            len -= 1;
        }

        let mut data = [0u8; LOG_ID_MAX_LEN];
        data[..len].copy_from_slice(&bytes[..len]);

        Self {
            data,
            len: len as u8,
        }
    }

    /// Returns the identifier as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.data[..self.len as usize])
            .expect("LogId invariant violated: invalid UTF-8")
    }
}

impl Display for LogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for LogId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for LogId {
    fn from(s: String) -> Self {
        Self::new(&s)
    }
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Initialize the logger with the given level.
pub fn init(level: Level) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Returns true if the given level should be logged.
#[inline]
fn enabled(level: Level) -> bool {
    level as u8 >= LOG_LEVEL.load(Ordering::Relaxed)
}

/// Converts days since Unix epoch to (year, month, day).
fn days_to_date(days: u64) -> (u32, u32, u32) {
    // Algorithm based on Howard Hinnant's date algorithms
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m, d)
}

/// Internal logging function with optional identifier prefix.
fn log_with_id(level: Level, id: Option<&str>, message: &str) {
    if enabled(level) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let days = secs / 86400;
        let (year, month, day) = days_to_date(days);
        let hours = (secs / 3600) % 24;
        let mins = (secs / 60) % 60;
        let s = secs % 60;
        let millis = now.subsec_millis();
        match id {
            Some(id) => eprintln!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} [{:5}] [{}] {}",
                year, month, day, hours, mins, s, millis, level, id, message
            ),
            None => eprintln!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} [{:5}] {}",
                year, month, day, hours, mins, s, millis, level, message
            ),
        }
    }
}

/// Thread-safe logger instance with an identifier prefix.
///
/// Each logger instance carries an ID that is prepended to all log messages,
/// allowing differentiation between multiple components (e.g., server instances).
#[derive(Clone, Copy)]
pub struct Logger {
    pub id: LogId,
}

impl Logger {
    /// Creates a new logger with the given identifier.
    pub fn new(id: impl Into<LogId>) -> Self {
        Self { id: id.into() }
    }

    /// Logs an info-level message.
    pub fn info(&self, message: &str) {
        log_with_id(Level::Info, Some(self.id.as_str()), message);
    }

    /// Logs a warning-level message.
    pub fn warn(&self, message: &str) {
        log_with_id(Level::Warn, Some(self.id.as_str()), message);
    }

    /// Logs an error-level message.
    pub fn error(&self, message: &str) {
        log_with_id(Level::Error, Some(self.id.as_str()), message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering() {
        assert!(Level::Info < Level::Warn);
        assert!(Level::Warn < Level::Error);
    }

    #[test]
    fn level_display() {
        assert_eq!(format!("{}", Level::Info), "INFO");
        assert_eq!(format!("{}", Level::Warn), "WARN");
        assert_eq!(format!("{}", Level::Error), "ERROR");
    }

    #[test]
    fn logger_new_with_str() {
        let logger = Logger::new("test-id");
        logger.info("test message");
        assert_eq!(logger.id.as_str(), "test-id");
    }

    #[test]
    fn logger_new_with_string() {
        let id = String::from("string-id");
        let logger = Logger::new(id);
        logger.info("test message");
        assert_eq!(logger.id.as_str(), "string-id");
    }

    #[test]
    fn logger_clone() {
        let logger1 = Logger::new("clone-test");
        let logger2 = logger1;

        logger1.info("from logger1");
        logger2.info("from logger2");
    }

    #[test]
    fn log_id_truncates_long_input() {
        let long = "a".repeat(50);
        let id = LogId::new(&long);
        assert_eq!(id.as_str().len(), LOG_ID_MAX_LEN);
    }

    #[test]
    fn log_id_truncates_at_utf8_boundary() {
        // 3-byte UTF-8 char repeated, then truncated mid-char
        let s = "\u{1234}".repeat(12); // 36 bytes total
        let id = LogId::new(&s);
        // Should truncate to 30 bytes (10 complete chars)
        assert_eq!(id.as_str().len(), 30);
        assert_eq!(id.as_str().chars().count(), 10);
    }

    #[test]
    fn days_to_date_epoch() {
        // Unix epoch is January 1, 1970
        let (year, month, day) = days_to_date(0);
        assert_eq!(year, 1970);
        assert_eq!(month, 1);
        assert_eq!(day, 1);
    }

    #[test]
    fn days_to_date_known_date() {
        // 2024-01-01 is 19723 days after epoch
        let (year, month, day) = days_to_date(19723);
        assert_eq!(year, 2024);
        assert_eq!(month, 1);
        assert_eq!(day, 1);
    }

    #[test]
    fn days_to_date_leap_year() {
        // 2024-02-29 (leap day) is 19782 days after epoch
        let (year, month, day) = days_to_date(19782);
        assert_eq!(year, 2024);
        assert_eq!(month, 2);
        assert_eq!(day, 29);
    }

    #[test]
    fn enabled_respects_level() {
        init(Level::Warn);

        assert!(!enabled(Level::Info));
        assert!(enabled(Level::Warn));
        assert!(enabled(Level::Error));

        // Reset to default for other tests
        init(Level::Info);
    }

    #[test]
    fn init_sets_log_level() {
        init(Level::Error);
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Warn));
        assert!(enabled(Level::Error));

        init(Level::Info);
        assert!(enabled(Level::Info));
    }
}
