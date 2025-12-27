//! Simple logging module.

use std::fmt::Display;
use std::sync::Arc;
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
#[derive(Clone)]
pub struct Logger {
    pub id: Arc<str>,
}

impl Logger {
    /// Creates a new logger with the given identifier.
    pub fn new(id: impl Into<Arc<str>>) -> Self {
        Self { id: id.into() }
    }

    /// Logs an info-level message.
    pub fn info(&self, message: &str) {
        log_with_id(Level::Info, Some(&self.id), message);
    }

    /// Logs a warning-level message.
    pub fn warn(&self, message: &str) {
        log_with_id(Level::Warn, Some(&self.id), message);
    }

    /// Logs an error-level message.
    pub fn error(&self, message: &str) {
        log_with_id(Level::Error, Some(&self.id), message);
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
    fn logger_new_with_string() {
        let logger = Logger::new("test-id");
        // Logger should be created without panic
        logger.info("test message");
    }

    #[test]
    fn logger_new_with_arc_str() {
        let id: Arc<str> = "arc-id".into();
        let logger = Logger::new(id);
        logger.info("test message");
    }

    #[test]
    fn logger_clone() {
        let logger1 = Logger::new("clone-test");
        let logger2 = logger1.clone();

        // Both loggers should work independently
        logger1.info("from logger1");
        logger2.info("from logger2");
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
