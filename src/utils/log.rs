//! Simple logging module with macros.

use std::fmt::Display;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

/// Log level for filtering messages.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info = 1,
    Warn = 2,
    Error = 3,
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

pub static SHOW_TIMESTAMP: AtomicBool = AtomicBool::new(true);
pub static SHOW_TYPE: AtomicBool = AtomicBool::new(true);

/// Internal logging function. Use the `info!`, `warn!`, or `error!` macros instead.
#[doc(hidden)]
pub fn log(level: Level, message: &str) {
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

    let mut stderr = StandardStream::stderr(ColorChoice::Auto);
    let mut spec = ColorSpec::new();
    match level {
        Level::Warn => {
            spec.set_fg(Some(Color::Yellow)).set_bold(true);
        }
        Level::Error => {
            spec.set_fg(Some(Color::Red)).set_bold(true);
        }
        Level::Info => {
            spec.clear();
        }
    }
    let _ = stderr.set_color(&spec);

    if SHOW_TIMESTAMP.load(Ordering::Relaxed) {
        let _ = write!(
            stderr,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} ",
            year, month, day, hours, mins, s, millis
        );
    }
    if SHOW_TYPE.load(Ordering::Relaxed) {
        let _ = write!(stderr, "[{:5}] ", level);
    }
    let _ = writeln!(stderr, "{}", message);
    let _ = stderr.reset();
}

/// Logs an info-level message.
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        if cfg!(not(test)) {
            $crate::utils::log::log($crate::utils::log::Level::Info, &format!($($arg)*), );
        }
    }};
}

/// Logs a warning-level message.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        if cfg!(not(test)) {
            $crate::utils::log::log($crate::utils::log::Level::Warn, &format!($($arg)*))
        }
    }};
}

/// Logs an error-level message.
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{
        if cfg!(not(test)) {
            $crate::utils::log::log($crate::utils::log::Level::Error, &format!($($arg)*))
        }
    }};
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
}
