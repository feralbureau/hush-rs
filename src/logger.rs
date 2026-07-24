//! Colored terminal logger for Hush.
//!
//! Mirrors [`hush-go/server/logger.go`](https://github.com/feralbureau/hush-go/blob/main/server/logger.go).

use std::fmt;
use std::io::Write;
use std::time::SystemTime;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[90m";
const BLUE: &str = "\x1b[34m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";

/// A minimal colored logger writing to stderr.
pub struct Logger {
    tag: String,
}

impl Logger {
    /// Create a new logger with an optional tag (shown dim in brackets).
    pub fn new(tag: &str) -> Self {
        Logger {
            tag: tag.to_string(),
        }
    }

    /// Log an info message with colored timestamp.
    pub fn info(&self, msg: fmt::Arguments<'_>) {
        self.write("INF", BLUE, msg);
    }

    /// Log a warning message.
    pub fn warn(&self, msg: fmt::Arguments<'_>) {
        self.write("WRN", YELLOW, msg);
    }

    /// Log an error message.
    pub fn error(&self, msg: fmt::Arguments<'_>) {
        self.write("ERR", RED, msg);
    }

    fn write(&self, level: &str, color: &str, msg: fmt::Arguments<'_>) {
        let ts = timestamp();
        let tag = if self.tag.is_empty() {
            String::new()
        } else {
            format!(" {DIM}[{}]{RESET}", self.tag)
        };
        let line = format!("{DIM}{ts}{RESET}{tag} {color}[{level}]{RESET} {msg}\n");
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
