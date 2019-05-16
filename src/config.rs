//! Configuration file specification and parsing.
//!
//! # Usage
//!
//! ```rust,ignore
//! let Config { domain, motd, .. } = config::from_file("ellidri.toml");
//! ```

use serde::Deserialize;
use std::path::Path;
use std::{fmt, fs, process, net};

fn bind_to_address() -> net::SocketAddr {
    net::SocketAddr::from(([0, 0, 0, 0], 6667))
}

fn worker_threads() -> usize {
    1
}

/// The main configuration. It contains all options read from the configuration
/// file.
#[derive(Deserialize)]
pub struct Config {
    /// The domain of the irc server. Sent to clients in most IRC messages.
    pub domain: String,

    /// The IP and TCP port to which to bind.
    ///
    /// It is set to *:6667 by default.
    #[serde(default = "bind_to_address")]
    pub bind_to_address: net::SocketAddr,

    /// The optional log level.
    ///
    /// Valid values are:
    /// - "trace": report incoming and outgoing messages.
    /// - "debug": report clients actions (default for dev builds).
    /// - "info": report new/closed connections (default for releases).
    /// - "warn": report warnings.
    /// - "error": report critical errors/bugs in the program.
    pub log_level: Option<String>,

    /// The message of the day.
    ///
    /// It can span on multiple lines by using three double-quotes (""") at the
    /// beginning and at the end. Empty lines are not ignored, but it is trimmed
    /// (it seems).
    pub motd: Option<String>,

    /// The number of threads spawned by tokio.
    ///
    /// Must be between 1 and 32,768. It is set to 1 by default.
    #[serde(default = "worker_threads")]
    pub worker_threads: usize,
}

fn invalid_config<T, E>(err: E) -> T
    where E: fmt::Display
{
    eprintln!("Oh no... senpai made a mistake in here...");
    eprintln!("Senpai, I don't know what to do with {}", err);
    eprintln!("Please fix that quickly senpai!!");
    eprintln!("        o_O                 THNK Y FR YR PTNC");
    process::exit(1)
}

/// Reads the configuration file at `path`, or exit if there is an error.
///
/// Error cases:
/// - can't open and read the file (does not exist, missing permissions, ...).
/// - can't decode its contents (missing value, invalid format).
///
/// # TODO
///
/// - validate the `domain` and the `log_level`.
pub fn from_file<P>(path: P) -> Config
    where P: AsRef<Path>
{
    let contents = fs::read_to_string(path).unwrap_or_else(|err| {
        eprintln!("Senpai! I can't open your config file!!");
        eprintln!("It looks like {}", err);
        process::exit(1);
    });
    let config: Config = toml::from_str(&contents).unwrap_or_else(|err| {
        invalid_config(err)
    });
    if !(1 <= config.worker_threads && config.worker_threads <= 32768) {
        invalid_config("worker_threads must be between 1 and 32768.")
    }
    if let Some(ref log_level) = config.log_level {
        if log_level != "trace" && log_level != "debug" && log_level != "info"
            && log_level != "warn" && log_level != "error"
        {
            invalid_config(r#"log_level must be "trace", "debug", "info", "warn" or "error"."#)
        }
    }
    config
}
