//! Configuration file specification and parsing.
//!
//! # Usage
//!
//! ```rust,ignore
//! let Config { domain, motd, .. } = config::from_file("ellidri.toml");
//! ```

use serde::Deserialize;
use std::path::Path;
use std::{fs, process, net};

fn bind_to_address() -> net::SocketAddr {
    net::SocketAddr::from(([0, 0, 0, 0], 6667))
}

/// The main configuration. It contains all options read from the configuration
/// file.
#[derive(Deserialize)]
pub struct Config {
    /// The IP and TCP port to which to bind.
    #[serde(default = "bind_to_address")]
    pub bind_to_address: net::SocketAddr,

    /// The domain of the irc server. Sent to clients in most IRC messages.
    pub domain: String,

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
    let contents = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Senpai! I can't open your config file!!");
        eprintln!("It looks like {}", e);
        process::exit(1);
    });
    toml::from_str(&contents).unwrap_or_else(|e| {
        eprintln!("Oh no... senpai made a mistake in here...");
        eprintln!("Senpai, I don't know what to do with {}", e);
        eprintln!("Please fix that quickly senpai!!");
        eprintln!("        o_O                 THNK Y FR YR PTNC");
        process::exit(1);
    })
}

impl Config {
    /// Returns the validated/cleaned log level.
    ///
    /// TODO make `from_file` fail if the content is invalid and remove this
    /// function.
    pub fn log_level(&self) -> Option<&str> {
        self.log_level.as_ref().and_then(|lvl| lvl.split_whitespace().next())
    }
}
