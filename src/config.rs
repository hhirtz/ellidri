//! Configuration structures.
//!
//! See [`doc/ellidri.conf`][1] on the repository for an explanation of each setting.
//!
//! [1]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/ellidri.conf

use ellidri_tokens::mode;
use serde::{Deserialize, Serialize};
use std::{fmt, fs, io, net, path};
use tokio_rustls::webpki;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Format(serde_yaml::Error),
    InvalidDomain,
    InvalidModes,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Format(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(val: io::Error) -> Self { Self::Io(val) }
}

impl From<serde_yaml::Error> for Error {
    fn from(val: serde_yaml::Error) -> Self { Self::Format(val) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::Format(err) => err.fmt(f),
            Self::InvalidDomain => write!(f, "'domain' must be a domain name (e.g. irc.com)"),
            Self::InvalidModes => write!(f, "'default_chan_mode' must be a mode string (e.g. +nt)"),
        }
    }
}

impl fmt::Display for SaslBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Database => write!(f, "database"),
        }
    }
}

/// TLS-related and needed information for TLS bindings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Tls {
    pub certificate: path::PathBuf,
    pub key: path::PathBuf,
    #[serde(default = "require_certificates")]
    pub require_certificates: bool,
}

/// Listening address + port + optional TLS settings.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Binding {
    pub address: net::SocketAddr,
    #[serde(flatten)]
    pub tls: Option<Tls>,
}

/// OPER credentials
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Oper {
    pub name: String,
    pub password: String,
}

/// Settings for `State`.
#[derive(Deserialize, Serialize)]
pub struct State {
    #[serde(default = "domain")]
    pub domain: String,

    #[serde(default = "default_chan_mode")]
    pub default_chan_mode: String,

    #[serde(default = "motd_file")]
    pub motd_file: String,

    pub password: Option<String>,

    #[serde(default)]
    pub opers: Vec<Oper>,

    #[serde(default = "org")]
    pub org_name: String,
    #[serde(default = "org")]
    pub org_location: String,
    #[serde(default = "org")]
    pub org_mail: String,

    #[serde(default = "awaylen")]
    pub awaylen: usize,
    #[serde(default = "channellen")]
    pub channellen: usize,
    #[serde(default = "keylen")]
    pub keylen: usize,
    #[serde(default = "kicklen")]
    pub kicklen: usize,
    #[serde(default = "namelen")]
    pub namelen: usize,
    #[serde(default = "nicklen")]
    pub nicklen: usize,
    #[serde(default = "topiclen")]
    pub topiclen: usize,
    #[serde(default = "userlen")]
    pub userlen: usize,

    #[serde(default = "login_timeout")]
    pub login_timeout: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SaslBackend {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "database")]
    Database,
}

pub mod db {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub enum Driver {
        #[cfg(feature = "sqlite")]
        #[serde(rename = "sqlite")]
        Sqlite,
        #[cfg(feature = "postgres")]
        #[serde(rename = "postgres", alias = "psql", alias = "postgresql")]
        Postgres,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Info {
        pub driver: Driver,
        pub url: String
    }
}

/// The whole configuration.
#[derive(Deserialize, Serialize)]
pub struct Config {
    #[serde(rename = "unsafe", default)]
    pub is_unsafe: bool,

    #[serde(default = "bindings")]
    pub bindings: Vec<Binding>,

    #[cfg(feature = "websocket")]
    pub ws_endpoint: Option<net::SocketAddr>,

    #[serde(default)]
    pub workers: usize,

    #[serde(flatten)]
    pub state: State,

    #[serde(default = "sasl_backend")]
    pub sasl_backend: SaslBackend,

    pub database: Option<db::Info>,
}

fn require_certificates() -> bool { true }

fn bindings() -> Vec<Binding> {
    vec![Binding {
        address: net::SocketAddr::from(([127, 0, 0, 1], 6667)),
        tls: None,
    }]
}

fn sasl_backend() -> SaslBackend { SaslBackend::None }

fn domain() -> String { String::from("ellidri.localdomain") }
fn default_chan_mode() -> String { String::from("+nst") }
fn motd_file() -> String { String::from("/etc/motd") }
fn org() -> String { String::from("unspecified") }
fn awaylen() -> usize { 300 }
fn channellen() -> usize { 50 }
fn keylen() -> usize { 24 }
fn kicklen() -> usize { 300 }
fn namelen() -> usize { 64 }
fn nicklen() -> usize { 32 }
fn topiclen() -> usize { 300 }
fn userlen() -> usize { 64 }
fn login_timeout() -> u64 { 60_000 }

impl State {
    pub fn sample() -> Self {
        Self {
            domain: domain(),
            default_chan_mode: default_chan_mode(),
            motd_file: motd_file(),
            password: None,
            opers: vec![],
            org_name: org(),
            org_location: org(),
            org_mail: org(),
            awaylen: awaylen(),
            channellen: channellen(),
            keylen: keylen(),
            kicklen: kicklen(),
            namelen: namelen(),
            nicklen: nicklen(),
            topiclen: topiclen(),
            userlen: userlen(),
            login_timeout: login_timeout(),
        }
    }
}

impl Config {
    pub fn sample() -> Self {
        Self {
            is_unsafe: false,
            bindings: bindings(),
            #[cfg(feature = "websocket")]
            ws_endpoint: None,
            workers: 0,
            state: State::sample(),
            sasl_backend: sasl_backend(),
            database: None,
        }
    }

    /// Reads the configuration file at the given path.
    pub fn from_file(path: impl AsRef<path::Path>) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let res: Self = serde_yaml::from_str(&contents)?;

        if webpki::DNSNameRef::try_from_ascii_str(&res.state.domain).is_err() {
            return Err(Error::InvalidDomain);
        }

        if !mode::is_channel_mode_string(&res.state.default_chan_mode) {
            return Err(Error::InvalidModes);
        }

        Ok(res)
    }
}
