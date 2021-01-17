//! Configuration structures.
//!
//! See [`doc/ellidri.conf`][1] on the repository for an explanation of each setting.
//!
//! [1]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/ellidri.conf

use ellidri_tokens::mode;
use scfg::Scfg;
use std::convert::TryFrom;
use std::{fmt, fs, io, net, path};
use tokio_rustls::webpki;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Format(scfg::ParseError),
    Content(String),
    InvalidDomain,
    InvalidModes,
}

impl Error {
    fn s(message: impl Into<String>) -> Error {
        Error::Content(message.into())
    }
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
    fn from(val: io::Error) -> Self {
        Self::Io(val)
    }
}

impl From<scfg::ParseError> for Error {
    fn from(val: scfg::ParseError) -> Self {
        Self::Format(val)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::Format(err) => err.fmt(f),
            Self::Content(message) => message.fmt(f),
            Self::InvalidDomain => write!(f, "'domain' must be a domain name (e.g. irc.com)"),
            Self::InvalidModes => write!(f, "'default_chan_mode' must be a mode string (e.g. +nt)"),
        }
    }
}

/// TLS-related and needed information for TLS bindings.
#[derive(Clone, Debug, PartialEq)]
pub struct Tls {
    pub certificate: path::PathBuf,
    pub key: path::PathBuf,
}

/// Listening address + port + optional TLS settings.
#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub address: net::SocketAddr,
    pub tls: Option<Tls>,
}

impl TryFrom<&scfg::Directive> for Binding {
    type Error = Error;

    fn try_from(directive: &scfg::Directive) -> Result<Binding> {
        let address = directive
            .params()
            .get(0)
            .ok_or_else(|| Error::s("'listen' directive is missing the listen address"))?
            .parse()
            .map_err(|err| {
                Error::Content(format!(
                    "'listen' directive has bad listen address: {}",
                    err
                ))
            })?;
        let tls = directive.child().and_then(|child| {
            let certificate = child.get("certificate")?.params().get(0)?.into();
            let key = child.get("key")?.params().get(0)?.into();
            Some(Tls { certificate, key })
        });
        Ok(Binding { address, tls })
    }
}

/// OPER credentials
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Oper {
    pub name: String,
    pub password: String,
}

/// Settings for `State`.
pub struct State {
    pub domain: String,
    pub org_name: String,
    pub org_location: String,
    pub org_mail: String,
    pub default_chan_mode: String,
    pub motd_file: String,
    pub opers: Vec<Oper>,
    pub password: String,
    pub awaylen: usize,
    pub channellen: usize,
    pub keylen: usize,
    pub kicklen: usize,
    pub namelen: usize,
    pub nicklen: usize,
    pub topiclen: usize,
    pub userlen: usize,
    pub login_timeout: u64,
}

impl Default for State {
    fn default() -> State {
        State {
            domain: String::from("ellidri.localdomain"),
            org_name: String::from("unspecified"),
            org_location: String::from("unspecified"),
            org_mail: String::from("unspecified"),
            default_chan_mode: String::from("+nst"),
            motd_file: String::from("/etc/motd"),
            opers: Vec::new(),
            password: String::new(),
            awaylen: 300,
            channellen: 50,
            keylen: 24,
            kicklen: 300,
            namelen: 64,
            nicklen: 32,
            topiclen: 300,
            userlen: 64,
            login_timeout: 60_000,
        }
    }
}

/// The whole configuration.
pub struct Config {
    pub bindings: Vec<Binding>,
    pub workers: usize,
    pub state: State,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bindings: vec![Binding {
                address: net::SocketAddr::from(([127, 0, 0, 1], 6667)),
                tls: None,
            }],
            workers: 0,
            state: State::default(),
        }
    }
}

fn get_setting_str(doc: &Scfg, name: &str) -> Option<Result<String>> {
    doc.get(name).map(|directive| {
        directive
            .params()
            .get(0)
            .cloned()
            .ok_or_else(|| Error::Content(format!("'{}' is missing a paramater", name)))
    })
}

fn get_setting_usize(doc: &Scfg, name: &str) -> Option<Result<usize>> {
    doc.get(name).map(|directive| {
        directive
            .params()
            .get(0)
            .cloned()
            .ok_or_else(|| Error::Content(format!("'{}' is missing a paramater", name)))?
            .parse()
            .map_err(|_| Error::Content(format!("'{}' only accepts an integer", name)))
    })
}

impl Config {
    /// Reads the configuration file at the given path.
    pub fn from_file(path: impl AsRef<path::Path>) -> Result<Self> {
        let doc: Scfg = fs::read_to_string(path)?.parse()?;
        let mut res = Config::default();

        if let Some(listen_directives) = doc.get_all("listen") {
            res.bindings.clear();
            for listen_directive in listen_directives {
                res.bindings.push(Binding::try_from(listen_directive)?)
            }
        }
        if let Some(workers) = get_setting_usize(&doc, "workers") {
            res.workers = workers?;
        }
        if let Some(domain) = get_setting_str(&doc, "domain") {
            res.state.domain = domain?;
            if webpki::DNSNameRef::try_from_ascii_str(&res.state.domain).is_err() {
                return Err(Error::InvalidDomain);
            }
        }
        if let Some(org) = doc.get("admin_info") {
            let org = org
                .child()
                .ok_or_else(|| Error::s("'admin_info' has an empty body"))?;
            if let Some(org_name) = get_setting_str(&org, "name") {
                res.state.org_name = org_name?;
            }
            if let Some(org_location) = get_setting_str(&org, "location") {
                res.state.org_location = org_location?;
            }
            if let Some(org_mail) = get_setting_str(&org, "mail") {
                res.state.org_mail = org_mail?;
            }
        }
        if let Some(default_chan_mode) = get_setting_str(&doc, "default_chan_mode") {
            res.state.default_chan_mode = default_chan_mode?;
            if !mode::is_channel_mode_string(&res.state.default_chan_mode) {
                return Err(Error::InvalidModes);
            }
        }
        if let Some(motd_file) = get_setting_str(&doc, "motd_file") {
            res.state.motd_file = motd_file?.into();
        }
        for oper in doc.get_all("oper").unwrap_or(&[]) {
            let password = oper
                .params()
                .get(1)
                .ok_or_else(|| Error::s("'oper' must have two parameters"))?
                .clone();
            let name = oper.params().get(0).unwrap().clone();
            res.state.opers.push(Oper { name, password });
        }
        if let Some(password) = get_setting_str(&doc, "password") {
            res.state.password = password?;
        }
        if let Some(awaylen) = get_setting_usize(&doc, "awaylen") {
            res.state.awaylen = awaylen?;
        }
        if let Some(channellen) = get_setting_usize(&doc, "channellen") {
            res.state.channellen = channellen?;
        }
        if let Some(keylen) = get_setting_usize(&doc, "keylen") {
            res.state.keylen = keylen?;
        }
        if let Some(kicklen) = get_setting_usize(&doc, "kicklen") {
            res.state.kicklen = kicklen?;
        }
        if let Some(namelen) = get_setting_usize(&doc, "namelen") {
            res.state.namelen = namelen?;
        }
        if let Some(nicklen) = get_setting_usize(&doc, "nicklen") {
            res.state.nicklen = nicklen?;
        }
        if let Some(topiclen) = get_setting_usize(&doc, "topiclen") {
            res.state.topiclen = topiclen?;
        }
        if let Some(userlen) = get_setting_usize(&doc, "userlen") {
            res.state.userlen = userlen?;
        }
        if let Some(login_timeout) = get_setting_usize(&doc, "login_timeout") {
            res.state.login_timeout = login_timeout? as u64;
        }

        Ok(res)
    }
}
