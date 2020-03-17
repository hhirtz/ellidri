//! Configuration parsing and structures.
//!
//! See [`doc/ellidri.conf`][1] on the repository for an explanation of each setting.
//!
//! [1]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/ellidri.conf

// TODO use bind_to 0.0.0.0:6697 .  to generate a certificate
use self::parser::{Parser, ModeString, Oper};
use std::{fmt, io, net, path};
use std::ops::Range;

mod parser;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Format(Parser, Option<usize>, Range<usize>, String),
}

impl From<io::Error> for Error {
    fn from(val: io::Error) -> Self { Self::Io(val) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::Format(parser, lineno, col, msg) => {
                writeln!(f, "{}", msg)?;
                if let Some(lineno) = lineno {
                    writeln!(f, "     |")?;
                    parser.lines().enumerate()
                        .skip_while(|(lno, _)| lno + 3 < *lineno)
                        .take_while(|(lno, _)| lno <= lineno)
                        .try_for_each(|(lno, line)| writeln!(f, "{:4} | {}", lno + 1, line))?;
                    let start = col.start + 1;
                    let len = col.end - col.start;
                    writeln!(f, "     |{0:1$}{2:^<3$}", ' ', start, '^', len)?;
                }
                Ok(())
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Settings for `State`.
#[derive(Default)]
pub struct State {
    pub domain: String,

    pub default_chan_mode: String,
    pub motd_file: Option<String>,
    pub password: Option<String>,
    pub opers: Vec<(String, String)>,

    pub org_name: String,
    pub org_location: String,
    pub org_mail: String,

    pub channellen: usize,
    pub kicklen: usize,
    pub nicklen: usize,
    pub topiclen: usize,
    pub userlen: usize,
}

/// Listening address + port + optional TLS settings.
pub struct Binding {
    pub address: net::SocketAddr,
    pub tls_identity: Option<path::PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaslBackend {
    None,
    Database,
}

impl Default for SaslBackend {
    fn default() -> Self { Self::None }
}

impl fmt::Display for SaslBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Database => write!(f, "db"),
        }
    }
}

pub mod db {
    pub enum Driver {
        #[cfg(feature = "sqlite")]
        Sqlite,
        #[cfg(feature = "postgres")]
        Postgres,
    }

    pub struct Url(pub Driver, pub String);
}

/// The whole configuration.
#[derive(Default)]
pub struct Config {
    pub bindings: Vec<Binding>,
    pub workers: usize,
    pub state: State,
    pub sasl_backend: SaslBackend,
    pub db_url: Option<db::Url>,
}

impl State {
    pub /*const*/ fn sample() -> Self {
        Self {
            domain: "ellidri.localdomain".to_owned(),
            default_chan_mode: "+nt".to_owned(),
            motd_file: None,
            password: None,
            opers: vec![],
            org_name: "Ellidri server showcase".to_owned(),
            org_location: "Somewhere on Earth".to_owned(),
            org_mail: "contact@ellidri.localdomain".to_owned(),
            channellen: 50,
            kicklen: 300,
            nicklen: 16,
            topiclen: 300,
            userlen: 64,
        }
    }
}

impl Config {
    pub /*const*/ fn sample() -> Self {
        Self {
            bindings: vec![
                Binding {
                    address: net::SocketAddr::from(([127, 0, 0, 1], 6667)),
                    tls_identity: None,
                }
            ],
            workers: 0,
            state: State::sample(),
            sasl_backend: SaslBackend::None,
            db_url: None,
        }
    }

    /// Reads the configuration file at the given path.
    pub fn from_file<P>(path: P) -> Result<Self>
        where P: AsRef<path::Path>
    {
        let mut res = Self::default();
        let mut default_chan_mode = ModeString(String::new());
        let mut opers = Vec::new();
        let parser = Parser::read(path)?;

        let parser = parser
            .setting("bind_to", |values| res.bindings = values)?
            .setting("oper",    |values| opers = values)?
            .unique_setting("workers",           false, |value| res.workers = value)?
            .unique_setting("domain",            true,  |value| res.state.domain = value)?
            .unique_setting("org_name",          true,  |value| res.state.org_name = value)?
            .unique_setting("org_location",      true,  |value| res.state.org_location = value)?
            .unique_setting("org_mail",          true,  |value| res.state.org_mail = value)?
            .unique_setting("default_chan_mode", false, |value| default_chan_mode = value)?
            .unique_setting("motd_file",         false, |value| res.state.motd_file = Some(value))?
            .unique_setting("password",          false, |value| res.state.password = Some(value))?
            .unique_setting("channellen",        false, |value| res.state.channellen = value)?
            .unique_setting("kicklen",           false, |value| res.state.kicklen = value)?
            .unique_setting("nicklen",           false, |value| res.state.nicklen = value)?
            .unique_setting("topiclen",          false, |value| res.state.topiclen = value)?
            .unique_setting("userlen",           false, |value| res.state.userlen = value)?
            .unique_setting("sasl_backend",      false, |value| res.sasl_backend = value)?;

        let db_needed = res.sasl_backend == SaslBackend::Database;
        let parser = parser
            .unique_setting("db_url", db_needed, |value| res.db_url = Some(value))?;

        parser.check_unknown_settings()?;

        res.state.default_chan_mode = default_chan_mode.0;
        for Oper(name, pass) in opers {
            res.state.opers.push((name, pass));
        }

        res.validate()?;
        Ok(res)
    }

    fn validate(&mut self) -> Result<()> {
        let def = Self::sample();

        if self.state.default_chan_mode.is_empty() {
            self.state.default_chan_mode = def.state.default_chan_mode;
        }
        if self.state.channellen == 0 { self.state.channellen = def.state.channellen; }
        if self.state.kicklen == 0 { self.state.kicklen = def.state.kicklen; }
        if self.state.nicklen == 0 { self.state.nicklen = def.state.kicklen; }
        if self.state.topiclen == 0 { self.state.topiclen = def.state.topiclen; }
        if self.state.userlen == 0 { self.state.userlen = def.state.userlen; }
        Ok(())
    }
}
