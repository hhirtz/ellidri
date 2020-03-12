//! Configuration parsing and structures.
//!
//! See [`doc/ellidri.conf`][1] on the repository for an explanation of each setting.
//!
//! [1]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/ellidri.conf

use std::{fmt, fs, io, net, path, str};
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

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
                    parser.lines.iter().enumerate()
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

fn rangestr(inner: &str, outer: &str) -> Range<usize> {
    let ilen = inner.len();
    let inner = inner.as_ptr() as usize;
    let outer = outer.as_ptr() as usize;
    let offset = inner - outer;
    offset..offset + ilen
}

struct ModeString(pub String);
struct Oper(pub String, pub String);

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

/// Listening address + port + optional TLS settings.
pub struct Binding {
    pub address: net::SocketAddr,
    pub tls_identity: Option<path::PathBuf>,
}

/// The whole configuration.
#[derive(Default)]
pub struct Config {
    pub bindings: Vec<Binding>,
    pub workers: usize,
    pub state: State,
}

pub trait TypeName {
    fn type_name() -> String;
}

impl TypeName for usize {
    fn type_name() -> String { "a positive integer".to_owned() }
}

impl TypeName for String {
    fn type_name() -> String { "a string".to_owned() }
}

impl TypeName for Binding {
    fn type_name() -> String { "following the format \"bind_to <address> [path]\"".to_owned() }
}

impl TypeName for ModeString {
    fn type_name() -> String { "a valid mode string".to_owned() }
}

impl TypeName for Oper {
    fn type_name() -> String { "following the format \"oper <name> <password>\"".to_owned() }
}

impl str::FromStr for ModeString {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if crate::modes::is_channel_mode_string(s) {
            Ok(ModeString(s.to_owned()))
        } else {
            Err(())
        }
    }
}

impl str::FromStr for Oper {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut words = s.split_whitespace();
        let name = words.next().ok_or(())?;
        let pass = words.next().ok_or(())?;
        Ok(Oper(name.to_owned(), pass.to_owned()))
    }
}

impl str::FromStr for Binding {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut words = s.splitn(2, char::is_whitespace).map(str::trim);
        let address = words.next().ok_or(())?
            .parse().map_err(|_| ())?;
        let tls_identity = words.next()
            .map(|word| word.parse().map_err(|_| ()))
            .transpose()?;
        Ok(Binding { address, tls_identity })
    }
}

#[derive(Default, Debug)]
pub struct Parser {
    lines: Vec<String>,
    settings: BTreeMap<usize, Setting>,
    occurences: HashMap<String, Vec<usize>>,
}

#[derive(Debug, Clone)]
pub struct Setting {
    lineno: usize,
    krange: Range<usize>,
    vrange: Range<usize>,
}

impl Parser {
    pub fn read<P>(path: P) -> Result<Self>
        where P: AsRef<path::Path>
    {
        let lines = fs::read_to_string(path)?.lines().map(str::to_owned).collect();
        let mut res = Self { lines, ..Self::default() };

        for (lineno, line) in res.lines.iter().enumerate() {
            let mut split = line.splitn(2, ' ').map(str::trim).filter(|s| !s.is_empty());

            let key = if let Some(key) = split.next() {key} else {continue};
            if key.starts_with('#') { continue; }
            let krange = rangestr(key, line);

            let value = if let Some(value) = split.next() {
                value
            } else {
                return Err(res.error(lineno, krange, "this setting has no value"));
            };
            let vrange = rangestr(value, line);

            res.settings.insert(lineno, Setting { lineno, krange, vrange });
            res.occurences.entry(key.to_owned()).or_default().push(lineno);
        }

        Ok(res)
    }

    pub fn unique_required_setting<S, F>(self, key: &str, and_then: F) -> Result<Self>
        where S: str::FromStr + TypeName,
              F: FnOnce(S),
    {
        if !self.occurences.contains_key(key) {
            return Err(Error::Format(self, None, 0..0, format!("missing setting {:?}", key)));
        }
        self.unique_setting(key, and_then)
    }

    pub fn unique_setting<S, F>(mut self, key: &str, and_then: F) -> Result<Self>
        where S: str::FromStr + TypeName,
              F: FnOnce(S),
    {
        if let Some(occ) = self.occurences.get(key) {
            if occ.is_empty() {
                unreachable!("occurences must not have empty Vecs");
            }
            if occ.len() > 1 {
                let last = *occ.last().unwrap();
                let setting = &self.settings[&last];
                let krange = setting.krange.clone();
                let msg = format!("{:?} must not appear more than once. Specified at lines {:?}",
                                  key, occ);
                return Err(self.error(last, krange, msg));
            }
            let lineno = occ[0];
            let setting = &self.settings[&lineno];
            let value = match self.lines[lineno][setting.vrange.clone()].parse() {
                Ok(value) => value,
                Err(_) => {
                    let msg = format!("this setting must be {}", S::type_name());
                    let vrange = setting.vrange.clone();
                    return Err(self.error(lineno, vrange, msg));
                }
            };
            and_then(value);
        }
        self.occurences.remove(key);
        Ok(self)
    }

    pub fn setting<S, F>(mut self, key: &str, and_then: F) -> Result<Self>
        where S: str::FromStr + TypeName,
              F: FnOnce(Vec<S>),
    {
        if let Some(occ) = self.occurences.get(key) {
            if occ.is_empty() {
                unreachable!("occurences must not have empty Vecs");
            }
            let mut res = Vec::new();
            for setting in occ.iter().map(|lno| self.settings[lno].clone()) {
                let value = match self.lines[setting.lineno][setting.vrange.clone()].parse() {
                    Ok(value) => value,
                    Err(_) => {
                        let msg = format!("this setting must be {}", S::type_name());
                        return Err(self.error(setting.lineno, setting.vrange, msg));
                    }
                };
                res.push(value);
            }
            and_then(res);
        }
        self.occurences.remove(key);
        Ok(self)
    }

    pub fn check_unknown_settings(self) -> Result<()> {
        if let Some((key, occ)) = self.occurences.iter().next() {
            if occ.is_empty() {
                unreachable!("occurences must not have empty Vecs");
            }
            let lineno = occ[0];
            let setting = &self.settings[&lineno];
            let krange = setting.krange.clone();
            let msg = format!("unknown setting {:?}", key);
            return Err(self.error(lineno, krange, msg));
        }
        Ok(())
    }

    pub fn error<S>(self, lineno: usize, col: Range<usize>, msg: S) -> Error
        where S: Into<String>
    {
        Error::Format(self, Some(lineno), col, msg.into())
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
        }
    }

    /// Reads the configuration file at the given path.
    ///
    /// Exits the program on failure (this behavior could change).
    pub fn from_file<P>(path: P) -> Result<Config>
        where P: AsRef<path::Path>
    {
        let mut res = Self::default();
        let mut default_chan_mode = ModeString(String::new());
        let mut opers = Vec::new();
        let mut parser = Parser::read(path)?;

        if cfg!(feature = "threads") {
            parser = parser.unique_setting("workers", |value| res.workers = value)?;
        }

        parser
            .setting("bind_to", |values| res.bindings = values)?
            .unique_required_setting("domain", |value| res.state.domain = value)?
            .unique_setting("default_chan_mode", |value| default_chan_mode = value)?
            .unique_setting("motd_file", |value| res.state.motd_file = Some(value))?
            .unique_setting("password", |value| res.state.password = Some(value))?
            .setting("oper", |values| opers = values)?
            .unique_required_setting("org_name", |value| res.state.org_name = value)?
            .unique_required_setting("org_location", |value| res.state.org_location = value)?
            .unique_required_setting("org_mail", |value| res.state.org_mail = value)?
            .unique_setting("channellen", |value| res.state.channellen = value)?
            .unique_setting("kicklen", |value| res.state.kicklen = value)?
            .unique_setting("nicklen", |value| res.state.nicklen = value)?
            .unique_setting("topiclen", |value| res.state.topiclen = value)?
            .unique_setting("userlen", |value| res.state.userlen = value)?
            .check_unknown_settings()?;

        res.state.default_chan_mode = default_chan_mode.0;
        for Oper(name, pass) in opers {
            res.state.opers.push((name, pass));
        }

        res.validate()?;
        Ok(res)
    }

    fn validate(&mut self) -> Result<()> {
        let def = Config::sample();

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
