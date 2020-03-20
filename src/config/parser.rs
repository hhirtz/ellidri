use std::{fs, path, str};
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use super::{Binding, db, Error, Result, SaslBackend};

fn rangestr(inner: &str, outer: &str) -> Range<usize> {
    let ilen = inner.len();
    let inner = inner.as_ptr() as usize;
    let outer = outer.as_ptr() as usize;
    let offset = inner - outer;
    offset..offset + ilen
}

pub struct ModeString(pub String);
pub struct Oper(pub String, pub String);

pub trait TypeName {
    fn type_name() -> String;
}

impl TypeName for bool {
    fn type_name() -> String { "\"true\" or \"false\"".to_owned() }
}

impl TypeName for u64 {
    fn type_name() -> String { format!("a positive integer (and lower than {})", u64::max_value()) }
}

impl TypeName for usize {
    fn type_name() -> String {
        format!("a positive integer (and lower than {})", usize::max_value())
    }
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

impl TypeName for SaslBackend {
    fn type_name() -> String { "\"none\" or \"db\"".to_owned() }
}

impl TypeName for db::Driver {
    fn type_name() -> String {
        if cfg!(all(feature = "sqlite", feature = "postgres")) {
            "\"sqlite\" or \"postgres\"".to_owned()
        } else if cfg!(feature = "sqlite") {
            "\"sqlite\"".to_owned()
        } else if cfg!(feature = "postgres") {
            "\"postgres\"".to_owned()
        } else {
            "omitted, ellidri hasn't been built with database support".to_owned()
        }
    }
}

impl TypeName for db::Url {
    fn type_name() -> String {
        if cfg!(all(feature = "sqlite", feature = "postgres")) {
            "an url like \"sqlite://...\" or \"postgres://...\"".to_owned()
        } else if cfg!(feature = "sqlite") {
            "an url like \"sqlite://...\"".to_owned()
        } else if cfg!(feature = "postgres") {
            "an url like \"postgres://...\"".to_owned()
        } else {
            "omitted, ellidri hasn't been built with database support".to_owned()
        }
    }
}

impl str::FromStr for SaslBackend {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "db" => Ok(Self::Database),
            _ => Err(()),
        }
    }
}

impl str::FromStr for db::Driver {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "sqlite")]
            "sqlite" => Ok(Self::Sqlite),
            #[cfg(feature = "postgres")]
            "postgres" | "postgresql" | "psql" => Ok(Self::Postgres),
            _ => Err(()),
        }
    }
}

impl str::FromStr for db::Url {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut split = s.splitn(2, "://");
        let driver = split.next().ok_or(())?.parse()?;
        let url = split.next().ok_or(())?;
        Ok(db::Url(driver, url.to_owned()))
    }
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
    pub lineno: usize,
    pub krange: Range<usize>,
    pub vrange: Range<usize>,
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

    pub fn unique_setting<S, F>(mut self, key: &str, required: bool, and_then: F) -> Result<Self>
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
        } else if required {
            return Err(Error::Format(self, None, 0..0, format!("missing setting {:?}", key)));
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

    pub fn lines(&self) -> impl Iterator<Item=&str> + '_ {
        self.lines.iter().map(String::as_ref)
    }
}
