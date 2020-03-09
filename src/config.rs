//! Configuration parsing and structures.
//!
//! See [`doc/ellidri.conf`][1] on the repository for an explanation of each setting.
//!
//! [1]: https://git.sr.ht/~taiite/ellidri/tree/master/doc/ellidri.conf

use std::{fs, net, path, process, str};

/// Settings for `State`.
#[derive(Default)]
pub struct StateConfig {
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

/// The whole configuration.
#[derive(Default)]
pub struct Config {
    pub bindings: Vec<Binding>,
    pub workers: usize,

    pub srv: StateConfig,
}

fn format_error(lineno: u32, msg: &str) -> ! {
    eprintln!("Config file error at line {}: {}", lineno, msg);
    process::exit(1);
}

fn missing_setting_error(setting: &str) -> ! {
    eprintln!("Config file error: missing setting {}", setting);
    process::exit(1);
}

fn mod_setting<S, F>(setting: &mut S, key: &str, value: &str, lineno: u32, type_str: &str,
                     validate: F)
    where S: Default + str::FromStr + PartialEq,
          F: FnOnce(&S)
{
    if setting != &S::default() {
        format_error(lineno, &format!("duplicate {} setting", key));
    }
    let value = value.parse().unwrap_or_else(|_| {
        format_error(lineno, &format!("expected {}", type_str));
    });
    validate(&value);
    *setting = value;
}

fn mod_spi_setting(setting: &mut usize, key: &str, value: &str, lineno: u32) {
    mod_setting(setting, key, value, lineno, "a strictly positive integer", |&value| {
        if value <= 0 {
            format_error(lineno, "expected a strictly positive number");
        }
    });
}

fn mod_option_setting<S, F>(setting: &mut Option<S>, key: &str, value: &str, lineno: u32,
                            type_str: &str, validate: F)
    where S: str::FromStr,
          F: FnOnce(&S)
{
    if setting.is_some() {
        format_error(lineno, &format!("duplicate {} setting", key));
    }
    let value = value.parse().unwrap_or_else(|_| {
        format_error(lineno, &format!("expected {}", type_str));
    });
    validate(&value);
    *setting = Some(value);
}

fn add_setting(config: &mut Config, key: &str, value: &str, lineno: u32) {
    if key == "bind_to" {
        let address = value.parse().unwrap_or_else(|_| format_error(lineno, "expected IP address"));
        config.bindings.push(Binding { address, tls_identity: None });
    } else if key == "with_tls" {
        if config.bindings.is_empty() {
            format_error(lineno, "with_tls must be set after a bind_to setting");
        }
        let last = config.bindings.len() - 1;
        if config.bindings[last].tls_identity.is_some() {
            format_error(lineno, "duplicate with_tls setting");
        }
        let id = value.parse().unwrap_or_else(|_| format_error(lineno, "expected a path"));
        config.bindings[last].tls_identity = Some(id);
    } else if cfg!(feature = "threads") && key == "workers" {
        mod_setting(&mut config.workers, key, value, lineno, "a positive integer", |&value| {
            if 32768 < value {
                format_error(lineno, "workers should be between 0 and 32768");
            }
        });
    } else if key == "domain" {
        mod_setting(&mut config.srv.domain, key, value, lineno, "", |_| ());
    } else if key == "default_chan_mode" {
        mod_setting(&mut config.srv.default_chan_mode, key, value, lineno, "", |value| {
            if !crate::modes::is_channel_mode_string(value) {
                format_error(lineno, "default_chan_mode is not a valid mode string");
            }
        });
    } else if key == "motd_file" {
        mod_option_setting(&mut config.srv.motd_file, key, value, lineno, "", |_| ());
    } else if key == "password" {
        mod_option_setting(&mut config.srv.password, key, value, lineno, "", |_| ());
    } else if key == "oper" {
        let mut words = value.split_whitespace();
        let oper_name = words.next().unwrap();
        let oper_pass = words.next().unwrap_or_else(|| {
            format_error(lineno, "oper must follow the format 'oper <name> <password>'");
        });
        config.srv.opers.push((oper_name.to_owned(), oper_pass.to_owned()));
    } else if key == "org_name" {
        mod_setting(&mut config.srv.org_name, key, value, lineno, "", |_| ());
    } else if key == "org_location" {
        mod_setting(&mut config.srv.org_location, key, value, lineno, "", |_| ());
    } else if key == "org_mail" {
        mod_setting(&mut config.srv.org_mail, key, value, lineno, "", |_| ());
    } else if key == "channellen" {
        mod_spi_setting(&mut config.srv.channellen, key, value, lineno);
    } else if key == "kicklen" {
        mod_spi_setting(&mut config.srv.kicklen, key, value, lineno);
    } else if key == "nicklen" {
        mod_spi_setting(&mut config.srv.nicklen, key, value, lineno);
    } else if key == "topiclen" {
        mod_spi_setting(&mut config.srv.topiclen, key, value, lineno);
    } else if key == "userlen" {
        mod_spi_setting(&mut config.srv.userlen, key, value, lineno);
    } else {
        format_error(lineno, "unknown setting");
    }
}

fn validate(config: &mut Config) {
    if config.bindings.is_empty() {
        missing_setting_error("bind_to");
    }

    if config.srv.domain.is_empty() {
        missing_setting_error("domain");
    }
    if config.srv.default_chan_mode.is_empty() {
        config.srv.default_chan_mode.push_str("+nt");
    }
    if config.srv.org_name.is_empty() {
        missing_setting_error("org_name");
    }
    if config.srv.org_location.is_empty() {
        missing_setting_error("org_location");
    }
    if config.srv.org_mail.is_empty() {
        missing_setting_error("org_mail");
    }
    if config.srv.channellen == 0 { config.srv.channellen = 50; }
    if config.srv.kicklen == 0 { config.srv.kicklen = 300; }
    if config.srv.nicklen == 0 { config.srv.nicklen = 9; }
    if config.srv.topiclen == 0 { config.srv.topiclen = 300; }
    if config.srv.userlen == 0 { config.srv.userlen = 64; }
}

/// Reads the configuration file at the given path.
///
/// Exits the program on failure (this behavior could change).
pub fn from_file(filename: String) -> Config {
    let contents = fs::read_to_string(&filename).unwrap_or_else(|err| {
        eprintln!("Could not open {:?}: {}", filename, err);
        process::exit(1);
    });
    let mut res = Config::default();

    for (line, lineno) in contents.lines().zip(1..) {
        let mut split = line.splitn(2, ' ').map(str::trim).filter(|s| !s.is_empty());
        let key = if let Some(key) = split.next() {key} else {continue};
        if key.starts_with('#') {
            continue;
        }
        let value = split.next().unwrap_or_else(|| format_error(lineno, "setting with no value"));
        add_setting(&mut res, key, value, lineno);
    }

    validate(&mut res);

    res
}
