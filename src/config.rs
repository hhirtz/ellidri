use std::{fs, net, path, process};

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
}

pub struct Binding {
    pub address: net::SocketAddr,
    pub tls_identity: Option<path::PathBuf>,
}

#[derive(Default)]
pub struct Config {
    pub bindings: Vec<Binding>,
    pub workers: Option<usize>,

    pub srv: StateConfig,
}

fn format_error(lineno: u32, msg: &'static str) -> ! {
    eprintln!("Config file error at line {}: {}", lineno, msg);
    process::exit(1)
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
        let id = value.parse().unwrap_or_else(|_| format_error(lineno, "expected path"));
        config.bindings[last].tls_identity = Some(id);
    } else if key == "workers" {
        if config.workers.is_some() {
            format_error(lineno, "duplicate workers setting");
        }
        let workers = value.parse().unwrap_or_else(|_| format_error(lineno, "expected integer"));
        config.workers = Some(workers);
    } else if key == "domain" {
        if !config.srv.domain.is_empty() {
            format_error(lineno, "duplicate domain setting");
        }
        config.srv.domain.push_str(value);
    } else if key == "default_chan_mode" {
        if !config.srv.default_chan_mode.is_empty() {
            format_error(lineno, "duplicate default_chan_mode setting");
        }
        if !crate::modes::is_channel_mode_string(value) {
            format_error(lineno, "default_chan_mode is not a valid mode string");
        }
        config.srv.default_chan_mode.push_str(value);
    } else if key == "motd_file" {
        if config.srv.motd_file.is_some() {
            format_error(lineno, "duplicate motd_file setting");
        }
        config.srv.motd_file = Some(value.to_owned());
    } else if key == "password" {
        if config.srv.password.is_some() {
            format_error(lineno, "duplicate password setting");
        }
        config.srv.password = Some(value.to_owned());
    } else if key == "oper" {
        let mut words = value.split_whitespace();
        let oper_name = words.next().unwrap();
        let oper_pass = words.next().unwrap_or_else(|| {
            format_error(lineno, "oper must follow the format 'oper <name> <password>'");
        });
        config.srv.opers.push((oper_name.to_owned(), oper_pass.to_owned()));
    } else if key == "org_name" {
        if !config.srv.org_name.is_empty() {
            format_error(lineno, "duplicate org_name setting");
        }
        config.srv.org_name.push_str(value);
    } else if key == "org_location" {
        if !config.srv.org_location.is_empty() {
            format_error(lineno, "duplicate org_location setting");
        }
        config.srv.org_location.push_str(value);
    } else if key == "org_mail" {
        if !config.srv.org_mail.is_empty() {
            format_error(lineno, "duplicate org_mail setting");
        }
        config.srv.org_mail.push_str(value);
    } else {
        format_error(lineno, "unexpected setting");
    }
}

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

    res
}
