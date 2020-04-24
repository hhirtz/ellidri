//! ellidri, your *kawaii* IRC server.

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms)]
#![allow(clippy::filter_map, clippy::find_map, clippy::shadow_unrelated, clippy::use_self)]

#![recursion_limit = "1024"]

pub use crate::config::Config;
use crate::control::Control;
pub use crate::state::State;
pub use ellidri_tokens as tokens;
use std::env;

pub mod auth;
mod channel;
mod client;
pub mod config;
mod control;
mod lines;
mod net;
mod state;
mod util;

pub fn main() {
    if cfg!(debug_assertions) {
        env::set_var("RUST_BACKTRACE", "1");
    }

    let log_settings = env_logger::Env::new()
        .filter_or("ELLIDRI_LOG", "ellidri=debug")
        .write_style("ELLIDRI_LOG_STYLE");
    env_logger::Builder::from_env(log_settings)
        .format(|buf, r| {
            use std::io::Write;
            writeln!(buf, "[{:<5} {}] {}", r.level(), r.target(), r.args())
        })
        .init();

    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(clap::Arg::with_name("CONFIG_FILE")
            .long("--config")
            .value_name("CONFIG_FILE")
            .help("ellidri's configuration file"))
        .get_matches();

    let config_path = matches.value_of("CONFIG_FILE").unwrap();
    let (mut runtime, control) = Control::new(config_path);

    runtime.spawn(control.run());
    runtime.block_on(infinite());
}

fn infinite() -> impl std::future::Future<Output=()> {
    futures::future::pending()
}
