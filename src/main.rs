//! ellidri, your *kawaii* IRC server.

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms)]
#![allow(
    clippy::filter_map,
    clippy::find_map,
    clippy::shadow_unrelated,
    clippy::use_self
)]
#![recursion_limit = "1024"]

use crate::channel::Channel;
use crate::client::Client;
use crate::control::Control;
use crate::state::State;
use std::{env, process};

mod channel;
mod client;
mod config;
mod control;
mod data;
#[macro_use]
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

    let config_path = parse_args();
    let (mut runtime, control) = Control::new(config_path.to_owned());

    runtime.spawn(control.run());
    runtime.block_on(infinite());
}

fn infinite() -> impl std::future::Future<Output = ()> {
    futures::future::pending()
}

fn parse_args() -> String {
    let mut args = env::args();

    let program = args.next().unwrap();

    let config_path = args.next().unwrap_or_else(|| {
        eprintln!("Usage: {} CONFIG_FILE", program);
        process::exit(1);
    });

    if config_path == "-h" || config_path == "--help" {
        eprintln!("ellidri {}", env!("CARGO_PKG_VERSION"));
        eprintln!("Usage: {} CONFIG_FILE", program);
        process::exit(1);
    } else if config_path == "-v" || config_path == "--version" {
        eprintln!("ellidri {}", env!("CARGO_PKG_VERSION"));
        process::exit(1);
    }

    config_path
}
