//! ellidri, your *kawaii* IRC server.
//!
//! # Usage
//!
//! You need a configuration file, and pass its name as an argument. The git
//! repository contains an example `ellidri.conf`, with comments describing the
//! different options. The `config` module also has documentation about it.
//!
//! During development: `cargo run -- ellidri.conf`
//!
//! For an optimized build:
//!
//! ```console
//! cargo install
//! ellidri ellidri.conf
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, rust_2018_idioms)]
#![allow(clippy::filter_map, clippy::find_map, clippy::shadow_unrelated, clippy::use_self)]

pub use crate::state::State;
use std::{env, process};

mod channel;
mod client;
pub mod config;
mod lines;
pub mod message;
mod modes;
mod net;
mod state;
mod util;

/// The beginning of everything
pub fn start() {
    let config_path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: {} CONFIG_FILE", env::args().nth(0).unwrap());
        process::exit(1);
    });

    if cfg!(debug_assertions) {
        env::set_var("RUST_BACKTRACE", "1");
    }

    let cfg = config::from_file(config_path);

    let log_settings = env_logger::Env::new()
        .filter_or("ELLIDRI_LOG", "ellidri=debug")
        .write_style("ELLIDRI_LOG_STYLE");
    env_logger::Builder::from_env(log_settings)
        .format(|buf, r| {
            use std::io::Write;
            writeln!(buf, "[{:<5} {}] {}", r.level(), r.target(), r.args())
        })
        .init();

    let mut runtime = runtime(&cfg);
    let shared = State::new(cfg.srv);

    let mut store = net::TlsIdentityStore::default();
    for config::Binding { address, tls_identity } in cfg.bindings {
        if let Some(identity_path) = tls_identity {
            let acceptor = store.acceptor(identity_path);
            let server = net::listen_tls(address, shared.clone(), acceptor);
            runtime.spawn(server);
            log::info!("Listening on {} for tls connections...", address);
        } else {
            let server = net::listen(address, shared.clone());
            runtime.spawn(server);
            log::info!("Listening on {} for plain-text connections...", address);
        }
    }

    runtime.block_on(infinite());
}

#[cfg(feature = "threads")]
fn runtime(cfg: &config::Config) -> tokio::runtime::Runtime {
    let mut builder = tokio::runtime::Builder::new();

    if let Some(workers) = cfg.workers {
        builder.core_threads(workers);
    }

    builder
        .threaded_scheduler()
        .enable_io()
        .build()
        .unwrap_or_else(|err| {
            log::error!("Failed to start the tokio runtime: {}", err);
            process::exit(1);
        })
}

#[cfg(not(feature = "threads"))]
fn runtime(_cfg: &config::Config) -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new()
        .unwrap_or_else(|err| {
            log::error!("Failed to start the tokio runtime: {}", err);
            process::exit(1);
        })
}

fn infinite() -> impl std::future::Future<Output=()> {
    futures::future::poll_fn(|_| futures::task::Poll::Pending)
}
