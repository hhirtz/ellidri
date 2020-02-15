//! ellidri, the *kawai* IRC server.
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

#![warn(clippy::all, rust_2018_idioms)]
#![allow(clippy::filter_map, clippy::find_map, clippy::shadow_unrelated, clippy::use_self)]

use crate::state::State;
use std::{env, process};

mod channel;
mod client;
pub mod config;
mod lines;
pub mod message;
mod misc;
mod modes;
mod net;
mod state;

/// The beginning of everything
pub fn start() {
    let config_path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: {} CONFIG_FILE", env::args().nth(0).unwrap());
        process::exit(1);
    });

    if cfg!(debug_assertions) {
        env::set_var("RUST_BACKTRACE", "1");
        env::set_var("RUST_LOG", "ellidri=trace");
    } else {
        env::set_var("RUST_LOG", "ellidri=info");
    }

    let c = config::from_file(config_path);

    env_logger::builder()
        .format(|buf, r| {
            use std::io::Write;
            writeln!(buf, "[{:<5} {}] {}", r.level(), r.target(), r.args())
        })
        .init();

    let shared = State::new(c.srv);
    let mut runtime = tokio::runtime::Runtime::new()
        .unwrap_or_else(|err| {
            log::error!("Failed to start the tokio runtime: {}", err);
            process::exit(1);
        });

    let mut store = net::TlsIdentityStore::default();
    for config::Binding { address, tls_identity } in c.bindings {
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

fn infinite() -> impl std::future::Future<Output=()> {
    futures::future::poll_fn(|_| futures::task::Poll::Pending)
}
