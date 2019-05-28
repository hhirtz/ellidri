//! ellidri, the *kawai* IRC server.
//!
//! # Usage
//!
//! You need a configuration file, and pass its name as an argument. The git
//! repository contains an example `ellidri.toml`, with comments describing the
//! different options. The `config` module also has documentation about it.
//!
//! During development: `cargo run -- ellidri.toml`
//!
//! For an optimized build:
//!
//! ```console
//! cargo install
//! ellidri ellidri.toml
//! ```

#![warn(clippy::all, rust_2018_idioms)]

use std::{env, fs, path, process};
use std::collections::HashMap;

use futures::Future;

use crate::config::BindToAddress;
use crate::state::State;

mod channel;
mod client;
mod config;
mod lines;
mod message;
mod misc;
mod modes;
mod net;
mod state;

/// Read the file at `path`, parse the identity and builds a TlsAcceptor object.
fn build_acceptor(path: &path::Path) -> tokio_tls::TlsAcceptor {
    let der = fs::read(path).unwrap_or_else(|err| {
        log::error!("I'm so sorry, senpai! I couldn't read {}...", path.display());
        log::error!("Please fix this, senpai...: {}", err);
        process::exit(1);
    });
    let identity = native_tls::Identity::from_pkcs12(&der, "").unwrap_or_else(|err| {
        log::error!("Senpai... there's something wrong with your identity file here: {}", err);
        process::exit(1);
    });
    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .build()
        .unwrap_or_else(|err| {
            log::error!("I don't know what to do with this identity senpai: {}", err);
            process::exit(1);
        });
    tokio_tls::TlsAcceptor::from(acceptor)
}

/// TlsAcceptor cache, to avoid reading the same identity file several times.
#[derive(Default)]
struct TlsIdentityStore {
    acceptors: HashMap<path::PathBuf, tokio_tls::TlsAcceptor>,
}

impl TlsIdentityStore {
    /// Retrieves the acceptor at `path`, or get it from the cache if it has already been built.
    pub fn acceptor(&mut self, path: path::PathBuf) -> tokio_tls::TlsAcceptor {
        self.acceptors.entry(path.clone())
            .or_insert_with(|| build_acceptor(&path))
            .clone()
    }
}

/// The beginning of everything
pub fn start() {
    let config_path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Excuse-me senpai... I don't know what to do... *sob*");
        eprintln!("Hint............................ ellidri CONFIG_FILE");
        eprintln!("            THANK YOU FOR YOUR PATIENCE!      (n.n')");
        process::exit(1);
    });

    // When ellidri is compiled without optimisations, enable backtrace logging
    // for thread crashes, and set the log level to debug.
    if cfg!(debug_assertions) {
        std::env::set_var("RUST_BACKTRACE", "1");
        std::env::set_var("RUST_LOG", "ellidri=debug");
    } else {
        std::env::set_var("RUST_LOG", "ellidri=info");
    }

    let c = config::from_file(config_path);

    if let Some(level) = c.log_level {
        std::env::set_var("RUST_LOG", format!("ellidri={}", level));
    }

    env_logger::builder()
        .format(|buf, r| {
            use std::io::Write;
            let now = chrono::Utc::now().naive_local()
                .format("%Y-%m-%d %H:%M:%S%.6f").to_string();
            writeln!(buf, "{} {:<5} {}", now, r.level(), r.args())
        })
        .init();

    log::warn!("Let's get started senpai!");

    let shared = State::new(c.domain, c.motd, c.default_chan_mode);
    let mut runtime = tokio::runtime::Builder::new()
        .core_threads(c.worker_threads)
        // TODO panic_handler
        .build()
        .unwrap_or_else(|err| {
            log::error!("Oh no, senpai! Your computer is killing me... argh..");
            log::error!("*dies painfully because of {}*", err);
            process::exit(1);
        });

    let mut store = TlsIdentityStore::default();
    for BindToAddress { addr, tls } in c.bind_to_address.into_iter() {
        if let Some(options) = tls {
            let acceptor = store.acceptor(options.tls_identity);
            let server = net::listen_tls(addr, shared.clone(), acceptor);
            runtime.spawn(server);
            log::warn!("I'm listening on {} (tls ^^), ok?", addr);
        } else {
            let server = net::listen(addr, shared.clone());
            runtime.spawn(server);
            log::warn!("I'm listening on {}, ok?", addr);
        }
    }

    runtime.shutdown_on_idle().wait().unwrap();
}
