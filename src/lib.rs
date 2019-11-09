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

use crate::state::State;
use std::{env, fs, path, process};
use std::collections::HashMap;

mod channel;
mod client;
pub mod config;
mod lines;
pub mod message;
mod misc;
mod modes;
mod net;
mod state;

/// Read the file at `p`, parse the identity and builds a TlsAcceptor object.
fn build_acceptor(p: &path::Path) -> tokio_tls::TlsAcceptor {
    let der = fs::read(p).unwrap_or_else(|err| {
        log::error!("Failed to read {:?}: {}", p.display(), err);
        process::exit(1);
    });
    let identity = native_tls::Identity::from_pkcs12(&der, "").unwrap_or_else(|err| {
        log::error!("Failed to parse {:?}: {}", p.display(), err);
        process::exit(1);
    });
    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv11))
        .build()
        .unwrap_or_else(|err| {
            log::error!("Failed to initialize TLS: {}", err);
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
    pub fn acceptor(&mut self, file: path::PathBuf) -> tokio_tls::TlsAcceptor {
        if let Some(acceptor) = self.acceptors.get(&file) {
            acceptor.clone()
        } else {
            let acceptor = build_acceptor(&file);
            self.acceptors.insert(file, acceptor.clone());
            acceptor
        }
    }
}

/// The beginning of everything
pub fn start() {
    let config_path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: {} CONFIG_FILE", env::args().nth(0).unwrap());
        process::exit(1);
    });

    if cfg!(debug_assertions) {
        env::set_var("RUST_BACKTRACE", "1");
        env::set_var("RUST_LOG", "ellidri=debug");
    } else {
        env::set_var("RUST_LOG", "ellidri=info");
    }

    let c = config::from_file(config_path);

    env_logger::builder()
        .format(|buf, r| {
            use std::io::Write;
            writeln!(buf, "{:<5} {}", r.level(), r.args())
        })
        .init();

    let shared = State::new(c.srv);
    let mut runtime = tokio::runtime::Builder::new()
        .core_threads(c.workers.unwrap_or(1))
        // TODO panic_handler
        .build()
        .unwrap_or_else(|err| {
            log::error!("Failed to start the tokio runtime: {}", err);
            process::exit(1);
        });

    let mut store = TlsIdentityStore::default();
    for config::Binding { address, tls_identity } in c.bindings.into_iter() {
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

    use futures::Future;
    runtime.shutdown_on_idle().wait().unwrap();
}
