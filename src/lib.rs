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

#![warn(clippy::all)]

use std::{env, process};

use futures::Future;

use crate::state::State;

pub mod client;
pub mod config;
pub mod lines;
pub mod message;
pub mod net;
pub mod state;

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

    let shared = State::new(c.domain, c.motd);
    let server = net::listen(c.bind_to_address, shared);

    log::warn!("Let's get started senpai!");
    log::warn!("I'm listening on {}, ok?", c.bind_to_address);

    let mut runtime = tokio::runtime::Builder::new()
        .core_threads(c.worker_threads)
        // TODO panic_handler
        .build()
        .unwrap_or_else(|err| {
            log::error!("Oh no, senpai! Your computer is killing me... argh..");
            log::error!("*dies painfully because of {}*", err);
            process::exit(1);
        });
    runtime.spawn(server);
    runtime.shutdown_on_idle().wait().unwrap();
}
