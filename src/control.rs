//! Runtime control utils.
//!
//! ellidri is built on tokio and the future ecosystem.  Therefore the main thing it does is manage
//! tasks.  Tasks are useful because they can be created, polled, and stopped.  This module, and
//! `Control` more specificaly, is responsible for loading and reloading the configuration file,
//! starting and stopping the necessary tasks.
//!
//! # Top-level tasks
//!
//! At the moment, the only kind of "top-level" task that ellidri runs are bindings; tasks that
//! bind then listen on a port.  They are defined in `net::listen`.  Bindings run with two data
//! "channels":
//!
//! - A "stop button":  the binding task will send its listening address when it fails unexpectedly
//!   (when it is not closed by `Control`),
//! - A command channel:  bindings accept commands that change their configuration.  All commands
//!   are described in the `Command` enum.
//!
//! # The configuration file
//!
//! ellidri reads a configuration file at startup.  This configuration file is meant to specify its
//! running state.  It can be reloaded at runtime, to change the whole state of the server.
//!
//! The first time the configuration file is read, ellidri uses it to create the tokio runtime.
//! This is because the number of workers is yet unknown, and cannot be changed afterwards.
//!
//! Configuration can then be reloaded upon receiving a SIGUSR1 signal (on UNIX systems only,
//! windows is not yet supported), or a REHASH command.  When it happens, `Control` reread the
//! configuration file and performs a diff algorithm to know which task needs to be stopped.  This
//! is really simple:
//!
//! - If an old binding is not present in the new configuration, `Control` drops the binding,
//! - If a new binding was not present in the old configuration, `Control` spawns the binding on
//!   the runtime,
//! - If a binding is present in both configurations, `Control` will keep the binding and send a
//!   command to it, either to make it listen for raw TCP connections, or to listen for TLS
//!   connections with a given `TlsAcceptor` (see `tokio-tls` doc for that).
//!
//! Bindings are identified by their socket address (IP address + TCP port).  TLS identities are
//! not kept track of, thus ellidri might reload the same TLS identity for a binding (it is fine to
//! let it do we are not reading thousands for TLS identities here).

use crate::{Config, net, State};
use crate::config::{Binding, Tls};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{fs, process};
use tokio::runtime as rt;
use tokio::sync::{mpsc, Notify};
use tokio::task;

/// A command from `Control` to binding tasks.
pub enum Command {
    /// Ask the binding task to listen for raw TCP connections and not use TLS.
    UsePlain,

    /// Ask the binding task to listen for TLS connections with the given acceptor.
    UseTls(Arc<tokio_rustls::TlsAcceptor>),
}

/// A binding task that is ready to be spawned on the runtime.
struct LoadedBinding<F> {
    /// The address to be bound.
    address: SocketAddr,

    /// Either `None` when the binding listens for raw TCP connections, or `Some(acceptor)` when the
    /// bindings listens for TLS connections with `acceptor`.
    acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,

    /// The sending end of the channel that brings commands to the task.
    handle: mpsc::Sender<Command>,

    /// The actual task, ready to be polled.
    future: F,
}

/// Creates a tokio runtime with the given number of worker threads.
fn create_runtime(workers: usize) -> rt::Runtime {
    let mut builder = rt::Builder::new();

    if workers != 0 {
        builder.core_threads(workers);
    }

    builder
        .threaded_scheduler()
        .enable_io()
        .enable_time()
        .build()
        .unwrap_or_else(|err| {
            log::error!("Failed to start the tokio runtime: {}", err);
            process::exit(1);
        })
}

/// Creates the bindings tasks and spawns them on the given runtime.
///
/// This function is what `Control` calls on startup to generate the bindings.  Because it exits
/// the program on failure, it is not to be called for reloading.
///
/// It spawns all the generated bindings on the runtime, and returns their listening address and
/// command channel.
fn load_bindings(
    bindings: Vec<Binding>,
    shared: &State,
    stop: &mpsc::Sender<SocketAddr>,
) -> Vec<(SocketAddr, mpsc::Sender<Command>)> {
    let mut res = Vec::with_capacity(bindings.len());
    let mut store = net::TlsIdentityStore::default();

    for Binding { address, tls } in bindings {
        let (handle, commands) = mpsc::channel(8);
        if let Some(Tls { certificate, key, ..  }) = tls {
            let acceptor = match store.acceptor(certificate, key) {
                Ok(acceptor) => acceptor,
                Err(_) => process::exit(1),
            };
            let server = net::listen(
                address,
                shared.clone(),
                Some(acceptor),
                stop.clone(),
                commands,
            );
            res.push((address, handle));
            tokio::spawn(server);
        } else {
            let server = net::listen(address, shared.clone(), None, stop.clone(), commands);
            res.push((address, handle));
            tokio::spawn(server);
        }
    }

    res
}

/// Reloads the configuration at `config_path`.
///
/// In four steps:
///
/// - Read the configuration and load the authentication provider,
/// - Remove old bindings that are not used anymore,
/// - Add new bindings, or send them a command to listen for raw TCP or TLS connections,
/// - Update the shared state.
async fn do_rehash(
    config_path: String,
    shared: &State,
    stop: mpsc::Sender<SocketAddr>,
    bindings: &mut Vec<(SocketAddr, mpsc::Sender<Command>)>,
) {
    log::info!("Reloading configuration from {:?}", config_path);
    let shared_clone = shared.clone();
    let reloaded = task::spawn_blocking(|| reload_config(config_path, shared_clone, stop)).await;
    let (cfg, new_bindings) = match reloaded {
        Ok(Some(reloaded)) => reloaded,
        _ => return,
    };

    let mut i = 0;
    while i < bindings.len() {
        let old_address = bindings[i].0;
        if new_bindings
            .iter()
            .all(|new_b| old_address != new_b.address)
        {
            bindings.swap_remove(i);
        } else {
            i += 1;
        }
    }

    for new_b in new_bindings {
        if let Some(i) = bindings.iter().position(|old_b| old_b.0 == new_b.address) {
            let res = bindings[i]
                .1
                .send(match new_b.acceptor {
                    Some(acceptor) => Command::UseTls(acceptor),
                    None => Command::UsePlain,
                })
                .await;
            if res.is_err() {
                // Failure to send the command means either the binding task have dropped the
                // command channel, or the binding task doesn't exist anymore.  Both possibilities
                // shouldn't happen (see doc for `Control.bindings`); but in the opposite case
                // let's remove the binding from the array that keeps track of them, and spawn the
                // new one on the runtime.
                bindings.swap_remove(i);
                tokio::spawn(new_b.future);
                bindings.push((new_b.address, new_b.handle));
            }
        } else {
            tokio::spawn(new_b.future);
            bindings.push((new_b.address, new_b.handle));
        }
    }

    shared.rehash(cfg.state).await;

    log::info!("Configuration reloaded");
}

/// Re-read the configuration file and re-generate the bindings.
///
/// See documentation of `reload_bindings` for how bindings are re-generated.
///
/// This function will put the contents of the MOTD file into `Config.motd_file`, so that the
/// shared state can use the field as-is, since it must not use blocking operations such as reading
/// a file.
fn reload_config(
    config_path: String,
    shared: State,
    stop: mpsc::Sender<SocketAddr>,
) -> Option<(Config, Vec<LoadedBinding<impl Future<Output = ()>>>)> {
    let mut cfg = match Config::from_file(&config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            log::error!("Failed to read {:?}: {}", config_path, err);
            return None;
        }
    };
    cfg.state.motd_file = match fs::read_to_string(&cfg.state.motd_file) {
        Ok(motd) => motd,
        Err(err) => {
            log::warn!("Failed to read {:?}: {}", cfg.state.motd_file, err);
            String::new()
        }
    };
    let new_bindings = reload_bindings(&cfg.bindings, &shared, &stop);
    Some((cfg, new_bindings))
}

/// Equivalent of `load_bindings` for when exiting the program is not acceptable.
///
/// Instead of spawning the binding tasks on the runtime, this function returns them in an array.
/// Also instead of exiting on failure, it continues its process.  Binding tasks that could not
/// be generated are not returned.
///
/// Otherwise both functions have the same behavior.
fn reload_bindings(
    bindings: &[Binding],
    shared: &State,
    stop: &mpsc::Sender<SocketAddr>,
) -> Vec<LoadedBinding<impl Future<Output = ()>>> {
    let mut res = Vec::with_capacity(bindings.len());
    let mut store = net::TlsIdentityStore::default();

    for Binding { address, tls } in bindings {
        let (handle, commands) = mpsc::channel(8);
        if let Some(Tls { certificate, key, ..  }) = tls {
            let acceptor = match store.acceptor(certificate, key) {
                Ok(acceptor) => acceptor,
                Err(_) => continue,
            };
            let future = net::listen(
                *address,
                shared.clone(),
                Some(acceptor.clone()),
                stop.clone(),
                commands,
            );
            res.push(LoadedBinding {
                address: *address,
                acceptor: Some(acceptor),
                handle,
                future,
            });
        } else {
            let future = net::listen(*address, shared.clone(), None, stop.clone(), commands);
            res.push(LoadedBinding {
                address: *address,
                acceptor: None,
                handle,
                future,
            });
        }
    }

    res
}

pub fn load_config_and_run(config_path: String) {
    let cfg = Config::from_file(&config_path).unwrap_or_else(|err| {
        log::error!("Failed to read {:?}: {}", config_path, err);
        process::exit(1);
    });

    let mut runtime = create_runtime(cfg.workers);

    runtime.block_on(run(config_path, cfg));
}

pub async fn run(config_path: String, cfg: Config) {
    let signal_fail = |err| {
        log::error!("Cannot listen for signals to reload the configuration: {}", err);
        process::exit(1);
    };

    #[cfg(unix)]
    let mut signals = {
        use tokio::signal::unix;

        unix::signal(unix::SignalKind::user_defined1()).unwrap_or_else(signal_fail)
    };

    #[cfg(windows)]
    let mut signals = {
        use tokio::signal::windows;

        windows::ctrl_break().unwrap_or_else(signal_fail)
    };

    let (stop, mut failures) = mpsc::channel(8);
    let rehash = Arc::new(Notify::new());

    let shared = State::new(cfg.state, rehash.clone()).await;
    let mut bindings = load_bindings(cfg.bindings, &shared, &stop);

    loop {
        tokio::select! {
            addr = failures.recv() => match addr {
                Some(addr) => for i in 0..bindings.len() {
                    if bindings[i].0 == addr {
                        bindings.swap_remove(i);
                        break;
                    }
                }
                None => {
                    // `failures.recv()` returns `None` when all senders have been dropped, so
                    // when all bindings tasks have stopped.
                    log::error!("No binding left, exiting.");
                    return;
                }
            },
            _ = rehash.notified() => {
                do_rehash(config_path.clone(), &shared, stop.clone(), &mut bindings).await;
            },
            _ = signals.recv() => {
                do_rehash(config_path.clone(), &shared, stop.clone(), &mut bindings).await;
            },
        }
    }
}
