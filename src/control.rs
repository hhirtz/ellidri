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

use crate::{auth, config, net, State};
use futures::FutureExt;
use std::{fs, process};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime as rt;
use tokio::signal::unix;
use tokio::sync::{mpsc, Notify};
use tokio::task;

/// A command from `Control` to binding tasks.
pub enum Command {
    /// Ask the binding task to listen for raw TCP connections and not use TLS.
    UsePlain,

    /// Ask the binding task to listen for TLS connections with the given acceptor.
    UseTls(Arc<tokio_tls::TlsAcceptor>),
}

/// A binding task that is ready to be spawned on the runtime.
struct LoadedBinding<F> {
    /// The address to be bound.
    address: SocketAddr,

    /// Either `None` when the binding listens for raw TCP connections, or `Some(acceptor)` when the
    /// bindings listens for TLS connections with `acceptor`.
    acceptor: Option<Arc<tokio_tls::TlsAcceptor>>,

    /// The sending end of the channel that brings commands to the task.
    handle: mpsc::Sender<Command>,

    /// The actual task, ready to be polled.
    future: F,
}

/// A WebSocket binding.
struct WsBinding {
    /// The local address.
    pub addr: SocketAddr,

    /// A channel to stop the binding.
    pub stop: Arc<Notify>,
}

impl WsBinding {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            stop: Arc::new(Notify::new()),
        }
    }
}

/// Reads the configuration file and initialize the relevant authentication provider.
fn load_config(config_path: &str) -> config::Result<(config::Config, Box<dyn auth::Provider>)> {
    let cfg = config::Config::from_file(config_path).map_err(|err| {
        log::error!("Failed to read {:?}: {}", config_path, err);
        err
    })?;

    let sasl_backend = cfg.sasl_backend;
    let auth_provider = auth::choose_provider(sasl_backend, cfg.database.clone())
        .unwrap_or_else(|err| {
            log::warn!("Failed to initialize the {} SASL backend: {}", sasl_backend, err);
            Box::new(auth::DummyProvider)
        });

    Ok((cfg, auth_provider))
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
fn load_bindings(bindings: Vec<config::Binding>, shared: &State, stop: &mpsc::Sender<SocketAddr>,
                 runtime: &mut rt::Runtime) -> Vec<(SocketAddr, mpsc::Sender<Command>)>
{
    let mut res = Vec::with_capacity(bindings.len());
    let mut store = net::TlsIdentityStore::default();

    for config::Binding { address, tls_identity } in bindings {
        let (handle, commands) = mpsc::channel(8);
        if let Some(identity_path) = tls_identity {
            let acceptor = match store.acceptor(identity_path) {
                Ok(acceptor) => acceptor,
                Err(_) => process::exit(1),
            };
            let server = net::listen(address, shared.clone(), Some(acceptor),
                                     stop.clone(), commands);
            res.push((address, handle));
            runtime.spawn(server);
        } else {
            let server = net::listen(address, shared.clone(), None, stop.clone(), commands);
            res.push((address, handle));
            runtime.spawn(server);
        }
    }

    res
}

/// The main task controler.
///
/// `Control` chooses which tasks are run.  See the module documentation for details.
pub struct Control {
    /// The path to the configuration file.
    config_path: String,

    /// The shared IRC state.
    shared: crate::State,

    /// The sending end of the channel used to track binding tasks' failures.
    ///
    /// It is shared with the binding tasks, so that they can report back when they fail.  Used to
    /// exit the program when no binding task is up.
    stop: mpsc::Sender<SocketAddr>,

    /// The receiving end of the channel used to track binding tasks' failures.
    failures: mpsc::Receiver<SocketAddr>,

    /// A channel to receive a notification when an operator sends REHASH.
    ///
    /// It is shared with `Control.shared`, which pings on this channel when REHASH is received.
    rehash: Arc<Notify>,

    /// The WebSocket binding.
    ///
    /// TLS support must be provided by a reverse proxy.
    ws: Option<WsBinding>,

    /// The list of socket addresses (IP address + TCP port) of the running binding tasks.
    ///
    /// `Control` keeps track of this in several ways:
    ///
    /// - When an address is received on the `failures` channel, it removes the relevant entry in
    ///   this array,
    /// - When reloading, it adds and removes the new and old bindings respectively.
    ///
    /// Note:  The binding tasks listen for the command channel, when this (only) sending end is
    /// dropped, the binding task will stop.  `Control` should take care not to clone the sending
    /// end, so this behavior doesn't change.
    bindings: Vec<(SocketAddr, mpsc::Sender<Command>)>,
}

impl Control {
    /// Generates, from the given configuration file path, a new `Control` and a new tokio runtime.
    pub fn new<S>(config_path: S) -> (rt::Runtime, Self)
        where S: Into<String>,
    {
        let config_path = config_path.into();
        let (stop, failures) = mpsc::channel(8);
        let rehash = Arc::new(Notify::new());
        let (cfg, auth_provider) = load_config(&config_path).unwrap_or_else(|_| process::exit(1));
        let mut runtime = create_runtime(cfg.workers);
        let shared = State::new(cfg.state, auth_provider, rehash.clone());
        let bindings = load_bindings(cfg.bindings, &shared, &stop, &mut runtime);
        let control = Self {
            config_path,
            shared,
            stop,
            failures,
            rehash,
            ws: cfg.ws_endpoint.map(WsBinding::new),
            bindings
        };
        (runtime, control)
    }

    /// Lets `Control` do its things.
    ///
    /// This task must not be run with `runtime.block_on()`, but instead `runtime.spawn`.  It will
    /// indeed use calls that cannot be made on the main thread (e.g. `tokio::block_in_place`).
    pub async fn run(self) {
        #[cfg(unix)]
        let mut signals = unix::signal(unix::SignalKind::user_defined1()).unwrap_or_else(|err| {
            log::error!("Cannot listen for signals to reload the configuration: {}", err);
            process::exit(1);
        });

        #[cfg(not(unix))]
        let signals = crate::util::PendingStream;

        let Self {
            config_path,
            shared,
            stop,
            mut failures,
            rehash,
            mut ws,
            mut bindings
        } = self;

        #[cfg(feature = "websocket")]
        ws.as_ref().map(|ws| spawn_ws(ws, shared.clone()));

        loop {
            futures::select! {
                addr = failures.recv().fuse() => match addr {
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
                _ = rehash.notified().fuse() => {
                    do_rehash(&config_path, &shared, &stop, &mut bindings, &mut ws).await;
                },
                _ = signals.recv().fuse() => {
                    do_rehash(&config_path, &shared, &stop, &mut bindings, &mut ws).await;
                },
            }
        }
    }
}

#[cfg(feature = "websocket")]
fn spawn_ws(ws: &WsBinding, shared: State) {
    use warp::Filter;

    let shared = warp::any().map(move || shared.clone());
    let server = warp::path::end()
        .and(warp::ws())
        .and(warp::addr::remote())
        .and(shared)
        .map(|ws: warp::ws::Ws, peer_addr: Option<SocketAddr>, shared| {
            ws
                .max_message_size(4096 + 512)
                .on_upgrade(move |socket| {
                    net::handle_ws(socket, peer_addr.unwrap(), shared)
                })
        });

    let ws_stop = ws.stop.clone();
    let addr = ws.addr;
    let (_, server) = warp::serve(server)
        .bind_with_graceful_shutdown(addr, async move {
            log::info!("Binding {} online, accepting WebSocket connections", addr);
            ws_stop.notified().await;
            log::info!("Binding {} now offline", addr);
        });
    tokio::spawn(server);
}

/// Reloads the configuration at `config_path`.
///
/// In four steps:
///
/// - Read the configuration and load the authentication provider,
/// - Remove old bindings that are not used anymore,
/// - Add new bindings, or send them a command to listen for raw TCP or TLS connections,
/// - Update the shared state.
async fn do_rehash(config_path: &str, shared: &State, stop: &mpsc::Sender<SocketAddr>,
                   bindings: &mut Vec<(SocketAddr, mpsc::Sender<Command>)>,
                   ws: &mut Option<WsBinding>)
{
    log::info!("Reloading configuration from {:?}", config_path);
    let reloaded = task::block_in_place(|| {
        reload_config(config_path, shared, stop)
    });
    let (cfg, auth_provider, new_bindings) = match reloaded {
        Some(reloaded) => reloaded,
        None => return,
    };

    let mut i = 0;
    while i < bindings.len() {
        let old_address = bindings[i].0;
        if new_bindings.iter().all(|new_b| old_address != new_b.address) {
            bindings.swap_remove(i);
        } else {
            i += 1;
        }
    }

    for new_b in new_bindings {
        if let Some(i) = bindings.iter().position(|old_b| old_b.0 == new_b.address) {
            let res = bindings[i].1.send(match new_b.acceptor {
                Some(acceptor) => Command::UseTls(acceptor),
                None => Command::UsePlain,
            }).await;
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

    #[cfg(feature = "websocket")]
    match cfg.ws_endpoint {
        Some(ws_endpoint) => if ws.as_ref().map_or(true, |ws| ws.addr != ws_endpoint) {
            *ws = Some(WsBinding::new(ws_endpoint));
        }
        None => {
            if let Some(ws) = &ws {
                ws.stop.notify();
            }
            *ws = None;
        }
    }

    shared.rehash(cfg.state, auth_provider).await;

    log::info!("Configuration reloaded");
}

/// Re-read the configuration file and re-generate the bindings.
///
/// See documentation of `reload_bindings` for how bindings are re-generated.
///
/// This function will put the contents of the MOTD file into `Config.motd_file`, so that the
/// shared state can use the field as-is, since it must not use blocking operations such as reading
/// a file.
fn reload_config(config_path: &str, shared: &State, stop: &mpsc::Sender<SocketAddr>)
    -> Option<(config::Config, Box<dyn auth::Provider>, Vec<LoadedBinding<impl Future<Output=()>>>)>
{
    let (mut cfg, auth_provider) = match load_config(config_path) {
        Ok((c, a)) => (c, a),
        Err(_) => return None,
    };
    cfg.state.motd_file = match fs::read_to_string(&cfg.state.motd_file) {
        Ok(motd) => motd,
        Err(err) => {
            log::warn!("Failed to read {:?}: {}", cfg.state.motd_file, err);
            String::new()
        }
    };
    let new_bindings = reload_bindings(&cfg.bindings, shared, stop);
    Some((cfg, auth_provider, new_bindings))
}

/// Equivalent of `load_bindings` for when exiting the program is not acceptable.
///
/// Instead of spawning the binding tasks on the runtime, this function returns them in an array.
/// Also instead of exiting on failure, it continues its process.  Binding tasks that could not
/// be generated are not returned.
///
/// Otherwise both functions have the same behavior.
fn reload_bindings(bindings: &[config::Binding], shared: &State, stop: &mpsc::Sender<SocketAddr>)
                   -> Vec<LoadedBinding<impl Future<Output=()>>>
{
    let mut res = Vec::with_capacity(bindings.len());
    let mut store = net::TlsIdentityStore::default();

    for config::Binding { address, tls_identity } in bindings {
        let (handle, commands) = mpsc::channel(8);
        if let Some(identity_path) = tls_identity {
            let acceptor = match store.acceptor(identity_path) {
                Ok(acceptor) => acceptor,
                Err(_) => continue,
            };
            let future = net::listen(*address, shared.clone(), Some(acceptor.clone()),
                                     stop.clone(), commands);
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
