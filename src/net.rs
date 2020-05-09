use crate::{control, lines, State};

use ellidri_reader::IrcReader;
use ellidri_tokens::Message;

use futures::future;
use futures::FutureExt;

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, str};

use tokio::sync::mpsc;
use tokio::{io, net, sync, time};

use tokio_rustls::rustls::internal::pemfile;
use tokio_rustls::rustls::{NoClientAuth, ServerConfig};
use tokio_rustls::TlsAcceptor;

const KEEPALIVE_SECS: u64 = 75;
const TLS_TIMEOUT_SECS: u64 = 30;

/// `TlsAcceptor` cache, to avoid reading the same files several times.
#[derive(Default)]
pub struct TlsIdentityStore {
    acceptors: HashMap<PathBuf, Arc<TlsAcceptor>>,
}

impl TlsIdentityStore {
    /// Retrieves the acceptor at `path`, or get it from the cache if it has already been built.
    pub fn acceptor<P1, P2>(
        &mut self,
        cert: P1,
        key: P2,
    ) -> Result<Arc<TlsAcceptor>, Box<dyn Error + 'static>>
    where
        P1: AsRef<Path> + Into<PathBuf>,
        P2: AsRef<Path> + Into<PathBuf>,
    {
        if let Some(acceptor) = self.acceptors.get(cert.as_ref()) {
            Ok(acceptor.clone())
        } else {
            let acceptor = Arc::new(build_acceptor(cert.as_ref(), key.as_ref())?);
            self.acceptors.insert(cert.into(), acceptor.clone());
            Ok(acceptor)
        }
    }
}

/// Read the file at `p`, parse the identity and builds a `TlsAcceptor` object.
fn build_acceptor(
    certfile: &Path,
    keyfile: &Path,
) -> Result<TlsAcceptor, Box<dyn Error + 'static>> {
    let mut config = ServerConfig::new(NoClientAuth::new());

    log::info!("Loading TLS certificate from {:?}", certfile.display());
    let cert = fs::read(certfile).map_err(|err| {
        log::error!("Failed to read {:?}: {}", certfile.display(), err);
        err
    })?;
    let cert = pemfile::certs(&mut cert.as_ref()).map_err(|_| {
        log::error!("Failed to parse {:?}", certfile.display());
        ""
    })?;

    log::info!("Loading TLS private key from {:?}", keyfile.display());
    let key = fs::read(keyfile).map_err(|err| {
        log::error!("Failed to read {:?}: {}", keyfile.display(), err);
        err
    })?;
    let key = {
        let mut keys = pemfile::pkcs8_private_keys(&mut key.as_ref()).map_err(|_| {
            log::error!("Failed to parse {:?}", keyfile.display());
            ""
        })?;
        if keys.is_empty() {
            log::error!("No key found in {:?}", keyfile.display());
            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "")));
        }
        keys.remove(0)
    };

    config.set_single_cert(cert, key).map_err(|err| {
        log::error!(
            "Failed to associate {:?} with {:?}: {}",
            certfile.display(),
            keyfile.display(),
            err
        );
        err
    })?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Returns a future that listens, accepts and handles incoming connections.
pub async fn listen(
    addr: SocketAddr,
    shared: State,
    mut acceptor: Option<Arc<TlsAcceptor>>,
    mut stop: mpsc::Sender<SocketAddr>,
    mut commands: mpsc::Receiver<control::Command>,
) {
    let mut ln = match net::TcpListener::bind(&addr).await {
        Ok(ln) => ln,
        Err(err) => {
            log::error!("Binding {} failed to come online: {}", addr, err);
            let _ = stop.send(addr).await;
            return;
        }
    };

    if acceptor.is_some() {
        log::info!("Binding {} online, accepting TLS connections", addr);
    } else {
        log::info!("Binding {} online, accepting plain-text connections", addr);
    }

    loop {
        futures::select! {
            maybe_conn = ln.accept().fuse() => match maybe_conn {
                Ok((conn, peer_addr)) => match acceptor.as_ref() {
                    Some(a) => handle_tls(conn, peer_addr, shared.clone(), a.clone()),
                    None => handle_tcp(conn, peer_addr, shared.clone()),
                }
                Err(err) => log::warn!("Binding {} failed to accept a connection: {}", addr, err),
            },
            command = commands.recv().fuse() => match command {
                Some(control::Command::UsePlain) => {
                    if acceptor.is_some() {
                        log::info!("Binding {} switched to plain-text connections", addr);
                    }
                    acceptor = None;
                }
                Some(control::Command::UseTls(a)) => {
                    if acceptor.is_some() {
                        log::info!("Binding {} reloaded its TLS configuration", addr);
                    } else {
                        log::info!("Binding {} switched to TLS connections", addr);
                    }
                    acceptor = Some(a);
                }
                None => {
                    log::info!("Binding {} now offline", addr);
                    return;
                },
            },
        }
    }
}

fn handle_tcp(conn: net::TcpStream, peer_addr: SocketAddr, shared: State) {
    if let Err(err) = conn.set_keepalive(Some(time::Duration::from_secs(KEEPALIVE_SECS))) {
        log::warn!("Failed to set TCP keepalive: {}", err);
        return;
    }
    tokio::spawn(handle(conn, peer_addr, shared));
}

fn handle_tls(
    conn: net::TcpStream,
    peer_addr: SocketAddr,
    shared: State,
    acceptor: Arc<TlsAcceptor>,
) {
    if let Err(err) = conn.set_keepalive(Some(time::Duration::from_secs(KEEPALIVE_SECS))) {
        log::warn!("Failed to set TCP keepalive for {}: {}", peer_addr, err);
        return;
    }
    tokio::spawn(async move {
        let tls_handshake_timeout = time::Duration::from_secs(TLS_TIMEOUT_SECS);
        let tls_handshake = time::timeout(tls_handshake_timeout, acceptor.accept(conn));
        match tls_handshake.await {
            Ok(Ok(tls_conn)) => handle(tls_conn, peer_addr, shared).await,
            Ok(Err(err)) => log::warn!("TLS handshake with {} failed: {}", peer_addr, err),
            Err(_) => log::warn!("TLS handshake with {} timed out", peer_addr),
        }
    });
}

macro_rules! rate_limit {
    ( $rate:expr, $burst:expr, $do:expr ) => {{
        let rate: u32 = $rate;
        let burst: u32 = $burst;
        let mut used_points: u32 = 0;
        let mut last_round = time::Instant::now();

        loop {
            used_points = match $do.await {
                Ok(points) => used_points + points,
                Err(err) => break Err(err),
            };
            if burst < used_points {
                let elapsed = last_round.elapsed();
                let millis = elapsed.as_millis();
                let millis = if (std::u32::MAX as u128) < millis {
                    std::u32::MAX
                } else {
                    millis as u32
                };

                used_points = used_points.saturating_sub(millis / rate);
                last_round += elapsed;

                if burst < used_points {
                    let wait_millis = (used_points - burst) * rate;
                    let wait = time::Duration::from_millis(wait_millis as u64);
                    time::delay_for(wait).await;
                    used_points = burst;
                    last_round += wait;
                }
            }
        }
    }};
}

/// Returns a future that handles an IRC connection.
async fn handle(conn: impl io::AsyncRead + io::AsyncWrite, peer_addr: SocketAddr, shared: State) {
    let (reader, mut writer) = io::split(conn);
    let mut reader = IrcReader::new(reader, 512);

    let (msg_queue, mut outgoing_msgs) = sync::mpsc::unbounded_channel();
    let peer_id = shared.peer_joined(peer_addr, msg_queue).await;
    tokio::spawn(login_timeout(peer_id, shared.clone()));

    let incoming = async {
        let mut buf = String::new();
        rate_limit!(125, 32, async {
            buf.clear();
            let n = reader.read_message(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    lines::CONNECTION_RESET,
                ));
            }
            log::trace!("{} >> {}", peer_addr, buf.trim());
            Ok(handle_buffer(peer_id, &buf, &shared).await)
        })
    };

    let outgoing = async {
        use io::AsyncWriteExt as _;

        while let Some(msg) = outgoing_msgs.recv().await {
            writer.write_all(msg.as_ref().as_bytes()).await?;
        }
        Ok(())
    };

    futures::pin_mut!(incoming, outgoing);

    let res = future::select(incoming, outgoing).await;
    shared.peer_quit(peer_id, res.factor_first().0.err()).await;
}

/// Handle a line from the client.
///
/// Returns `None` if the connection must be closed, `Some(points)` otherwise.  Points are used for
/// rate limits.
async fn handle_buffer(peer_id: usize, buf: &str, shared: &State) -> u32 {
    if let Some(msg) = Message::parse(buf) {
        return shared.handle_message(peer_id, msg).await;
    }
    1
}

async fn login_timeout(peer_id: usize, shared: State) {
    let timeout = shared.login_timeout().await;
    time::delay_for(time::Duration::from_millis(timeout)).await;
    shared.remove_if_unregistered(peer_id).await;
}
