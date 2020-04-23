use crate::{control, lines, State};
use ellidri_reader::IrcReader;
use ellidri_tokens::Message;
use futures::future;
use futures::FutureExt;
use std::{fs, path, str};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{io, net, sync, time};
use tokio::sync::mpsc;
use tokio_tls::TlsAcceptor;

const KEEPALIVE_SECS: u64 = 75;
const TLS_TIMEOUT_SECS: u64 = 30;

/// `TlsAcceptor` cache, to avoid reading the same identity file several times.
#[derive(Default)]
pub struct TlsIdentityStore {
    acceptors: HashMap<path::PathBuf, Arc<TlsAcceptor>>,
}

impl TlsIdentityStore {
    /// Retrieves the acceptor at `path`, or get it from the cache if it has already been built.
    pub fn acceptor<P>(&mut self, file: P) -> Result<Arc<TlsAcceptor>, Box<dyn Error + 'static>>
        where P: AsRef<path::Path> + Into<path::PathBuf>,
    {
        if let Some(acceptor) = self.acceptors.get(file.as_ref()) {
            Ok(acceptor.clone())
        } else {
            let acceptor = Arc::new(build_acceptor(file.as_ref())?);
            self.acceptors.insert(file.into(), acceptor.clone());
            Ok(acceptor)
        }
    }
}

/// Read the file at `p`, parse the identity and builds a `TlsAcceptor` object.
fn build_acceptor(p: &path::Path) -> Result<TlsAcceptor, Box<dyn Error + 'static>> {
    log::info!("Loading TLS identity from {:?}", p.display());
    let der = fs::read(p)
        .map_err(|err| {
            log::error!("Failed to read {:?}: {}", p.display(), err);
            err
        })?;
    let identity = native_tls::Identity::from_pkcs12(&der, "")
        .map_err(|err| {
            log::error!("Failed to parse {:?}: {}", p.display(), err);
            err
        })?;
    let acceptor = native_tls::TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv11))
        .build()
        .map_err(|err| {
            log::error!("Failed to initialize TLS: {}", err);
            err
        })?;
    Ok(TlsAcceptor::from(acceptor))
}

/// Returns a future that listens, accepts and handles incoming connections.
pub async fn listen(addr: SocketAddr, shared: State, mut acceptor: Option<Arc<TlsAcceptor>>,
                    mut stop: mpsc::Sender<SocketAddr>,
                    mut commands: mpsc::Receiver<control::Command>)
{
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

fn handle_tls(conn: net::TcpStream, peer_addr: SocketAddr, shared: State,
              acceptor: Arc<TlsAcceptor>)
{
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
                Ok(Some(points)) => used_points + points,
                Ok(None) => break Ok(()),
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

                used_points = used_points.saturating_sub(millis / rate * 4);
                last_round += elapsed;

                if burst < used_points {
                    let wait_millis = (used_points - burst) / 4 * rate;
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
async fn handle<S>(conn: S, peer_addr: SocketAddr, shared: State)
    where S: io::AsyncRead + io::AsyncWrite
{
    let (reader, writer) = io::split(conn);
    let mut reader = IrcReader::new(reader, 512);
    let mut writer = io::BufWriter::new(writer);
    let (msg_queue, mut outgoing_msgs) = sync::mpsc::unbounded_channel();
    let peer_id = shared.peer_joined(peer_addr, msg_queue).await;
    tokio::spawn(login_timeout(peer_id, shared.clone()));

    let incoming = async {
        let mut buf = String::new();
        rate_limit!(1024, 16, async {
            buf.clear();
            let n = reader.read_message(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, lines::CONNECTION_RESET));
            }
            log::trace!("{} >> {}", peer_addr, buf.trim());
            Ok(handle_buffer(peer_id, &buf, &shared).await)
        })
    };

    let outgoing = async {
        use io::AsyncWriteExt as _;
        use crate::client::MessageQueueItem::*;

        while let Some(msg) = outgoing_msgs.recv().await {
            match msg {
                Data { start, buf } => writer.write_all(buf[start..].as_bytes()).await?,
                Flush => writer.flush().await?,
            }
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
async fn handle_buffer(peer_id: usize, buf: &str, shared: &State) -> Option<u32> {
    if let Some(msg) = Message::parse(buf) {
        return shared.handle_message(peer_id, msg).await.ok();
    }
    Some(1)
}

async fn login_timeout(peer_id: usize, shared: State) {
    let timeout = shared.login_timeout().await;
    time::delay_for(time::Duration::from_millis(timeout)).await;
    shared.remove_if_unregistered(peer_id).await;
}

#[cfg(feature = "websocket")]
use futures_util::future::TryFutureExt;
#[cfg(feature = "websocket")]
use futures_util::stream::StreamExt;

#[cfg(feature = "websocket")]
pub async fn handle_ws(ws: warp::ws::WebSocket, peer_addr: SocketAddr, shared: State) {
    let (writer, mut reader) = ws.split();
    let (msg_queue, outgoing_msgs) = sync::mpsc::unbounded_channel();
    let peer_id = shared.peer_joined(peer_addr, msg_queue).await;
    tokio::spawn(login_timeout(peer_id, shared.clone()));

    let incoming = async {
        rate_limit!(1024, 16, async {
            match reader.next().await {
                Some(Ok(msg)) if msg.is_text() => {
                    Ok(handle_buffer(peer_id, msg.to_str().unwrap(), &shared).await)
                }
                Some(Ok(_)) => Ok(Some(1)),
                Some(Err(err)) => Err(err.to_string()),
                None => Err(lines::CONNECTION_RESET.to_string()),
            }
        })
    };

    let outgoing = outgoing_msgs
        .map(|msg| {
            // TODO avoid clone
            Ok(warp::ws::Message::text(msg.as_ref()))
        })
        .forward(writer)
        .map_err(|err| err.to_string());

    futures::pin_mut!(incoming, outgoing);
    let res = future::select(incoming, outgoing).await;
    shared.peer_quit(peer_id, res.factor_first().0.err()).await;
}
