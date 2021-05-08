use crate::{control, lines, State, tls};
use ellidri_tokens::Message;
use std::net::SocketAddr;
use std::str;
use tokio::sync::mpsc;
use tokio::{io, net, sync, time};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

#[cfg(feature = "tls")]
const TLS_TIMEOUT_SECS: u64 = 30;
const MAX_MESSAGE_LENGTH: u64 = 4096;


/// Returns a future that listens, accepts and handles incoming connections.
pub async fn listen(
    addr: SocketAddr,
    shared: State,
    mut acceptor: Option<tls::Acceptor>,
    stop: mpsc::Sender<SocketAddr>,
    mut commands: mpsc::Receiver<control::Command>,
) {
    let ln = match net::TcpListener::bind(&addr).await {
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
        tokio::select! {
            maybe_conn = ln.accept() => match maybe_conn {
                Ok((conn, peer_addr)) => match acceptor.as_ref() {
                    Some(a) => handle_tls(conn, peer_addr, shared.clone(), a.clone()),
                    None => handle_tcp(conn, peer_addr, shared.clone()),
                }
                Err(err) => log::warn!("Binding {} failed to accept a connection: {}", addr, err),
            },
            command = commands.recv() => match command {
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
    tokio::spawn(handle(conn, peer_addr, shared));
}

#[cfg_attr(not(feature = "tls"), allow(unused_variables))]
fn handle_tls(
    conn: net::TcpStream,
    peer_addr: SocketAddr,
    shared: State,
    acceptor: tls::Acceptor,
) {
    #[cfg(feature = "tls")]
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
                Err(err) => {
                    let res: io::Result<()> = Err(err);
                    break res;
                }
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
                    time::sleep(wait).await;
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
    let mut reader = io::BufReader::new(reader);

    let (msg_queue, mut outgoing_msgs) = sync::mpsc::unbounded_channel();
    let peer_id = shared.peer_joined(peer_addr, msg_queue).await;
    tokio::spawn(login_timeout(peer_id, shared.clone()));

    let incoming = async {
        let mut buf = String::new();
        rate_limit!(125, 32, async {
            buf.clear();
            let n = (&mut reader).take(MAX_MESSAGE_LENGTH).read_line(&mut buf).await?;
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

    let res: Option<io::Error>;
    tokio::select! {
        r = incoming => res = r.err(),
        r = outgoing => res = r.err(),
    }

    shared.peer_quit(peer_id, res).await;
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
    time::sleep(time::Duration::from_millis(timeout)).await;
    shared.remove_if_unregistered(peer_id).await;
}
