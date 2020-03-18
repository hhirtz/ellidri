use crate::lines;
use crate::message::Message;
use crate::state::State;
use std::{fs, path, process, str};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{io, net, sync, time};
use tokio_tls::TlsAcceptor;

// Timeouts, in milliseconds.
// TODO: make them configurable.
const READ_TIMEOUT: u64 = 5_000;
const REGISTRATION_TIMEOUT: u64 = 60_000;

/// `TlsAcceptor` cache, to avoid reading the same identity file several times.
#[derive(Default)]
pub struct TlsIdentityStore {
    acceptors: HashMap<path::PathBuf, Arc<tokio_tls::TlsAcceptor>>,
}

impl TlsIdentityStore {
    /// Retrieves the acceptor at `path`, or get it from the cache if it has already been built.
    pub fn acceptor(&mut self, file: path::PathBuf) -> Arc<tokio_tls::TlsAcceptor> {
        if let Some(acceptor) = self.acceptors.get(&file) {
            acceptor.clone()
        } else {
            let acceptor = Arc::new(build_acceptor(&file));
            self.acceptors.insert(file, acceptor.clone());
            acceptor
        }
    }
}

/// Read the file at `p`, parse the identity and builds a `TlsAcceptor` object.
fn build_acceptor(p: &path::Path) -> tokio_tls::TlsAcceptor {
    log::info!("Loading TLS identity from {:?}", p.display());
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

// TODO make listen and listen_tls poll a Notify future and return when they are notified
// https://docs.rs/tokio/0.2.13/tokio/sync/struct.Notify.html

// TODO make listen and listen_tls not call process::exit and just return the error.
// right now we can't since there's no way to exit the program when a listener fails.

/// Returns a future that listens, accepts and handles incoming plain-text connections.
pub async fn listen(addr: SocketAddr, shared: State) -> io::Result<()> {
    let mut ln = net::TcpListener::bind(&addr).await.unwrap_or_else(|err| {
        log::error!("Failed to listen to {}: {}", addr, err);
        process::exit(1);
    });

    log::info!("Listening on {} for plain-text connections...", addr);

    loop {
        match ln.accept().await {
            Ok((conn, peer_addr)) => { tokio::spawn(handle(conn, peer_addr, shared.clone())); }
            Err(err) => { log::warn!("Failed to accept connection: {}", err); }
        }
    }
}

/// Returns a future that listens, accepts and handles incoming TLS connections.
pub async fn listen_tls(addr: SocketAddr, shared: State, acceptor: Arc<TlsAcceptor>) -> io::Result<()> {
    let mut ln = net::TcpListener::bind(&addr).await.unwrap_or_else(|err| {
        log::error!("Failed to listen to {}: {}", addr, err);
        process::exit(1);
    });

    log::info!("Listening on {} for tls connections...", addr);

    loop { match ln.accept().await {
        Ok((conn, peer_addr)) => {
            let shared = shared.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls_conn = match acceptor.accept(conn)
                    .await
                    .map_err(|err| {
                        log::warn!("TLS handshake failed: {}", err);
                    })
                { Ok(tls_conn) => tls_conn, Err(_) => return, };
                handle(tls_conn, peer_addr, shared).await;
            });
        }
        Err(err) => log::warn!("Failed to accept connection: {}", err),
    }}
}

/// Returns a future that handles an IRC connection.
async fn handle<S>(conn: S, peer_addr: SocketAddr, shared: State)
    where S: io::AsyncRead + io::AsyncWrite
{
    let (reader, mut writer) = io::split(conn);
    let mut reader = io::BufReader::new(reader);
    let (msg_queue, mut outgoing_msgs) = sync::mpsc::unbounded_channel();
    shared.peer_joined(peer_addr, msg_queue).await;
    // TODO spawn task that kill the client if it's not registered after a delay

    let incoming = async {
        use io::AsyncBufReadExt as _;

        let mut buf = String::new();
        loop {
            buf.clear();
            // TODO better control of the reading.  Especially:
            // - put a limit on line length (4096 + 512  if starts with @, 512 otherwise)
            //   (also 512 should be configurable)
            // - kill clients that send 1-byte (or so) reads every time
            reader.read_line(&mut buf).await?;
            log::trace!("{} >> {}", peer_addr, buf.trim());
            handle_buffer(&peer_addr, &buf, &shared).await?;
        }
    };

    let outgoing = async {
        use io::AsyncWriteExt as _;

        while let Some(msg) = outgoing_msgs.recv().await {
            writer.write_all(msg.as_ref()).await?;
        }
        // The client is not in `shared` anymore.  Let it read for a bit, then close the connection.
        time::delay_for(time::Duration::from_millis(READ_TIMEOUT)).await;
        Err(io::ErrorKind::TimedOut.into())
    };

    let res: io::Result<((), ())> = futures::future::try_join(incoming, outgoing).await;
    shared.peer_quit(&peer_addr, res.err()).await;
}

async fn handle_buffer(peer_addr: &SocketAddr, buf: &str, shared: &State) -> io::Result<()> {
    if buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, lines::CONNECTION_RESET));
    }

    if let Some(msg) = Message::parse(buf) {
        shared.handle_message(peer_addr, msg).await
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
    }

    Ok(())
}
