use crate::message::Message;
use crate::state::State;
use futures::sync::mpsc;
use std::{io, iter, process};
use std::net::SocketAddr;
use tokio::io as aio;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio_tls::TlsAcceptor;

/// Returns a future that listens, accepts and handles incoming plain-text connections.
pub fn listen(addr: SocketAddr, shared: State) -> impl Future<Item=(), Error=()> {
    TcpListener::bind(&addr)
        .unwrap_or_else(|err| {
            log::error!("Failed to bind to {}: {}", addr, err);
            process::exit(1);
        })
        .incoming()
        .map_err(|err| log::debug!("Failed to accept connection: {}", err))
        .for_each(move |conn| {
            let peer_addr = conn.peer_addr().map_err(|_| ())?;
            tokio::spawn(handle(conn, peer_addr, shared.clone()));
            Ok(())
        })
}

/// Returns a future that listens, accepts and handles incoming TLS connections.
pub fn listen_tls(addr: SocketAddr, shared: State, acceptor: TlsAcceptor)
                  -> impl Future<Item=(), Error=()>
{
    TcpListener::bind(&addr)
        .unwrap_or_else(|err| {
            log::error!("Failed to bind to {}: {}", addr, err);
            process::exit(1);
        })
        .incoming()
        .map_err(|err| log::debug!("Failed to accept connection: {}", err))
        .for_each(move |conn| {
            let peer_addr = conn.peer_addr().map_err(|_| ())?;
            let shared = shared.clone();
            let tls_accept = acceptor.accept(conn)
                .map_err(|err| log::debug!("TLS handshake failed: {}", err))
                .and_then(move |tls_conn| {
                    tokio::spawn(handle(tls_conn, peer_addr, shared));
                    Ok(())
                });
            tokio::spawn(tls_accept);
            Ok(())
        })
}

/// Returns a future that handle an IRC connection.
fn handle<S>(conn: S, peer_addr: SocketAddr, shared: State) -> impl Future<Item=(), Error=()>
    where S: AsyncRead + AsyncWrite
{
    let (reader, writer) = conn.split();
    let reader = io::BufReader::new(reader);
    let (msg_queue, outgoing_msgs) = mpsc::unbounded();
    shared.peer_joined(peer_addr, msg_queue);

    let shared_clone = shared.clone();
    let incoming = stream::iter_ok(iter::repeat(()))
        .fold(reader, move |reader, ()| {
            let shared = shared_clone.clone();
            aio::read_until(reader, b'\n', Vec::new())
                .and_then(move |(reader, buf)| {
                    handle_buffer(&peer_addr, buf, shared)
                        .map(|_| reader)
                })
                .map_err(|_| ())
        })
        .map(|_| ());

    let outgoing = outgoing_msgs
        .fold(writer, move |writer, msg| {
            aio::write_all(writer, msg)
                .map(|(writer, _)| writer)
                .map_err(|_| ())
        })
        .map(|_| ());

    incoming.join(outgoing).then(move |_res| {
        // TODO use res when its a io::Error
        shared.peer_quit(&peer_addr, Some(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")));
        Ok(())
    })
}

fn handle_buffer(peer_addr: &SocketAddr, buf: Vec<u8>, shared: State) -> io::Result<()> {
    if buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
    }

    let buf = String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "doesn't speak utf-8"))?;

    if let Ok(Some(msg)) = Message::parse(&buf) {
        shared.handle_message(peer_addr, msg);
    }
    Ok(())
}
