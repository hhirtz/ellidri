use std::iter;
use std::io::BufReader;
use std::net::SocketAddr;

use futures::sync::mpsc;
use native_tls;
use tokio::io;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio_tls;

use crate::lines;
use crate::message::{Command, Message, rpl};
use crate::state::State;

/// Returns a future that listens, accepts and handles incoming clear-text IRC connections.
pub fn listen(addr: SocketAddr, shared: State) -> impl Future<Item=(), Error=()> {
    TcpListener::bind(&addr).expect("Failed to bind to address")
        .incoming()
        .map_err(|err| {
            log::info!("I'm seeing thing senpai, someone just {}. Or is it that I'm getting too old?? No way!", err);
        })
        .for_each(move |conn| {
            let peer_addr = conn.peer_addr().map_err(|_| ())?;
            tokio::spawn(handle(conn, peer_addr, shared.clone()));
            Ok(())
        })
}

pub fn listen_tls(addr: SocketAddr, shared: State, der: &[u8]) -> impl Future<Item=(), Error=()> {
    let identity = native_tls::Identity::from_pkcs12(der, "").unwrap();
    let tls_acceptor = tokio_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(identity).build().unwrap());
    TcpListener::bind(&addr).expect("Failed to bind to address")
        .incoming()
        .map_err(|err| {
            log::info!("I'm seeing thing senpai, someone just {}. Or is it that I'm getting too old?? No way!", err);
        })
        .for_each(move |conn| {
            let peer_addr = conn.peer_addr().map_err(|_| ())?;
            let shared = shared.clone();
            let tls_accept = tls_acceptor.accept(conn)
                .map_err(move |err| {
                    log::info!("Senpai! Some weird {} didn't know how to speak TLS! Like, who would have {} anyway", peer_addr, err);
                })
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
    let reader = BufReader::new(reader);
    let (msg_queue, outgoing_msgs) = mpsc::unbounded();
    shared.insert(peer_addr, msg_queue);

    let shared_clone = shared.clone();
    let incoming = stream::iter_ok(iter::repeat(()))
        .fold(reader, move |reader, ()| {
            let shared = shared_clone.clone();
            let shared_clone = shared.clone();  // bite
            io::read_until(reader, b'\n', Vec::new())
                .and_then(|(reader, buf)| {
                    if buf.is_empty() {
                        Err(io::ErrorKind::BrokenPipe.into())
                    } else {
                        Ok((reader, String::from_utf8(buf)))
                    }
                })
                .and_then(move |(reader, maybe_str)| match maybe_str {
                    Ok(s) => Ok((reader, Message::parse(s))),
                    Err(e) => {
                        Err(io::Error::new(io::ErrorKind::InvalidData, e))
                    }
                })
                .and_then(move |(reader, maybe_msg)| match maybe_msg {
                    Ok(Some(msg)) => {
                        handle_message(msg, peer_addr, shared_clone)
                            .map(move |_| reader)
                    },
                    Ok(None) => Ok(reader),
                    Err(_) => {
                        let err = io::Error::new(io::ErrorKind::InvalidData,
                                                 "it was just a typo...");
                        Err(err)
                    },
                })
                .map_err(move |err| match err.kind() {
                    io::ErrorKind::BrokenPipe => broken_pipe(err, peer_addr),
                    _ => invalid_data(err, peer_addr),
                })
        })
        .map(|_| ());

    let outgoing = outgoing_msgs
        .fold(writer, move |writer, msg| {
            //log::trace!("us -> {}: {}", peer_addr, msg);
            io::write_all(writer, msg)
                .map(|(writer, _)| writer)
                .map_err(move |err| broken_pipe(err, peer_addr))
        })
        .map(|_| ());

    incoming.join(outgoing).then(move |_| {
        shared.remove(peer_addr);
        Ok(())
    })
}

/// Handles an IRC message.
fn handle_message(msg: Message, peer_addr: SocketAddr, shared: State)
                  -> Result<(), io::Error>
{
    log::trace!("{} -> us: {}", peer_addr, msg);

    let command = match msg.command() {
        Ok(cmd) => cmd,
        Err(unknown) => {
            log::debug!("{}: Unknown command {:?}", peer_addr, unknown);
            shared.send_reply(peer_addr, rpl::ERR_UNKNOWNCOMMAND,
                              &[unknown, lines::UNKNOWN_COMMAND]);
            return Ok(());
        },
    };

    // Check if the client has sent a command that can be sent right now (e.g. a client cannot send
    // a `CAP LS` after it has registered).
    if !shared.can_issue_command(peer_addr, command) {
        log::debug!("{}: Unexpected command {:?}", peer_addr, command);
        if command == Command::User {
            shared.send_reply(peer_addr, rpl::ERR_ALREADYREGISTRED, &[lines::RATELIMIT]);
        }
        return Ok(());
    }

    if !msg.has_enough_params() {
        log::debug!("{}: Incomplete message {:?}", peer_addr, msg);
        let num_params = msg.params().count();
        if command == Command::Nick {
            shared.send_reply(peer_addr, rpl::ERR_NONICKNAMEGIVEN, &[lines::NO_NICKNAME_GIVEN]);
        } else if command == Command::PrivMsg && num_params == 0 {
            shared.send_reply(peer_addr, rpl::ERR_NORECIPIENT, &[lines::NO_RECIPIENT]);
        } else if command == Command::PrivMsg && num_params == 1 {
            shared.send_reply(peer_addr, rpl::ERR_NOTEXTTOSEND, &[lines::NO_TEXT_TO_SEND]);
        } else {
            shared.send_reply(peer_addr, rpl::ERR_NEEDMOREPARAMS,
                              &[command.as_str(), lines::NEED_MORE_PARAMS]);
        }
        return Ok(());
    }

    let mut ps = msg.params();
    match command {
        Command::Join => shared.cmd_join(peer_addr, ps.next().unwrap(), ps.next()),
        Command::Mode => shared.cmd_mode(peer_addr, ps.next().unwrap(), ps.next(), ps),
        Command::Motd => shared.cmd_motd(peer_addr),
        Command::Nick => shared.cmd_nick(peer_addr, ps.next().unwrap()),
        Command::Part => shared.cmd_part(peer_addr, ps.next().unwrap(), ps.next()),
        Command::Ping => shared.send_command(peer_addr, Command::Pong, &[ps.next().unwrap()]),
        Command::Pong => {},
        Command::PrivMsg => shared.cmd_privmsg(peer_addr, ps.next().unwrap(), ps.next().unwrap()),
        Command::Quit => {
            shared.cmd_quit(peer_addr, ps.next());
            return Err(io::Error::new(io::ErrorKind::Other, "but I just wanted to quit..."));
        },
        Command::Topic => shared.cmd_topic(peer_addr, ps.next().unwrap(), ps.next()),
        Command::User => {
            let user = ps.next().unwrap();
            // https://tools.ietf.org/html/rfc2812.html#section-3.1.3
            let mode: u8 = ps.next().unwrap().parse().unwrap_or_default();
            let _ = ps.next().unwrap();
            let real = ps.next().unwrap();
            shared.cmd_user(peer_addr, user, real, mode & 8 != 0, mode & 4 != 0);
        },
        // Message::parse doesn't return a message with a Command::Reply.
        Command::Reply(_) => unreachable!(),
    }
    Ok(())
}

// Logging error messages.

fn broken_pipe(err: io::Error, peer_addr: SocketAddr) {
    log::info!("{} left!! I'm so sad... *sob* They said {}, meanie...", peer_addr, err);
}

fn invalid_data(err: io::Error, peer_addr: SocketAddr) {
    log::info!("Some people came, I didn't understand what they were saying...
But they're gone now, we're alone together senpai!! :3
            *grabs knife*          (*0w0)
(You hear someone whisper) {}
Connection with {} has been terminated! <3", err, peer_addr);
}
