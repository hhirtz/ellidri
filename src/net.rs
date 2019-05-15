use std::iter;
use std::io::BufReader;
use std::net::SocketAddr;

use futures::sync::mpsc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use crate::message::{Command, Message, rpl};
use crate::state::State;

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

fn handle(conn: TcpStream, peer_addr: SocketAddr, shared: State)
          -> impl Future<Item=(), Error=()>
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

fn handle_message(msg: Message, peer_addr: SocketAddr, shared: State)
                  -> Result<(), io::Error>
{
    log::trace!("us -> {}: {}", peer_addr, msg);

    let command = match msg.command() {
        Ok(cmd) => cmd,
        Err(unknown) => {
            log::debug!("{}: Unknown command {}", peer_addr, unknown);
            shared.send_reply(peer_addr, rpl::ERR_UNKNOWNCOMMAND,
                              &[unknown, "rfc2812 motherfucker, do you speak it?"]);
            return Ok(());
        },
    };

    if !shared.can_issue_command(peer_addr, command) {
        log::debug!("{}: Unexpected command {}", peer_addr, command);
        if command == Command::User {
            shared.send_reply(peer_addr, rpl::ERR_ALREADYREGISTRED,
                              &["Fucking creep, stop spamming."]);
        }
        return Ok(());
    }

    if !msg.has_enough_params() {
        log::debug!("{}: Incomplete message {}", peer_addr, msg);
        if command == Command::Nick {
            shared.send_reply(peer_addr, rpl::ERR_NONICKNAMEGIVEN,
                              &["So what do I call you? \"piece of shit\" seems appropriate, no?"]);
        } else {
            shared.send_reply(peer_addr, rpl::ERR_NEEDMOREPARAMS, &[command.as_str(),
                              "What did you expect, motherfucker? Don't bother me if you have nothing to say."]);
        }
        return Ok(());
    }

    match command {
        Command::Join => shared.cmd_join(peer_addr, msg.param(0), msg.param_opt(1)),
        Command::Mode => shared.cmd_mode(peer_addr, msg.param(0), msg.param_opt(1)),
        Command::Motd => shared.cmd_motd(peer_addr),
        Command::Nick => shared.cmd_nick(peer_addr, msg.param(0)),
        Command::Part => shared.cmd_part(peer_addr, msg.param(0), msg.param_opt(1)),
        Command::Ping => shared.send_command(peer_addr, Command::Pong, &[msg.param(0)]),
        Command::Pong => {},
        Command::PrivMsg => shared.cmd_privmsg(peer_addr, msg.param(0), msg.param(1)),
        Command::Quit => {
            shared.cmd_quit(peer_addr, msg.param_opt(0));
            return Err(io::Error::new(io::ErrorKind::Other, "but I just wanted to quit..."));
        },
        Command::Topic => shared.cmd_topic(peer_addr, msg.param(0), msg.param_opt(1)),
        Command::User => {
            // https://tools.ietf.org/html/rfc2812.html#section-3.1.3
            let mode: u8 = msg.param(1).parse().unwrap_or_default();
            shared.cmd_user(peer_addr, msg.param(0), msg.param(3), mode & 8 != 0, mode & 4 != 0);
        },
    }
    Ok(())
}

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
