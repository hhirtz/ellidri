//! Testing utilities for `ellidri::state`

use crate::{config, Config};
use crate::client::MessageQueueItem;
use crate::message::{assert_msg, Command, Message};
use std::cell::RefCell;
use std::net::SocketAddr;
use super::StateInner;
use tokio::sync::mpsc;

type Queue = mpsc::UnboundedReceiver<MessageQueueItem>;

pub const DOMAIN: &str = "elli.dri";
const NICKBUF_START: &str = "NICK :";
thread_local! {
    static CONFIG: Config = Config::default();
    static NICKBUF: RefCell<String> = RefCell::new(String::from(NICKBUF_START));
}

pub(crate) fn simple_state() -> StateInner {
    StateInner::new(config::State { domain: DOMAIN.to_owned(), ..config::State::sample() })
}

pub(crate) fn add_client(s: &mut StateInner) -> (SocketAddr, Queue) {
    let port = s.clients.len() as u16;
    let res = SocketAddr::from(([127, 0, 0, 1], port));
    let (msg_queue, outgoing_msgs) = mpsc::unbounded_channel();
    s.peer_joined(res, msg_queue);
    (res, outgoing_msgs)
}

pub(crate) fn add_registered_client(s: &mut StateInner, nickname: &str) -> (SocketAddr, Queue) {
    let (addr, queue) = add_client(s);
    NICKBUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.truncate(NICKBUF_START.len());
        buf.push_str(nickname);
        let nick = Message::parse(&buf).unwrap();
        let user = Message::parse("USER X X X X").unwrap();
        let _ = s.handle_message(&addr, nick);
        let _ = s.handle_message(&addr, user);
    });
    (addr, queue)
}

pub(crate) fn handle_message(state: &mut StateInner, addr: &SocketAddr, message: &str) {
    let message = Message::parse(message).unwrap();
    let _ = state.handle_message(addr, message);
}

pub fn flush(queue: &mut Queue) {
    loop {
        match queue.try_recv() {
            Ok(msg) => {
                println!("flushed: {:?}", msg);
            },
            Err(mpsc::error::TryRecvError::Empty) => return,
            Err(_) => unreachable!(),
        }
    }
}

pub fn collect(res: &mut String, queue: &mut Queue) {
    loop {
        match queue.try_recv() {
            Ok(item) => {
                let s: &str = item.as_ref();
                res.push_str(s);
            },
            Err(mpsc::error::TryRecvError::Empty) => return,
            Err(_) => unreachable!(),
        }
    }
}

pub fn messages(s: &str) -> impl Iterator<Item=Message<'_>> {
    s.lines().map(|line| Message::parse(line).expect("bad message"))
}

#[allow(clippy::type_complexity)]  // TODO
pub fn assert_msgs(s: &str, expected: &[(Option<&str>, Result<Command, &str>, &[&str])]) {
    let mut i = 0;
    for msg in messages(s) {
        let (prefix, command, params) = expected[i];
        assert_msg(&msg, prefix, command, params);
        i += 1;
    }
    assert_eq!(i, expected.len());
}
