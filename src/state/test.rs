//! Testing utilities for `ellidri::state`

use crate::config::{Config, StateConfig};
use crate::client::MessageQueueItem;
use crate::message::Message;
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
    StateInner::new(StateConfig {
        domain: DOMAIN.to_owned(),
        default_chan_mode: "+nt".to_owned(),
        ..StateConfig::default()
    })
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
        s.handle_message(&addr, nick);
        s.handle_message(&addr, user);
    });
    (addr, queue)
}

pub fn flush(queue: &mut Queue) {
    loop {
        match queue.try_recv() {
            Ok(_) => {},
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

pub(crate) fn sequence(state: &mut StateInner, messages: &[(&SocketAddr, &str)]) {
    for (c, message) in messages {
        let message = Message::parse(message).unwrap();
        state.handle_message(c, message);
    }
}
