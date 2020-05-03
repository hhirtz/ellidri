//! Testing utilities for `ellidri::state`

use super::State;
use crate::client::MessageQueueItem;
use crate::{auth, config};
use ellidri_tokens::{assert_msg, Command, Message};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};

pub type ClientId = usize;
pub type Queue = mpsc::UnboundedReceiver<MessageQueueItem>;

pub fn simple_state() -> State {
    let config = config::State::sample();
    let auth_provider = auth::choose_provider(config::SaslBackend::None, None).unwrap();
    let rehash = Arc::new(Notify::new());
    State::new(config, auth_provider, rehash)
}

pub async fn add_client(s: &State) -> (ClientId, Queue) {
    let port = s.0.lock().await.clients.len() as u16;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let (msg_queue, outgoing_msgs) = mpsc::unbounded_channel();
    let res = s.peer_joined(addr, msg_queue).await;
    (res, outgoing_msgs)
}

pub async fn add_registered_client(s: &State, nickname: &str) -> (usize, Queue) {
    let (id, queue) = add_client(s).await;
    let nick = format!("NICK :{}", nickname);
    let nick = Message::parse(&nick).unwrap();
    let user = Message::parse("USER X X X X").unwrap();
    let _ = s.handle_message(id, nick).await;
    let _ = s.handle_message(id, user).await;
    (id, queue)
}

pub async fn handle_message(state: &State, id: ClientId, message: &str) {
    let message = Message::parse(message).unwrap();
    let _ = state.handle_message(id, message).await;
}

pub fn flush(queue: &mut Queue) {
    loop {
        match queue.try_recv() {
            Ok(_msg) => {
                //println!("flushed: {:?}", msg);
            }
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
            }
            Err(mpsc::error::TryRecvError::Empty) => return,
            Err(_) => unreachable!(),
        }
    }
}

pub fn messages(s: &str) -> impl Iterator<Item = Message<'_>> {
    s.lines()
        .map(|line| Message::parse(line).expect("bad message"))
}

type ExpectedMessage<'a> = (Option<&'a str>, Result<Command, &'a str>, &'a [&'a str]);

pub fn assert_msgs(s: &str, expected: &[ExpectedMessage<'_>]) {
    let mut i = 0;
    for msg in messages(s) {
        let (prefix, command, params) = expected[i];
        assert_msg(&msg, prefix, command, params);
        i += 1;
    }
    assert_eq!(i, expected.len());
}
