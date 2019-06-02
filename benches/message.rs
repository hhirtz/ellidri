extern crate ellidri;

use std::net;

use criterion::{black_box, Criterion, criterion_group, criterion_main};
use ellidri::{MessageQueueItem, State};
use ellidri::config::{AdminInfo, StateConfig};
use ellidri::message::{Command, Message};
use futures::sync::mpsc;

fn message_builder(c: &mut Criterion) {
    c
        .bench_function("Message::with_prefix(no_build)", |b| {
            let prefix = "ellidri";
            let command = Command::Admin;
            b.iter(|| Message::with_prefix(prefix, black_box(command)).build())
        })
        .bench_function("Message::with_prefix()", |b| {
            let prefix = "ellidri";
            let command = Command::Admin;
            b.iter(|| Message::with_prefix(prefix, black_box(command)).build().into_bytes())
        })
        .bench_function("Message::with_prefix(long_prefix)", |b| {
            let prefix = "multiuser.chat.irc.ellidri.localdomain";
            let command = Command::Admin;
            b.iter(|| Message::with_prefix(prefix, black_box(command)).build().into_bytes())
        })
        .bench_function("Message::with_prefix(param)", |b| {
            let prefix = "ellidri";
            let command = Command::Admin;
            b.iter(|| {
                Message::with_prefix(prefix, black_box(command))
                    .param("AniceParamWithNoSpacePlease")
                    .build()
                    .into_bytes()
            })
        })
        .bench_function("Message::with_prefix(param, param)", |b| {
            let prefix = "ellidri";
            let command = Command::Admin;
            b.iter(|| {
                Message::with_prefix(prefix, black_box(command))
                    .param("AniceParamWithNoSpacePlease")
                    .param("AniceParamWithNoSpacePlease")
                    .build()
                    .into_bytes()
            })
        })
        .bench_function("Message::with_prefix(param, trailing_param)", |b| {
            let prefix = "ellidri";
            let command = Command::Admin;
            b.iter(|| {
                Message::with_prefix(prefix, black_box(command))
                    .param("AniceParamWithNoSpacePlease")
                    .trailing_param("There, it can have spaces now")
                    .into_bytes()
            })
        })
        .bench_function("Message::with_prefix(param, trailing_param, no_build)", |b| {
            let prefix = "ellidri";
            let command = Command::Admin;
            b.iter(|| {
                Message::with_prefix(prefix, black_box(command))
                    .param("AniceParamWithNoSpacePlease")
                    .trailing_param("There, it can have spaces now");
            })
        })
        .bench_function("Message::with_prefix(trailing_param)", |b| {
            let prefix = "ellidri";
            let command = Command::Admin;
            b.iter(|| {
                Message::with_prefix(prefix, black_box(command))
                    .trailing_param("There, it can have spaces now")
                    .into_bytes()
            })
        });
}

fn message_parse(c: &mut Criterion) {
    c
        .bench_function("Message::parse()", |b| {
            let msg = "PRIVMSG";
            b.iter(|| Message::parse(black_box(msg)))
        })
        .bench_function("Message::parse(unknown command)", |b| {
            let msg = "ProbablyNotACommand";
            b.iter(|| Message::parse(black_box(msg)))
        })
        .bench_function("Message::parse(long prefix)", |b| {
            let msg = ":multiuser.chat.ellidri.localdomain PRIVMSG";
            b.iter(|| Message::parse(black_box(msg)))
        })
        .bench_function("Message::parse(prefix, args)", |b| {
            let msg = ":kawai PRIVMSG #kekbab :You must be joking!";
            b.iter(|| Message::parse(black_box(msg)))
        });
}

fn message_params(c: &mut Criterion) {
    c
        .bench_function("Message::params()", |b| {
            let msg = Message::parse(":kawai PRIVMSG #kekbab :You must be joking!\r\n")
                .unwrap().unwrap();
            b.iter(|| black_box(msg.params()).count())
        });
}

criterion_group!(message,
                 message_builder, message_params, message_parse);

struct DummyState {
    state: State,
    counter: u8,
    outgoing_queues: Vec<mpsc::UnboundedReceiver<MessageQueueItem>>,
}

impl DummyState {
    pub fn new() -> DummyState {
        const MOTD: &str = "
        A very cool motd.
        Please subsribe, thanks.
        Your favorite Youtuber.";
        let config = StateConfig {
            domain: String::from("ellidri.localdomain"),
            admin: AdminInfo {
                org_name: String::from("You... I think"),
                location: String::from("Somewhere in this very computer"),
                mail: String::from("There's no mail, sorry"),
            },
            default_chan_mode: String::from("+nt"),
            motd: Some(String::from(MOTD)),
            opers: vec![(String::from("name"), String::from("password"))],
            oper_hosts: vec![String::from("*")],
            password: None,
        };
        DummyState {
            state: State::new(config),
            counter: 0,
            outgoing_queues: Vec::new(),
        }
    }

    pub fn build(&self) -> State {
        self.state.clone()
    }

    pub fn add_client(&mut self) -> net::SocketAddr {
        let addr = net::SocketAddr::from(([self.counter, 0, 0, 0], 6667));
        let (queue, outgoing) = mpsc::unbounded();
        self.state.insert(addr, queue);
        self.counter += 1;
        self.outgoing_queues.push(outgoing);
        addr
    }
}

fn state_cmd_nick(c: &mut Criterion) {
    c
        .bench_function("State::cmd_nick()", |b| {
            let mut dummy = DummyState::new();
            let client = dummy.add_client();
            let state = dummy.build();
            b.iter(|| {
                state.cmd_nick(black_box(client), "Nick");
                state.cmd_nick(black_box(client), "Nick2")
            })
        })
        .bench_function("State::cmd_nick(bad_nick)", |b| {
            let mut dummy = DummyState::new();
            let client = dummy.add_client();
            let state = dummy.build();
            b.iter(|| {
                state.cmd_nick(black_box(client), ":");
                state.cmd_nick(black_box(client), ":")
            })
        })
        .bench_function("State::cmd_nick(taken)", |b| {
            let mut dummy = DummyState::new();
            let client1 = dummy.add_client();
            let client2 = dummy.add_client();
            let state = dummy.build();
            state.cmd_nick(client1, "Nick");
            b.iter(|| {
                state.cmd_nick(black_box(client2), "Nick");
                state.cmd_nick(black_box(client2), "Nick")
            })
        });
}

fn state_send_reply(c: &mut Criterion) {
    c
        .bench_function("State::send_reply()", |b| {
            let mut dummy = DummyState::new();
            let client = dummy.add_client();
            let state = dummy.build();
            b.iter(|| state.send_reply(black_box(client), "404", &["Not found"]))
        });
}

criterion_group!(state,
                 state_cmd_nick, state_send_reply);

criterion_main!(
    message,
   // state,
);
