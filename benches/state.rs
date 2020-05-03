use criterion as c;
use criterion::{criterion_group, criterion_main};
use futures::executor::block_on;
use ellidri::state::{State, test};
use ellidri_tokens as irc;

const ALL_CAPS: &str = "account-notify away-notify batch cap-notify echo-message extended-join \
invite-notify labeled-response message-tags multi-prefix server-time setname userhost-in-names";

struct StateCase(State, Vec<(test::ClientId, test::Queue)>);

fn state(num_clients: usize) -> StateCase {
    block_on(async {
        let s = test::simple_state();
        let mut clients = Vec::with_capacity(num_clients);
        for i in 0..num_clients {
            let mut c = test::add_registered_client(&s, &format!("client{}", i)).await;
            test::flush(&mut c.1);
            clients.push(c);
        }
        StateCase(s, clients)
    })
}

impl StateCase {
    pub fn with_caps(self, caps: &str) -> Self {
        self.all_send(&format!("CAP REQ :{}", caps))
    }

    pub fn all_join(self, channel: &str) -> StateCase {
        self.all_send(&format!("JOIN {}", channel))
    }

    pub fn all_send(mut self, message: &str) -> StateCase {
        block_on(async {
            for c in &self.1 {
                test::handle_message(&self.0, c.0, message).await;
            }
            for c in &mut self.1 {
                test::flush(&mut c.1);
            }
        });
        self
    }
}

fn bench(c: &mut c::Criterion) {
    c.bench_function("PRIVMSG to a 1000-user channel", |b| {
        let StateCase(s, mut cs) = state(1000).all_join("#channel");
        b.iter(|| block_on(async {
            test::handle_message(&s, cs[0].0, "PRIVMSG #channel :salut ça va ?").await;
            for c in &mut cs {
                test::flush(&mut c.1);
            }
        }));
    })
    .bench_function("PRIVMSG to a 1000-user channel with caps", |b| {
        let StateCase(s, mut cs) = state(1000)
            .with_caps(ALL_CAPS)
            .all_join("#channel");
        b.iter(|| block_on(async {
            test::handle_message(&s, cs[0].0, "@label=123456 PRIVMSG #channel :salut ça va ?").await;
            for c in &mut cs {
                test::flush(&mut c.1);
            }
        }));
    });
}

fn bench2(c: &mut c::Criterion) {
    let tags = "label=123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ;msgid=123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ;;;;;;;;;;;+;;+;;+;;+;+=;;+=;;+=;;=;;=;;;;;;;;;;;;time=123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ;+client_tag=";
    let message = ":this.is.the.prefix PRIVMSG #this-is-the-channel :This is the message.\r\n";

    let mut group = c.benchmark_group("Tags");
    group.throughput(c::Throughput::Bytes(tags.len() as u64));
    group.bench_function("decode", |b| b.iter(|| {
        for tag in irc::tags(tags) {
            c::black_box(tag);
        }
    }));
    group.finish();

    let mut group = c.benchmark_group("Messages");
    group.throughput(c::Throughput::Bytes(message.len() as u64));
    group.bench_function("decode", |b| b.iter(|| {
        for msg in irc::Message::parse(message) {
            c::black_box(msg);
        }
    }));
    group.finish();
}

criterion_group!(benches, bench, bench2);
criterion_main!(benches);
