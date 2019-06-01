extern crate ellidri;

use criterion::{black_box, Criterion, criterion_group, criterion_main};
use ellidri::message::{Message};

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

criterion_group!(message, message_parse, message_params);
criterion_main!(message);
