use criterion as c;
use criterion::{criterion_group, criterion_main};
use ellidri_tokens as irc;

// TODO read from big files

const MESSAGE: &str = "@label=hi;;+=;++;+;=;+data=iodjziidd,e15f531e5f3z5efzef\\s\\s;+=++;msgid=hello;;a;a;a;a;a;a;AD.AD.AD.;;KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK=VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV :wow-thats-what-i-call-a-domain-name-dot-com.pizza.beer USER someusername what is :going on this is not what I paid for please stop using fake real names the more so if they're this long!!!";

const TAG: &str = "my_really_good_tag.surprise.its.actually_a-domoain_name.com/therealnameofthevendoredtagorshouldisaykeyinsteadofnametoreallyfollowircv3sbehavior=This\\sis\\sthe\\svalue\\sof\\sthe\\key.\\nYou\\scan\\sput\\sescapes\\sin\\sthe\\value\\sso\\sthat\\sit\\scan\\scontain\\sspaces\\sor\\snewlines\\nFor\\sexample:\\s\\\\s\\sis\\sthe\\sescaped\\sspace,\\sand\\s\\\\:\\sis\"\\:\".\\sSimple,\\sright?";
const _COMPLEX_TAGS: &str = "@msgid=42;time=12:12:12:12:12;+=;=;;++++;+draft/reply=41;+do.it/dont";

fn message(c: &mut c::Criterion) {
    let mut long_message = String::with_capacity(4096);
    long_message.push_str(MESSAGE);
    (0..3000).for_each(|_| long_message.push('a'));
    c.bench_function("Message::parse() + tags()", |b| {
        b.iter(|| {
            let msg = irc::Message::parse(c::black_box(&long_message)).unwrap();
            irc::tags(msg.tags).for_each(|tag| {
                c::black_box(tag);
            })
        })
    })
    .bench_function("Tag::unescape_value_into()", |b| {
        let tag = irc::Tag::parse(TAG);
        let mut buf = String::with_capacity(1024);
        b.iter(|| {
            buf.clear();
            c::black_box(&tag).unescape_value_into(&mut buf);
        })
    });
}

criterion_group!(benches, message);
criterion_main!(benches);
