# ellidri-tokens

A minimal library that provides helpers to:

- correctly and efficiently parse IRC messages and modes
- correctly and efficiently build IRC messages

To the [documentation](https://docs.rs/ellidri-tokens)!


## Usage

```toml
[dependencies]
ellidri-tokens = "0.1.0"
```

Let's start with a simple problem...

```rust
use ellidri_tokens as irc;

// What's the topic of #ircdocs?
let msg = irc::Message::parse("TOPIC #ircdocs\r\n").unwrap();

assert_eq!(msg.num_params, 1);
assert_eq!(msg.params[0], "#ircdocs");

match msg.command {
    Ok(Command::Topic) => {
        // Let's send back the topic!
        let mut buffer = irc::Buffer::new();

        buffer.message("my.server.com", irc::rpl::TOPIC)
            .param("their_nick")
            .param("#ircdocs")
            .trailing_param("Praise the IRC!");

        let string = buffer.build();
        println!("{}", string);
        // :my.server.com 332 their_nick #ircdocs :Praise the IRC!\r\n
    }
    _ => unreachable!(),
}
```

And what if I want to use modern IRCv3?

```rust
use ellidri_tokens as irc;

// I want to join #ircdocs!  with tags!
let msg = irc::Message::parse("@label=mylabel JOIN #ircdocs\r\n").unwrap();

let mut tags = msg.tags();  // Iterate over the tags!
assert_eq!(tags.next(), Some(Tag { key: "label", value: Some("mylabel") }));
assert_eq!(tags.next(), None);

match msg.command {
    Ok(Command::Join) => {
        // Ok! make them join!
        let mut reply_buffer = irc::ReplyBuffer::new(
            "my.server.com",  // server's domain!
            "their_nick",     // ... their nick!
            msg.tags().find(|tag| tag.key == "label").and_then(|tag| tag.value),
        );

        reply_buffer.start_lr_batch();  // start the labeled-response batch!
        reply_buffer.message("their_nick!~user@host", Command::Join)
            .param("#ircdocs");

        // Easily send replies!
        reply_buffer.reply(irc::rpl::TOPIC)
            .param("#ircdocs")
            .trailing_param("Praise the IRC!");

        reply_buffer.reply(irc::rpl::NAMREPLY)
            .param("=")
            .param("#ircdocs")
            .trailing_param("@dan- their_nick");

        reply.end_lr();  // end the batch... or write ACK!

        let string = reply_buffer.build();
        println!("{}", string);
        // @label=mylabel :my.server.com BATCH +0 labeled-response\r\n
        // @batch=0 :their_nick!~user@host 332 their_nick #ircdocs :Praise the IRC!\r\n
        // @batch=0 :my.server.com 353 their_nick = #ircdocs :@dan- their_nick\r\n
        // :my.server.com BATCH -0\r\n
    }
    _ => unreachable!(),
}
```

Parse mode strings like a boss!

```rust
use ellidri_tokens::mode;

let mut modes = mode::user_query("+i-oi");
assert_eq!(modes.next().unwrap(), Ok(mode::UserChange::Invisible(true)));
assert_eq!(modes.next().unwrap(), Ok(mode::UserChange::Deoperator));
assert_eq!(modes.next().unwrap(), Ok(mode::UserChange::Invisible(false)));
assert!(modes.next().is_none());

let mut modes = mode::channel_query("+ol-m", &["chief", "42"]);
assert_eq!(modes.next().unwrap(), Ok(mode::ChannelChange::Operator(true, "chief")));
assert_eq!(modes.next().unwrap(), Ok(mode::ChannelChange::UserLimit(Some("42")));
assert_eq!(modes.next().unwrap(), Ok(mode::ChannelChange::Moderated(false));
assert!(modes.next().is_none());
```


## License

This library is under the ISC license.
