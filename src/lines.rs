use std::{fmt, net};

use crate::message::MessageBuffer;

pub const ADMIN_ME: &str =
"TODO";

pub const BAD_CHAN_KEY: &str =
"TODO";

pub const BANNED_FROM_CHAN: &str =
"TODO";

pub const CANNOT_SEND_TO_CHAN: &str =
"The fuck you're trying to do, motherfucker? Do you fucking mind knocking at the door?";

pub const CHAN_O_PRIVS_NEEDED: &str =
"TODO";

pub const CHANNEL_IS_FULL: &str =
"TODO";

pub const END_OF_BAN_LIST: &str =
"TODO";

pub const END_OF_EXCEPT_LIST: &str =
"TODO";

pub const END_OF_INFO: &str =
"TODO";

pub const END_OF_INVITE_LIST: &str =
"TODO";

pub const END_OF_LIST: &str =
"TODO";

pub const END_OF_MOTD: &str =
"Creep, don't get cocky just because senpai told me to say it!";

pub const END_OF_NAMES: &str =
"Found your fucking friends yet, dickhead?";

pub const ERRONEOUS_NICNAME: &str =
"That name is a joke. No, it wasn't funny. Go away.";

pub const INVITE_ONLY_CHAN: &str =
"TODO";

pub const KEY_SET: &str =
"TODO";

pub const LUSER_CHANNELS: &str =
"stinking dens dug";

pub const NEED_MORE_PARAMS: &str =
"What did you expect, motherfucker? Don't bother me if you have nothing to say.";

pub const NICKNAME_IN_USE: &str =
"Serves you right, shithead, one of you already has that shitty name!";

pub const NO_MOTD: &str =
"Senpai wouldn't bother talking to scum like you!";

pub const NO_RECIPIENT: &str =
"Do you understand what you're doing? Do you even understand human language? Hello?";

pub const NO_TEXT_TO_SEND: &str =
"If you have nothing to say, dumbass, you can go fuck yourself.";

pub const NO_TOPIC: &str =
"Dumbass, this chan doesn't have any topic!";

pub const NO_NICKNAME_GIVEN: &str =
"So what do I call you? \"piece of shit\" seems appropriate, no?";

pub const NOT_ON_CHANNEL_PART: &str =
"You lost, dumbass? Try QUIT.";

pub const NOT_ON_CHANNEL_TOPIC: &str =
"Topic might be: Go fuck yourself you fucking retard.";

pub const NO_SUCH_NICK: &str =
"Sorry to disappoint you but... I don't speak smelly NEET. Yuck!";

pub const NO_SUCH_CHANNEL: &str =
"Do you see this shit, motherfucker? Try and say that one more time.";

pub const PASSWORD_MISMATCH: &str =
"TODO";

pub const RATELIMIT: &str =
"Fucking creep, stop spamming.";

pub const UNKNOWN_COMMAND: &str =
"rfc2812 motherfucker, do you speak it?";

pub const UNKNOWN_MODE: &str =
"Is that a threat, motherfucker? I'll let that slide for now.\
If I see you do that again, you know what to do.";

pub const USER_NOT_IN_CHANNEL: &str =
"TODO";

pub const USERS_DONT_MATCH: &str =
"TODO";

pub const YOURE_OPER: &str =
"TODO";

// Welcome messages

pub const WELCOME: &str =
"Hmph. It's not like I wanted to welcome you.";

pub const YOUR_HOST: &str =
"I did it for senpai! Ooh senpai~ you're the best!";

pub const I_SUPPORT: &str =
"are allowed by senpai";

// lines with parameters

pub fn created(mut r: MessageBuffer<'_>, since: &chrono::DateTime<chrono::Local>) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("We've been together since ");
    trailing.push_str(&since.to_rfc2822());
    r.build();
}

pub fn luser_client(mut r: MessageBuffer<'_>, num_clients: usize) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("There are ");
    trailing.push_str(&num_clients.to_string());
    trailing.push_str(" shitheads on 1 server");
    r.build();
}

pub fn luser_me(mut r: MessageBuffer<'_>, num_clients: usize) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("I have ");
    trailing.push_str(&num_clients.to_string());
    trailing.push_str(" shitheads and 0 servers");
    r.build();
}

// src/net.rs

pub fn print_accept_error<E>(err: E)
    where E: fmt::Display
{
    log::info!(
        "I'm seeing thing senpai, someone just {}. Or is it that I'm getting too old?? No way!",
        err);
}

pub fn print_tls_error<E>(err: E, addr: net::SocketAddr)
    where E: fmt::Display
{
    log::info!(
        "Senpai! Some weird {} didn't know how to speak TLS! Like, who would have {} anyway",
        addr, err);
}

pub fn print_broken_pipe_error<E>(err: E, addr: net::SocketAddr)
    where E: fmt::Display
{
    log::info!("{} left!! I'm so sad... *sob* They said {}, meanie...", addr, err);
}

pub fn print_invalid_data_error<E>(err: E, addr: net::SocketAddr)
    where E: fmt::Display
{
    log::info!("Some people came, I didn't understand what they were saying...
But they're gone now, we're alone together senpai!! :3
            *grabs knife*          (*0w0)
(You hear someone whisper) {}
Connection with {} has been terminated! <3", err, addr);
}
