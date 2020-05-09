use std::fmt::Arguments;

//
// Network messages
//

pub const BAD_PASSWORD: &str = "You're not senpai!";

pub const CLOSING_LINK: &str = "Bye bye senpai!";

pub const CONNECTION_RESET: &str = "This senpai left without saying anything...";

pub fn quit<F, T>(reason: Option<&str>, f: F) -> T
where
    F: FnOnce(Arguments<'_>) -> T,
{
    if let Some(reason) = reason {
        f(format_args!("This senpai left a note: {}", reason))
    } else {
        f(format_args!("This senpai left"))
    }
}

pub const REGISTRATION_TIMEOUT: &str = "Senpai is such a slowpoke... baka";

//
// IRC replies
//

pub const ADMIN_ME: &str = "Administrative info";

pub const ALREADY_REGISTERED: &str = "You can't re-register, dummy!";

pub const NOW_AWAY: &str = "See you later!";

pub const UN_AWAY: &str = "Welcome back!";

pub const BAD_CHAN_KEY: &str = "Whoops, guess you've entered the wrong channel key :s";

pub const BANNED_FROM_CHAN: &str = "They don't want you in here senpai...";

pub const CANNOT_SEND_TO_CHAN: &str = "They can't hear you from here senpai...";

pub const CHAN_O_PRIVS_NEEDED: &str = "You need to ask a channel operator";

pub const CHANNEL_IS_FULL: &str = "Please, this channel could not take it!";

pub const END_OF_BAN_LIST: &str = "End of ban list";

pub const END_OF_EXCEPT_LIST: &str = "End of except list";

pub const END_OF_INFO: &str = "End of info";

pub const END_OF_INVITE_LIST: &str = "End of invite list";

pub const END_OF_LIST: &str = "End of list";

pub const END_OF_MOTD: &str = "End of MOTD";

pub const END_OF_NAMES: &str = "End of names";

pub const END_OF_WHO: &str = "End of WHO list";

pub const END_OF_WHOIS: &str = "End of WHOIS list";

pub const ERRONEOUS_NICKNAME: &str = "Meh, this is obviously a bad nickname...";

pub const INPUT_TOO_LONG: &str =
    "Please wait senpai, that's too big!  If only there was one message at a time...";

pub const INVITE_ONLY_CHAN: &str = "They didn't invite you yet, keep trying~!";

pub const KEY_SET: &str = "The channel key is already here, senpai!";

pub const NEED_MORE_PARAMS: &str = "You are not telling me everything, are you?";

pub const NICKNAME_IN_USE: &str = "Another senpai already took this nickname...";

pub const NO_MOTD: &str = "ellidri can't find the MOTD...";

pub const NO_TOPIC: &str = "It seems this channel doesn't have any topic";

pub const NO_PRIVILEDGES: &str = "Senpai, could you stop doing that? ellidri doesn't like it...";

pub const NO_SUCH_NICK: &str = "I can't find this senpai...";

pub const NO_SUCH_CHANNEL: &str = "I can't find this channel...";

pub const NOT_ON_CHANNEL: &str = "Senpai... I can't do that if you're not on the channel!";

pub const NOT_REGISTERED: &str = "You must register first!";

pub const PASSWORD_MISMATCH: &str = "Nope! Wrong password";

pub const PART_ALL: &str = "Baka!";

pub const REHASHING: &str = "Oh~~!  Onwards to reload the configuration!";

pub const UNKNOWN_COMMAND: &str = "Hnn... What did you just say?";

pub const UNKNOWN_MODE: &str = "This letter right here... what does it mean?";

pub const USER_NOT_IN_CHANNEL: &str = "This senpai isn't on the channel";

pub const USERS_DONT_MATCH: &str = "Kyaaa! Peeking is bad senpai! Please don't do that again!";

pub const USER_ON_CHANNEL: &str = "Don't worry senpai! They're already on the channel!";

pub const YOURE_OPER: &str = "You are now a BIG senpai!";

pub const WHOIS_IDLE: &str = "Seconds since last activity, registration time";

//
// Welcome messages
//

#[macro_export]
macro_rules! lines_your_host {
    ( $host:expr, $version:expr ) => {
        format_args!("Your host is {} running version {}", $host, $version)
    };
}

pub const I_SUPPORT: &str = "are allowed by ellidri";

#[macro_export]
macro_rules! lines_created {
    ( $since:expr ) => {
        format_args!("I've been looking at you since {}", $since)
    };
}

pub const LUSER_CHANNELS: &str = "channels created";

#[macro_export]
macro_rules! lines_luser_client {
    ( $num_clients:expr ) => {
        format_args!("There are {} senpai(s) on 1 server", $num_clients)
    };
}

#[macro_export]
macro_rules! lines_luser_me {
    ( $num_clients:expr ) => {
        format_args!("I have {} senpai(s) and 0 servers", $num_clients)
    };
}

pub const LUSER_OP: &str = "operator(s) online";

pub const LUSER_UNKNOWN: &str = "unknown connection(s)";

#[macro_export]
macro_rules! lines_motd_start {
    ( $domain:expr ) => {
        format_args!("- {} message of the day -", $domain)
    };
}

#[macro_export]
macro_rules! lines_welcome {
    ( $name:expr ) => {
        format_args!("Welcome home, {}", $name)
    };
}

//
// SASL
//

pub const SASL_ABORTED: &str = "ABORT BAKA";

pub const SASL_ALREADY: &str = "I can't authenticate you again senpai!";

pub const SASL_FAILED: &str = "it's not like I wanted to do my best for you, but it didn't worked";

pub const SASL_MECHS: &str = "please use these to authenticate!";

pub const SASL_SUCCESSFUL: &str = "sugoi~~! looks like it worked!";

pub const SASL_TOO_LONG: &str = "senpai, it's too big!";

#[macro_export]
macro_rules! lines_logged_in {
    ( $user:expr ) => {
        format_args!("okaeri {}", $user)
    };
}

//
// Setname
//

pub const INVALID_REALNAME: &str = "Meh, this is obviously a bad realname...";
