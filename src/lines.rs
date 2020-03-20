use crate::message::MessageBuffer;

// Network messages

pub const CONNECTION_RESET: &str =
"This senpai left without saying anything...";

// IRC replies

pub const ADMIN_ME: &str =
"Administrative info";

pub const ALREADY_REGISTERED: &str =
"You can't reregister dummy!";

pub const BAD_CHAN_KEY: &str =
"Woops, guess you've entered the wrong channel key :s";

pub const BANNED_FROM_CHAN: &str =
"They don't want you in here senpai...";

pub const CANNOT_SEND_TO_CHAN: &str =
"They can't hear you from here senpai...";

pub const CHAN_O_PRIVS_NEEDED: &str =
"You need to ask a channel operator";

pub const CHANNEL_IS_FULL: &str =
"Please, this channel could not take it!";

pub const CLOSING_LINK: &str =
"Bye bye senpai!";

pub const END_OF_BAN_LIST: &str =
"End of ban list";

pub const END_OF_EXCEPT_LIST: &str =
"End of excect list";

pub const END_OF_INFO: &str =
"End of info";

pub const END_OF_INVITE_LIST: &str =
"End of invite list";

pub const END_OF_LIST: &str =
"End of list";

pub const END_OF_MOTD: &str =
"End of MOTD";

pub const END_OF_NAMES: &str =
"End of names";

pub const END_OF_WHO: &str =
"End of WHO list";

pub const END_OF_WHOIS: &str =
"End of WHOIS list";

pub const ERRONEOUS_NICNAME: &str =
"Meh, this is obviously a bad nickname...";

pub const INPUT_TOO_LONG: &str =
"Please wait senpai, that's too big!  If only there was one message at a time...";

pub const INVITE_ONLY_CHAN: &str =
"They didn't invite you yet, keep trying~!";

pub const KEY_SET: &str =
"The channel key is already here, senpai!";

pub const LUSER_CHANNELS: &str =
"channels created";

pub const NEED_MORE_PARAMS: &str =
"You are not telling me everything, are you?";

pub const NICKNAME_IN_USE: &str =
"Another senpai already took this nickname...";

pub const NO_MOTD: &str =
"ellidri can't find the MOTD...";

pub const NO_TOPIC: &str =
"It seems this channel doesn't have any topic";

pub const NOT_ON_CHANNEL: &str =
"Senpai... I can't do that if you're not on the channel!";

pub const NOT_REGISTERED: &str =
"You must register first!";

pub const NO_SUCH_NICK: &str =
"I can't find this senpai...";

pub const NO_SUCH_CHANNEL: &str =
"I can't find this channel...";

pub const PASSWORD_MISMATCH: &str =
"Nope! Wrong password";

pub const UNKNOWN_COMMAND: &str =
"Hnn... What did you just say?";

pub const UNKNOWN_MODE: &str =
"This letter right here... what does it mean?";

pub const USER_NOT_IN_CHANNEL: &str =
"This senpai isn't on the channel";

pub const USERS_DONT_MATCH: &str =
"Kyaaa! Peeking is bad senpai! Please don't do that again!";

pub const USER_ON_CHANNEL: &str =
"Don't worry senpai! They're already on the channel!";

pub const YOURE_OPER: &str =
"You are now a BIG senpai!";

pub const WHOIS_IDLE: &str =
"Seconds since last activity, registration time";

// Welcome messages

pub const YOUR_HOST: &str =
concat!("Your host is ellidri, running version ", crate::server_version!());

pub const I_SUPPORT: &str =
"are allowed by ellidri";

pub fn created(mut r: MessageBuffer<'_>, since: &str) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("I've been looking at you since ");
    trailing.push_str(since);
}

pub fn luser_client(mut r: MessageBuffer<'_>, num_clients: usize) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("There are ");
    trailing.push_str(&num_clients.to_string());
    trailing.push_str(" senpais on 1 server");
}

pub fn luser_me(mut r: MessageBuffer<'_>, num_clients: usize) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("I have ");
    trailing.push_str(&num_clients.to_string());
    trailing.push_str(" senpais and 0 servers");
}

pub fn motd_start(mut r: MessageBuffer<'_>, domain: &str) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("- ");
    trailing.push_str(domain);
    trailing.push_str(" message of the day -");
}

pub fn welcome(mut r: MessageBuffer<'_>, name: &str) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("Welcome home, ");
    trailing.push_str(name);
}

// SASL

pub const SASL_ABORTED: &str =
"ABORT BAKA";

pub const SASL_ALREADY: &str =
"I can't authenticate you again senpai!";

pub const SASL_FAILED: &str =
"it's not like I wanted to do my best for you, but it didn't worked";

pub const SASL_MECHS: &str =
"please use these to authenticate!";

pub const SASL_SUCCESSFUL: &str =
"sugoi~~! looks like it worked!";

pub const SASL_TOO_LONG: &str =
"senpai, it's too big!";

pub fn logged_in(mut r: MessageBuffer<'_>, user: &str) {
    let trailing = r.raw_trailing_param();
    trailing.push_str("okaeri ");
    trailing.push_str(user);
}

// Setname

pub const INVALID_REALNAME: &str =
"Meh, this is obviously a bad realname...";
