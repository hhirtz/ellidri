pub use self::cap::Capabilities;
pub use self::req::Request;
pub use self::strings::{ChannelName, HostName, JoinList, Key, List, Mask, Nickname};
pub mod auth;
pub mod cap;
pub mod modes;
pub mod req;
mod strings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<'a> {
    ErroneousNickname(&'a str),
    InvalidCap,
    InvalidCapCmd(&'a str),
    NoSuchChannel(&'a str),
    NoSuchNick(&'a str),
    NeedMoreParams(ellidri_tokens::Command, usize),
    UnknownCommand(&'a str),
}
