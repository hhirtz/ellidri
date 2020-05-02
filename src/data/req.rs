use super::*;
use ellidri_tokens::{Command, Message};
use std::convert::TryFrom;

#[derive(Clone, Copy, Debug, Default)]
pub struct WhoFilter {
    pub operator: bool,
}

impl<'a> From<&'a str> for WhoFilter {
    fn from(val: &'a str) -> Self {
        let mut res = Self::default();
        for c in val.chars() {
            match c {
                'o' => res.operator = true,
                _ => {}
            }
        }
        res
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WhoChannel<'a> {
    pub mask: ChannelName<'a>,
    pub filter: WhoFilter,
}
#[derive(Clone, Copy, Debug)]
pub struct WhoMask<'a> {
    pub mask: Mask<'a>,
    pub filter: WhoFilter,
}
#[derive(Clone, Copy, Debug)]
pub struct WhoUser<'a> {
    pub mask: Nickname<'a>,
    pub filter: WhoFilter,
}

#[derive(Clone, Copy, Debug)]
pub struct Kill<'a> {
    pub who: Nickname<'a>,
    pub reason: &'a str,
}
#[derive(Clone, Copy, Debug)]
pub struct Oper<'a> {
    pub name: &'a str,
    pub password: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct TopicSet<'a> {
    pub channel: ChannelName<'a>,
    pub topic: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct User<'a> {
    pub username: &'a str,
    pub realname: &'a str,
}
#[derive(Clone, Copy, Debug)]
pub struct ModeUserSet<'a> {
    pub user: Nickname<'a>,
    pub modes: modes::User<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct Invite<'a> {
    pub who: Nickname<'a>,
    pub to: ChannelName<'a>,
}
#[derive(Clone, Copy, Debug)]
pub struct Kick<'a> {
    pub who: List<'a, Nickname<'a>>,
    pub from: ChannelName<'a>,
    pub reason: Option<&'a str>,
}
#[derive(Clone, Copy, Debug)]
pub struct MessageAll<'a> {
    pub feedback: bool,
    pub command: Command,
    pub content: Option<&'a str>,
}
#[derive(Clone, Copy, Debug)]
pub struct MessageChannel<'a> {
    pub feedback: bool,
    pub command: Command,
    pub to: ChannelName<'a>,
    pub content: Option<&'a str>,
}
#[derive(Clone, Copy, Debug)]
pub struct MessageUser<'a> {
    pub feedback: bool,
    pub command: Command,
    pub to: Nickname<'a>,
    pub content: Option<&'a str>,
}
#[derive(Clone, Copy, Debug)]
pub struct ModeChannelSet<'a> {
    pub channel: ChannelName<'a>,
    pub modes: modes::Channel<'a>,
}
#[derive(Clone, Copy, Debug)]
pub struct Part<'a> {
    pub from: List<'a, ChannelName<'a>>,
    pub reason: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub enum Request<'a> {
    // Requests about general server info.
    Admin,
    Info,
    LUsers,
    Motd,
    Time,
    Version,
    WhoChannel(WhoChannel<'a>),
    WhoMask(WhoMask<'a>),
    WhoUser(WhoUser<'a>),
    WhoAll(WhoFilter),
    WhoIs(Nickname<'a>),

    // IRCop restricted requests.
    Kill(Kill<'a>),
    Oper(Oper<'a>),
    Rehash,

    // Requests about channel info.
    List(List<'a, ChannelName<'a>>),
    ListAll,
    Names(List<'a, ChannelName<'a>>),
    NamesAll,
    TopicGet(ChannelName<'a>),
    TopicSet(TopicSet<'a>),

    // Client session related requests.
    Authenticate(auth::Payload<'a>),
    CapLs(cap::Version),
    CapList,
    CapReq(cap::Diff),
    CapEnd,
    Pass(&'a str),
    Ping(&'a str),
    Pong(&'a str),
    Quit(Option<&'a str>),
    User(User<'a>),

    // Client info related requests.
    Away(Option<&'a str>),
    ModeUserGet(Nickname<'a>),
    ModeUserSet(ModeUserSet<'a>),
    Nick(Nickname<'a>),
    SetName(&'a str),

    // Channel management requests.
    Invite(Invite<'a>),
    Join(JoinList<'a>),
    Kick(Kick<'a>),
    MessageAll(MessageAll<'a>),
    MessageChannel(MessageChannel<'a>),
    MessageUser(MessageUser<'a>),
    ModeChannelGet(ChannelName<'a>),
    ModeChannelSet(ModeChannelSet<'a>),
    Part(Part<'a>),
    PartAll,
}

impl<'a> Request<'a> {
    pub fn new(msg: &'a Message<'a>) -> Result<Self, Error<'a>> {
        let command = msg
            .command
            .map_err(|unknown| Error::UnknownCommand(unknown))?;

        if !msg.has_enough_params() {
            return Err(Error::NeedMoreParams(command, msg.num_params));
        }

        Ok(match command {
            Command::Admin => Self::Admin,
            Command::Info => Self::Info,
            Command::LUsers => Self::LUsers,
            Command::Motd => Self::Motd,
            Command::Time => Self::Time,
            Command::Version => Self::Version,
            Command::Who => {
                let mask = msg.params[0];
                let filter = WhoFilter::from(msg.params[1]);
                if mask.is_empty() || (mask.len() == 1 && mask.as_bytes()[0] == b'*') {
                    Self::WhoAll(filter)
                } else if let Ok(mask) = ChannelName::try_from(mask) {
                    Self::WhoChannel(WhoChannel { mask, filter })
                } else if let Ok(mask) = Nickname::try_from(mask) {
                    Self::WhoUser(WhoUser { mask, filter })
                } else {
                    let mask = Mask::try_from(mask)?;
                    Self::WhoMask(WhoMask { mask, filter })
                }
            }
            Command::WhoIs => {
                let mask = Nickname::try_from(msg.params[0])?;
                Self::WhoIs(mask)
            }

            Command::Kill => {
                let who = Nickname::try_from(msg.params[0])?;
                let reason = msg.params[1];
                Self::Kill(Kill { who, reason })
            }
            Command::Oper => {
                let name = msg.params[0];
                let password = msg.params[1];
                Self::Oper(Oper { name, password })
            }
            Command::Rehash => Self::Rehash,

            Command::List => {
                let channel_names = msg.params[0];
                if channel_names.is_empty() {
                    Self::ListAll
                } else {
                    let channels = List::new(channel_names, ',');
                    Self::List(channels)
                }
            }
            Command::Names => {
                let channel_names = msg.params[0];
                if channel_names.is_empty() {
                    Self::NamesAll
                } else {
                    let channels = List::new(channel_names, ',');
                    Self::Names(channels)
                }
            }
            Command::Topic => {
                let channel = ChannelName::try_from(msg.params[0])?;
                if msg.num_params == 1 {
                    Self::TopicGet(channel)
                } else {
                    let topic = msg.params[1];
                    Self::TopicSet(TopicSet { channel, topic })
                }
            }

            Command::Authenticate => {
                let payload = auth::Payload::from(msg.params[0]);
                Self::Authenticate(payload)
            }
            Command::Cap => match msg.params[0] {
                "LS" => {
                    let version = cap::Version::from(msg.params[1]);
                    Self::CapLs(version)
                }
                "LIST" => Self::CapList,
                "REQ" => {
                    let requested = cap::Diff::try_from(msg.params[1])?;
                    Self::CapReq(requested)
                }
                "END" => Self::CapEnd,
                other => return Err(Error::InvalidCapCmd(other)),
            },
            Command::Pass => {
                let password = msg.params[0];
                Self::Pass(password)
            }
            Command::Ping => {
                let payload = msg.params[0];
                Self::Ping(payload)
            }
            Command::Pong => {
                let payload = msg.params[0];
                Self::Pong(payload)
            }
            Command::Quit => {
                let reason = if msg.params[0].is_empty() {
                    None
                } else {
                    Some(msg.params[0])
                };
                Self::Quit(reason)
            }
            Command::User => {
                let username = msg.params[0];
                let realname = msg.params[3];
                Self::User(User { username, realname })
            }

            Command::Away => {
                let reason = if msg.params[0].is_empty() {
                    None
                } else {
                    Some(msg.params[0])
                };
                Self::Away(reason)
            }
            Command::Mode => {
                let n = msg.num_params;
                if let Ok(channel) = ChannelName::try_from(msg.params[0]) {
                    if n == 1 {
                        Self::ModeChannelGet(channel)
                    } else {
                        let modes = modes::Channel::new(msg.params[1], &msg.params[2..n]);
                        Self::ModeChannelSet(ModeChannelSet { channel, modes })
                    }
                } else {
                    let user = Nickname::try_from(msg.params[0])?;
                    if n == 1 {
                        Self::ModeUserGet(user)
                    } else {
                        let modes = modes::User::new(msg.params[1]);
                        Self::ModeUserSet(ModeUserSet { user, modes })
                    }
                }
            }
            Command::Nick => {
                let nickname = Nickname::try_from(msg.params[0])?;
                Self::Nick(nickname)
            }
            Command::SetName => {
                let realname = msg.params[0];
                Self::SetName(realname)
            }

            Command::Invite => {
                let who = Nickname::try_from(msg.params[0])?;
                let to = ChannelName::try_from(msg.params[1])?;
                Self::Invite(Invite { who, to })
            }
            Command::Join => {
                if msg.params[0] == "0" {
                    Self::PartAll
                } else {
                    let channels = JoinList::new(msg.params[0], msg.params[1]);
                    Self::Join(channels)
                }
            }
            Command::Kick => {
                let from = ChannelName::try_from(msg.params[0])?;
                let who = List::new(msg.params[1], ',');
                let reason = if msg.params[2].is_empty() {
                    None
                } else {
                    Some(msg.params[2])
                };
                Self::Kick(Kick { who, from, reason })
            }
            Command::PrivMsg | Command::Notice | Command::TagMsg => {
                let feedback = match command {
                    Command::Notice => false,
                    Command::PrivMsg | Command::TagMsg => true,
                    _ => unreachable!(),
                };
                let content = match command {
                    Command::PrivMsg | Command::Notice => {
                        if msg.params[1].is_empty() {
                            return Err(Error::NeedMoreParams(command, 1));
                        }
                        Some(msg.params[1])
                    }
                    Command::TagMsg => None,
                    _ => unreachable!(),
                };
                if msg.params[0] == "*" {
                    Self::MessageAll(MessageAll {
                        feedback,
                        command,
                        content,
                    })
                } else if let Ok(to) = ChannelName::try_from(msg.params[0]) {
                    Self::MessageChannel(MessageChannel {
                        feedback,
                        command,
                        to,
                        content,
                    })
                } else {
                    let to = Nickname::try_from(msg.params[0])?;
                    Self::MessageUser(MessageUser {
                        feedback,
                        command,
                        to,
                        content,
                    })
                }
            }
            Command::Part => {
                let from = List::new(msg.params[0], ',');
                let reason = if msg.params[1].is_empty() {
                    None
                } else {
                    Some(msg.params[1])
                };
                Self::Part(Part { from, reason })
            }

            Command::Reply(_) => unreachable!(),
        })
    }

    pub fn points(&self) -> u32 {
        match self {
            // Requests about general server info.
            Self::Admin => 2,
            Self::Info => 3,
            Self::LUsers => 3,
            Self::Motd => 3,
            Self::Time => 2,
            Self::Version => 2,
            Self::WhoChannel(_) => 5,
            Self::WhoMask(_) => 10,
            Self::WhoUser(_) => 4,
            Self::WhoAll(_) => 8,
            Self::WhoIs(_) => 4,

            // IRCop restricted requests.
            Self::Kill(_) => 16,
            Self::Oper(_) => 16,
            Self::Rehash => 16,

            // Requests about channel info.
            Self::List(_) => 4,
            Self::ListAll => 8,
            Self::Names(_) => 4,
            Self::NamesAll => 2,
            Self::TopicGet(_) => 4,
            Self::TopicSet(_) => 7,

            // Client session related requests.
            Self::Authenticate(_) => 16,
            Self::CapLs(_) => 2,
            Self::CapList => 2,
            Self::CapReq(_) => 2,
            Self::CapEnd => 2,
            Self::Pass(_) => 2,
            Self::Ping(_) => 2,
            Self::Pong(_) => 2,
            Self::Quit(_) => 2,
            Self::User(_) => 2,

            // Client info related requests.
            Self::Away(_) => 8,
            Self::ModeUserGet(_) => 4,
            Self::ModeUserSet(_) => 7,
            Self::Nick(_) => 8,
            Self::SetName(_) => 8,

            // Channel management requests.
            Self::Invite(_) => 10,
            Self::Join(_) => 8,
            Self::Kick(_) => 6,
            Self::MessageAll(_) => 24,
            Self::MessageChannel(_) => 8,
            Self::MessageUser(_) => 8,
            Self::ModeChannelGet(_) => 4,
            Self::ModeChannelSet(_) => 7,
            Self::Part(_) => 6,
            Self::PartAll => 12,
        }
    }
}
