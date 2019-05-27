use std::iter;

// Don't forget to change CHANMODES in StateInner::send_welcome
pub const USER_MODES: &str = "aiorsw";
pub const SIMPLE_CHAN_MODES: &str = "aimnqst";

#[cfg(not(feature = "irdille"))]
pub const EXTENDED_CHAN_MODES: &str = "beIklov";
#[cfg(feature = "irdille")]
pub const EXTENDED_CHAN_MODES: &str = "beIklovP";

struct SimpleQuery<'a> {
    modes: &'a [u8],
    value: bool,
}

impl<'a> Iterator for SimpleQuery<'a> {
    type Item = (bool, u8);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.modes.is_empty() {
                return None;
            }
            match self.modes[0] {
                b'+' => { self.value = true; },
                b'-' => { self.value = false; },
                c => {
                    self.modes = &self.modes[1..];
                    return Some((self.value, c));
                },
            }
            self.modes = &self.modes[1..];
        }
    }
}

pub enum Error {
    UnknownMode(char),
    MissingModeParam,
}

pub type Result<T> = std::result::Result<T, Error>;

pub enum UserModeChange {
    Invisible(bool),
    Wallops(bool),
    ServerNotices(bool),
}

pub struct UserQuery<'a> {
    inner: SimpleQuery<'a>,
}

impl<'a> UserQuery<'a> {
    pub fn new(modes: &'a [u8]) -> UserQuery<'a> {
        UserQuery {
            inner: SimpleQuery {
                modes,
                value: true,
            },
        }
    }
}

impl<'a> Iterator for UserQuery<'a> {
    type Item = Result<UserModeChange>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(value, mode)| {
            match mode {
                b'i' => Ok(UserModeChange::Invisible(value)),
                b'w' => Ok(UserModeChange::Wallops(value)),
                b's' => Ok(UserModeChange::ServerNotices(value)),
                other => Err(Error::UnknownMode(other as char)),
            }
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ChannelModeChange<'a> {
    Anonymous(bool),
    InviteOnly(bool),
    Moderated(bool),
    NoPrivMsgFromOutside(bool),
    Quiet(bool),
    Secret(bool),
    TopicRestricted(bool),
    Key(bool, &'a str),
    UserLimit(Option<&'a str>),
    GetBans,
    GetExceptions,
    GetInvitations,
    ChangeBan(bool, &'a str),
    ChangeException(bool, &'a str),
    ChangeInvitation(bool, &'a str),
    ChangeOperator(bool, &'a str),
    ChangeVoice(bool, &'a str),

    #[cfg(feature = "irdille")]
    MsgModifier(Option<&'a str>),
}

impl<'a> ChannelModeChange<'a> {
    pub fn value(&self) -> bool {
        use ChannelModeChange::*;
        match self {
            Anonymous(v) |
            InviteOnly(v) |
            Moderated(v) |
            NoPrivMsgFromOutside(v) |
            Quiet(v) |
            Secret(v) |
            TopicRestricted(v) |
            Key(v, _) |
            ChangeBan(v, _) |
            ChangeException(v, _) |
            ChangeInvitation(v, _) |
            ChangeOperator(v, _) |
            ChangeVoice(v, _) => *v,
            UserLimit(l) => l.is_some(),

            #[cfg(feature = "irdille")]
            MsgModifier(l) => l.is_some(),

            _ => false,
        }
    }

    pub fn symbol(&self) -> Option<char> {
        use ChannelModeChange::*;
        match self {
            Anonymous(_) => Some('a'),
            InviteOnly(_) => Some('i'),
            Moderated(_) => Some('m'),
            NoPrivMsgFromOutside(_) => Some('n'),
            Quiet(_) => Some('q'),
            Secret(_) => Some('s'),
            TopicRestricted(_) => Some('t'),
            Key(_, _) => Some('k'),
            UserLimit(_) => Some('l'),
            ChangeBan(_, _) => Some('b'),
            ChangeException(_, _) => Some('e'),
            ChangeInvitation(_, _) => Some('I'),
            ChangeOperator(_, _) => Some('o'),
            ChangeVoice(_, _) => Some('v'),

            #[cfg(feature = "irdille")]
            MsgModifier(_) => Some('P'),

            _ => None,
        }
    }

    pub fn param(&self) -> Option<&'a str> {
        use ChannelModeChange::*;
        match self {
            Key(_, p) => Some(p),
            UserLimit(l) => *l,
            ChangeBan(_, p) => Some(p),
            ChangeException(_, p) => Some(p),
            ChangeInvitation(_, p) => Some(p),
            ChangeOperator(_, p) => Some(p),
            ChangeVoice(_, p) => Some(p),

            #[cfg(feature = "irdille")]
            MsgModifier(p) => *p,

            _ => None,
        }
    }
}

pub struct ChannelQuery<'a, I> {
    inner: SimpleQuery<'a>,
    params: I,
}

impl<'a, I> ChannelQuery<'a, I> {
    pub fn new(modes: &'a str, params: I) -> ChannelQuery<'a, I> {
        let modes = modes.as_bytes();
        ChannelQuery {
            inner: SimpleQuery {
                modes,
                value: true,
            },
            params,
        }
    }
}

impl<'a> ChannelQuery<'a, iter::Empty<&'a str>> {
    pub fn simple(modes: &'a str) -> Self {
        ChannelQuery::new(modes, iter::empty())
    }
}

impl<'a, I> Iterator for ChannelQuery<'a, I>
    where I: Iterator<Item=&'a str>
{
    type Item = Result<ChannelModeChange<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(value, mode)| {
            match mode {
                b'a' => Ok(ChannelModeChange::Anonymous(value)),
                b'i' => Ok(ChannelModeChange::InviteOnly(value)),
                b'm' => Ok(ChannelModeChange::Moderated(value)),
                b'n' => Ok(ChannelModeChange::NoPrivMsgFromOutside(value)),
                b'q' => Ok(ChannelModeChange::Quiet(value)),
                b's' => Ok(ChannelModeChange::Secret(value)),
                b't' => Ok(ChannelModeChange::TopicRestricted(value)),
                b'k' => if let Some(param) = self.params.next() {
                    Ok(ChannelModeChange::Key(value, param))
                } else {
                    Err(Error::MissingModeParam)
                },
                b'l' => if value {
                    if let Some(param) = self.params.next() {
                        Ok(ChannelModeChange::UserLimit(Some(param)))
                    } else {
                        Err(Error::MissingModeParam)
                    }
                } else {
                    Ok(ChannelModeChange::UserLimit(None))
                },
                b'b' => if let Some(param) = self.params.next() {
                    Ok(ChannelModeChange::ChangeBan(value, param))
                } else {
                    Ok(ChannelModeChange::GetBans)
                },
                b'e' => if let Some(param) = self.params.next() {
                    Ok(ChannelModeChange::ChangeException(value, param))
                } else {
                    Ok(ChannelModeChange::GetExceptions)
                },
                b'I' => if let Some(param) = self.params.next() {
                    Ok(ChannelModeChange::ChangeInvitation(value, param))
                } else {
                    Ok(ChannelModeChange::GetInvitations)
                },
                b'o' => if let Some(param) = self.params.next() {
                    Ok(ChannelModeChange::ChangeOperator(value, param))
                } else {
                    Err(Error::MissingModeParam)
                },
                b'v' => if let Some(param) = self.params.next() {
                    Ok(ChannelModeChange::ChangeVoice(value, param))
                } else {
                    Err(Error::MissingModeParam)
                },

                #[cfg(feature = "irdille")]
                b'P' => if value {
                    if let Some(param) = self.params.next() {
                        Ok(ChannelModeChange::MsgModifier(Some(param)))
                    } else {
                        Err(Error::MissingModeParam)
                    }
                } else {
                    Ok(ChannelModeChange::MsgModifier(None))
                },

                other => Err(Error::UnknownMode(other as char)),
            }
        })
    }
}

pub fn is_channel_mode_string(s: &str) -> bool {
    ChannelQuery::simple(s).all(|r| r.is_ok())
}
