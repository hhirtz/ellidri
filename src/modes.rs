use std::iter;

pub const USER_MODES: &str = "aiorsw";
pub const SIMPLE_CHAN_MODES: &str = "imnst";
pub const EXTENDED_CHAN_MODES: &str = "beIklov";
pub const CHANMODES: &str = "CHANMODES=beI,k,l,aimnpqst";

struct SimpleQuery<'a> {
    modes: &'a [u8],
    value: bool,
}

impl<'a> SimpleQuery<'a> {
    pub fn new(modes: &'a str) -> Self {
        Self {
            modes: modes.as_bytes(),
            value: true,
        }
    }
}

impl Iterator for SimpleQuery<'_> {
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
    UnsettableMode
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug)]
pub enum UserModeChange {
    Invisible(bool),
}

impl UserModeChange {
    pub fn value(self) -> bool {
        match self {
            Self::Invisible(v) => v,
        }
    }

    pub fn symbol(self) -> char {
        match self {
            Self::Invisible(_) => 'i',
        }
    }
}

pub fn user_query(modes: &str) -> impl Iterator<Item=Result<UserModeChange>> + '_ {
    SimpleQuery::new(modes).map(|(value, mode)| {
        match mode {
            b'i' => Ok(UserModeChange::Invisible(value)),
            other if USER_MODES.contains(other as char) => Err(Error::UnsettableMode),
            other => Err(Error::UnknownMode(other as char)),
        }
    })
}

#[derive(Clone, Copy, Debug)]
pub enum ChannelModeChange<'a> {
    InviteOnly(bool),
    Moderated(bool),
    NoPrivMsgFromOutside(bool),
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
}

impl<'a> ChannelModeChange<'a> {
    pub fn value(&self) -> bool {
        use ChannelModeChange::*;
        match self {
            InviteOnly(v) |
            Moderated(v) |
            NoPrivMsgFromOutside(v) |
            Secret(v) |
            TopicRestricted(v) |
            Key(v, _) |
            ChangeBan(v, _) |
            ChangeException(v, _) |
            ChangeInvitation(v, _) |
            ChangeOperator(v, _) |
            ChangeVoice(v, _) => *v,
            UserLimit(l) => l.is_some(),
            _ => false,
        }
    }

    pub fn symbol(&self) -> Option<char> {
        use ChannelModeChange::*;
        match self {
            InviteOnly(_) => Some('i'),
            Moderated(_) => Some('m'),
            NoPrivMsgFromOutside(_) => Some('n'),
            Secret(_) => Some('s'),
            TopicRestricted(_) => Some('t'),
            Key(_, _) => Some('k'),
            UserLimit(_) => Some('l'),
            ChangeBan(_, _) => Some('b'),
            ChangeException(_, _) => Some('e'),
            ChangeInvitation(_, _) => Some('I'),
            ChangeOperator(_, _) => Some('o'),
            ChangeVoice(_, _) => Some('v'),
            _ => None,
        }
    }

    pub fn param(&self) -> Option<&'a str> {
        use ChannelModeChange::*;
        match self {
            Key(_, p) | ChangeBan(_, p) | ChangeException(_, p) | ChangeInvitation(_, p)
                | ChangeOperator(_, p) | ChangeVoice(_, p) => Some(p),
            UserLimit(l) => *l,
            _ => None,
        }
    }
}

pub fn channel_query<'a, I>(modes: &'a str, params: I)
    -> impl Iterator<Item=Result<ChannelModeChange<'a>>>
where
    I: IntoIterator<Item=&'a str> + 'a
{
    let mut params = params.into_iter();
    SimpleQuery::new(modes).map(move |(value, mode)| {
        match mode {
            b'i' => Ok(ChannelModeChange::InviteOnly(value)),
            b'm' => Ok(ChannelModeChange::Moderated(value)),
            b'n' => Ok(ChannelModeChange::NoPrivMsgFromOutside(value)),
            b's' => Ok(ChannelModeChange::Secret(value)),
            b't' => Ok(ChannelModeChange::TopicRestricted(value)),
            b'k' => if let Some(param) = params.next() {
                Ok(ChannelModeChange::Key(value, param))
            } else {
                Err(Error::MissingModeParam)
            },
            b'l' => if value {
                if let Some(param) = params.next().filter(|p| !p.is_empty()) {
                    Ok(ChannelModeChange::UserLimit(Some(param)))
                } else {
                    Err(Error::MissingModeParam)
                }
            } else {
                Ok(ChannelModeChange::UserLimit(None))
            },
            b'b' => if let Some(param) = params.next().filter(|p| !p.is_empty()) {
                Ok(ChannelModeChange::ChangeBan(value, param))
            } else {
                Ok(ChannelModeChange::GetBans)
            },
            b'e' => if let Some(param) = params.next().filter(|p| !p.is_empty()) {
                Ok(ChannelModeChange::ChangeException(value, param))
            } else {
                Ok(ChannelModeChange::GetExceptions)
            },
            b'I' => if let Some(param) = params.next().filter(|p| !p.is_empty()) {
                Ok(ChannelModeChange::ChangeInvitation(value, param))
            } else {
                Ok(ChannelModeChange::GetInvitations)
            },
            b'o' => if let Some(param) = params.next().filter(|p| !p.is_empty()) {
                Ok(ChannelModeChange::ChangeOperator(value, param))
            } else {
                Err(Error::MissingModeParam)
            },
            b'v' => if let Some(param) = params.next().filter(|p| !p.is_empty()) {
                Ok(ChannelModeChange::ChangeVoice(value, param))
            } else {
                Err(Error::MissingModeParam)
            },
            other => Err(Error::UnknownMode(other as char)),
        }
    })
}

pub fn simple_channel_query(modes: &str) -> impl Iterator<Item=Result<ChannelModeChange<'_>>> {
    channel_query(modes, iter::empty())
}

pub fn is_channel_mode_string(s: &str) -> bool {
    simple_channel_query(s).all(|r| r.is_ok())
}

pub fn needs_chanop(modes: &str) -> bool {
    simple_channel_query(modes).any(|mode| match mode {
        Ok(ChannelModeChange::GetBans) | Ok(ChannelModeChange::GetExceptions)
            | Ok(ChannelModeChange::GetInvitations) => false,
        _ => true,
    })
}
