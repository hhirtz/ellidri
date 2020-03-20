//! Mode parsing and validation

use std::iter;

/// User modes supported by ellidri.  Advertised in welcome messages.
pub const USER_MODES: &str = "aiorsw";

/// Channel modes that have no parameters and are supported by ellidri.  Advertised in welcome
/// messages.
pub const SIMPLE_CHAN_MODES: &str = "imnst";

/// Channel modes that require a parameter and are supported by ellidri.  Advertised in welcome
/// messages.
pub const EXTENDED_CHAN_MODES: &str = "beIkl";

/// CHANMODES feature advertised in RPL_ISUPPORT.
pub const CHANMODES: &str = "CHANMODES=beI,k,l,imnpqst";

/// Iterator over the modes of a string.
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

/// *_query related errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// One of the modes in the query is unknown.
    UnknownMode(char),

    /// A mode is missing its required parameter.
    MissingModeParam,

    /// This mode is supported by ellidri, but cannot be setted with the MODE command.
    UnsettableMode
}

/// Alias to std's Result using this module's Error.
pub type Result<T> = std::result::Result<T, Error>;

/// Item of a user mode query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserModeChange {
    Invisible(bool),
}

impl UserModeChange {
    /// Whether this change is enabling or disabling a mode.
    pub fn value(self) -> bool {
        match self {
            Self::Invisible(v) => v,
        }
    }

    /// The letter of this mode change.
    pub fn symbol(self) -> char {
        match self {
            Self::Invisible(_) => 'i',
        }
    }
}

/// An iterator over the changes of a MODE query.
///
/// # Example
///
/// ```rust
/// # use ellidri::modes;
/// # use ellidri::modes::{Error, UserModeChange};
/// let mut query = modes::user_query("+ii-iXa");
///
/// assert_eq!(query.next(), Some(Ok(UserModeChange::Invisible(true))));
/// assert_eq!(query.next(), Some(Ok(UserModeChange::Invisible(true))));
/// assert_eq!(query.next(), Some(Ok(UserModeChange::Invisible(false))));
/// assert_eq!(query.next(), Some(Err(Error::UnknownMode('X'))));
/// assert_eq!(query.next(), Some(Err(Error::UnsettableMode)));
/// assert_eq!(query.next(), None);
/// ```
pub fn user_query(modes: &str) -> impl Iterator<Item=Result<UserModeChange>> + '_ {
    SimpleQuery::new(modes).map(|(value, mode)| {
        match mode {
            b'i' => Ok(UserModeChange::Invisible(value)),
            other if USER_MODES.contains(other as char) => Err(Error::UnsettableMode),
            other => Err(Error::UnknownMode(other as char)),
        }
    })
}

/// Item of a channel mode query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    ChangeHalfop(bool, &'a str),
    ChangeVoice(bool, &'a str),
}

impl ChannelModeChange<'_> {
    /// Whether this change is enabling or disabling a mode.
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
            ChangeHalfop(v, _) |
            ChangeVoice(v, _) => *v,
            UserLimit(l) => l.is_some(),
            _ => false,
        }
    }

    /// The letter of this mode change.
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
            ChangeHalfop(_, _) => Some('h'),
            ChangeVoice(_, _) => Some('v'),
            _ => None,
        }
    }

    /// The parameter of this mode change.
    pub fn param(&self) -> Option<&str> {
        use ChannelModeChange::*;
        match self {
            Key(_, p) | ChangeBan(_, p) | ChangeException(_, p) | ChangeInvitation(_, p)
                | ChangeOperator(_, p) | ChangeHalfop(_, p) | ChangeVoice(_, p) => Some(p),
            UserLimit(l) => *l,
            _ => None,
        }
    }
}

/// An iterator over the changes of a MODE query.
///
/// # Example
///
/// ```rust
/// # use ellidri::modes;
/// # use ellidri::modes::{ChannelModeChange, Error};
/// let mut query = modes::channel_query("-olX+kmv", vec!["admin", "secret_key"]);
///
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::ChangeOperator(false, "admin"))));
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::UserLimit(None))));
/// assert_eq!(query.next(), Some(Err(Error::UnknownMode('X'))));
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::Key(true, "secret_key"))));
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::Moderated(true))));
/// assert_eq!(query.next(), Some(Err(Error::MissingModeParam)));
/// assert_eq!(query.next(), None);
/// ```
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
            b'h' => if let Some(param) = params.next().filter(|p| !p.is_empty()) {
                Ok(ChannelModeChange::ChangeHalfop(value, param))
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

/// Same as `channel_query`, but with no mode parameters.
pub fn simple_channel_query(modes: &str) -> impl Iterator<Item=Result<ChannelModeChange<'_>>> {
    channel_query(modes, iter::empty())
}

/// Whether the given string is a valid channel MODE query.
///
/// **Note:** the string must not contain spaces nor mode params.
///
/// # Example
///
/// ```rust
/// # use ellidri::modes;
/// assert!(modes::is_channel_mode_string("+nt"));
/// assert!(!modes::is_channel_mode_string("+X"));
/// ```
pub fn is_channel_mode_string(s: &str) -> bool {
    simple_channel_query(s).all(|r| r.is_ok())
}
