//! Mode parsing and validation

use std::borrow::Borrow;

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
            let (&c, rest) = if let Some(it) = self.modes.split_first() {
                it
            } else {
                return None;
            };
            self.modes = rest;
            match c {
                b'+' => { self.value = true; },
                b'-' => { self.value = false; },
                c => {
                    return Some((self.value, c));
                },
            }
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

    /// This mode is supported by ellidri, but cannot be changed with the MODE command.
    UnchangeableMode
}

/// Alias to std's Result using this module's Error.
pub type Result<T> = std::result::Result<T, Error>;

/// Item of a user mode query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserModeChange {
    Invisible(bool),
    DeOperator,
}

impl UserModeChange {
    /// Whether this change is enabling or disabling a mode.
    pub fn value(self) -> bool {
        match self {
            Self::Invisible(v) => v,
            Self::DeOperator => false,
        }
    }

    /// The letter of this mode change.
    pub fn symbol(self) -> char {
        match self {
            Self::Invisible(_) => 'i',
            Self::DeOperator => 'o',
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
/// let mut query = modes::user_query("+io-oXa");
///
/// assert_eq!(query.next(), Some(Ok(UserModeChange::Invisible(true))));
/// assert_eq!(query.next(), Some(Ok(Error::UnchangeableMode)));
/// assert_eq!(query.next(), Some(Ok(UserModeChange::Deoperator)));
/// assert_eq!(query.next(), Some(Err(Error::UnknownMode('X'))));
/// assert_eq!(query.next(), Some(Err(Error::UnchangeableMode)));
/// assert_eq!(query.next(), None);
/// ```
pub fn user_query(modes: &str) -> impl Iterator<Item=Result<UserModeChange>> + '_ {
    SimpleQuery::new(modes).map(|(value, mode)| {
        match mode {
            b'i' => Ok(UserModeChange::Invisible(value)),
            b'o' if !value => Ok(UserModeChange::DeOperator),
            other if USER_MODES.contains(other as char) => Err(Error::UnchangeableMode),
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
    pub fn symbol(&self) -> char {
        use ChannelModeChange::*;
        match self {
            InviteOnly(_) => 'i',
            Moderated(_) => 'm',
            NoPrivMsgFromOutside(_) => 'n',
            Secret(_) => 's',
            TopicRestricted(_) => 't',
            Key(_, _) => 'k',
            UserLimit(_) => 'l',
            ChangeBan(_, _) | GetBans => 'b',
            ChangeException(_, _) | GetExceptions => 'e',
            ChangeInvitation(_, _) | GetInvitations => 'I',
            ChangeOperator(_, _) => 'o',
            ChangeHalfop(_, _) => 'h',
            ChangeVoice(_, _) => 'v',
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
/// let mut query = modes::channel_query("-olX+kmv", &["admin", "secret_key"]);
///
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::ChangeOperator(false, "admin"))));
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::UserLimit(None))));
/// assert_eq!(query.next(), Some(Err(Error::UnknownMode('X'))));
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::Key(true, "secret_key"))));
/// assert_eq!(query.next(), Some(Ok(ChannelModeChange::Moderated(true))));
/// assert_eq!(query.next(), Some(Err(Error::MissingModeParam)));
/// assert_eq!(query.next(), None);
/// ```
pub fn channel_query<'a, I, S>(modes: &'a str, params: I)
    -> impl Iterator<Item=Result<ChannelModeChange<'a>>>
where
    I: IntoIterator<Item=&'a S> + 'a,
    S: Borrow<str> + 'a,
{
    let mut params = params.into_iter().map(|p| p.borrow()).filter(|p| !p.is_empty());
    SimpleQuery::new(modes).map(move |(value, mode)| {
        match mode {
            b'i' => Ok(ChannelModeChange::InviteOnly(value)),
            b'm' => Ok(ChannelModeChange::Moderated(value)),
            b'n' => Ok(ChannelModeChange::NoPrivMsgFromOutside(value)),
            b's' => Ok(ChannelModeChange::Secret(value)),
            b't' => Ok(ChannelModeChange::TopicRestricted(value)),
            b'k' => if let Some(param) = params.next() {
                Ok(ChannelModeChange::Key(value, param))
            } else if !value {
                // Accept "MODE -k" since freenode does it this way
                Ok(ChannelModeChange::Key(false, "*"))
            } else {
                Err(Error::MissingModeParam)
            },
            b'l' => if value {
                if let Some(param) = params.next() {
                    Ok(ChannelModeChange::UserLimit(Some(param)))
                } else {
                    Err(Error::MissingModeParam)
                }
            } else {
                Ok(ChannelModeChange::UserLimit(None))
            },
            b'b' => if let Some(param) = params.next() {
                Ok(ChannelModeChange::ChangeBan(value, param))
            } else {
                Ok(ChannelModeChange::GetBans)
            },
            b'e' => if let Some(param) = params.next() {
                Ok(ChannelModeChange::ChangeException(value, param))
            } else {
                Ok(ChannelModeChange::GetExceptions)
            },
            b'I' => if let Some(param) = params.next() {
                Ok(ChannelModeChange::ChangeInvitation(value, param))
            } else {
                Ok(ChannelModeChange::GetInvitations)
            },
            b'o' => if let Some(param) = params.next() {
                Ok(ChannelModeChange::ChangeOperator(value, param))
            } else {
                Err(Error::MissingModeParam)
            },
            b'h' => if let Some(param) = params.next() {
                Ok(ChannelModeChange::ChangeHalfop(value, param))
            } else {
                Err(Error::MissingModeParam)
            },
            b'v' => if let Some(param) = params.next() {
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
    channel_query::<_, String>(modes, &[])
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

#[allow(clippy::cognitive_complexity)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_query() {
        let mut q = SimpleQuery::new("+ab+C++D+-+E--fg+-h");
        assert_eq!(q.next(), Some((true, b'a')));
        assert_eq!(q.next(), Some((true, b'b')));
        assert_eq!(q.next(), Some((true, b'C')));
        assert_eq!(q.next(), Some((true, b'D')));
        assert_eq!(q.next(), Some((true, b'E')));
        assert_eq!(q.next(), Some((false, b'f')));
        assert_eq!(q.next(), Some((false, b'g')));
        assert_eq!(q.next(), Some((false, b'h')));
        assert_eq!(q.next(), None);

        let mut q = SimpleQuery::new("a");
        assert_eq!(q.next(), Some((true, b'a')));
        assert_eq!(q.next(), None);

        let mut q = SimpleQuery::new("");
        assert_eq!(q.next(), None);

        let mut q = SimpleQuery::new(" ");
        assert_eq!(q.next(), Some((true, b' ')));
        assert_eq!(q.next(), None);
    }

    // Taken from oragono <3
    #[test]
    fn test_chanmode_key() {
        let mut q = channel_query::<_, String>("+k", &[]);
        assert_eq!(q.next(), Some(Err(Error::MissingModeParam)));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+k", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(true, "beer"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query::<_, String>("-k", &[]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(false, "*"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-k", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(false, "beer"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+kb", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(true, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::GetBans)));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-kb", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::GetBans)));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+bk", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::ChangeBan(true, "beer"))));
        assert_eq!(q.next(), Some(Err(Error::MissingModeParam)));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-bk", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::ChangeBan(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(false, "*"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+kb", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(true, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::ChangeBan(true, "wine"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-kb", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::ChangeBan(false, "wine"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+bk", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::ChangeBan(true, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(true, "wine"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-bk", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::ChangeBan(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelModeChange::Key(false, "wine"))));
        assert_eq!(q.next(), None);
    }
}  // mod tests
