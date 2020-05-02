//! Mode parsing and validation

use std::str;

/// User modes supported by ellidri.  Advertised in welcome messages.
pub const USER_MODES: &str = "aiorsw";

/// Channel modes that have no parameters and are supported by ellidri.  Advertised in welcome
/// messages.
pub const SIMPLE_CHAN_MODES: &str = "imnst";

/// Channel modes that require a parameter and are supported by ellidri.  Advertised in welcome
/// messages.
pub const EXTENDED_CHAN_MODES: &str = "beIkl";

/// CHANMODES feature advertised in RPL_ISUPPORT.
pub const CHANMODES: &str = "CHANMODES=beI,k,l,imnst";

/// Iterator over the modes of a string.
struct SimpleQuery<'a> {
    modes: str::Chars<'a>,
    value: bool,
}

impl<'a> SimpleQuery<'a> {
    pub fn new(modes: &'a str) -> Self {
        Self {
            modes: modes.chars(),
            value: true,
        }
    }
}

impl Iterator for SimpleQuery<'_> {
    type Item = (bool, char);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let c = if let Some(c) = self.modes.next() {
                c
            } else {
                return None;
            };
            match c {
                '+' => {
                    self.value = true;
                }
                '-' => {
                    self.value = false;
                }
                c => {
                    return Some((self.value, c));
                }
            }
        }
    }
}

/// *_query related errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// One of the modes in the query is unknown.
    Unknown(char, bool),

    /// A mode is missing its required parameter.
    MissingParam(char, bool),

    /// This mode is supported by ellidri, but cannot be changed with the MODE command.
    Unchangeable(char, bool),
}

/// Alias to std's Result using this module's Error.
pub type Result<T> = std::result::Result<T, Error>;

/// Item of a user mode query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserChange {
    Invisible(bool),
    DeOperator,
}

impl UserChange {
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
/// # use ellidri_tokens::mode::{self, Error, UserChange};
/// let mut query = mode::user_query("+io-oXa");
///
/// assert_eq!(query.next(), Some(Ok(UserChange::Invisible(true))));
/// assert_eq!(query.next(), Some(Err(Error::Unchangeable('o', true))));
/// assert_eq!(query.next(), Some(Ok(UserChange::DeOperator)));
/// assert_eq!(query.next(), Some(Err(Error::Unknown('X', false))));
/// assert_eq!(query.next(), Some(Err(Error::Unchangeable('a', false))));
/// assert_eq!(query.next(), None);
/// ```
pub fn user_query(modes: &str) -> impl Iterator<Item = Result<UserChange>> + '_ {
    SimpleQuery::new(modes).map(|(value, mode)| match mode {
        'i' => Ok(UserChange::Invisible(value)),
        'o' if !value => Ok(UserChange::DeOperator),
        other if USER_MODES.contains(other) => Err(Error::Unchangeable(other, value)),
        other => Err(Error::Unknown(other, value)),
    })
}

/// Item of a channel mode query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelChange<'a> {
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

impl ChannelChange<'_> {
    /// Whether this change is enabling or disabling a mode.
    pub fn value(&self) -> bool {
        use ChannelChange::*;
        match self {
            InviteOnly(v)
            | Moderated(v)
            | NoPrivMsgFromOutside(v)
            | Secret(v)
            | TopicRestricted(v)
            | Key(v, _)
            | ChangeBan(v, _)
            | ChangeException(v, _)
            | ChangeInvitation(v, _)
            | ChangeOperator(v, _)
            | ChangeHalfop(v, _)
            | ChangeVoice(v, _) => *v,
            UserLimit(l) => l.is_some(),
            _ => false,
        }
    }

    /// The letter of this mode change.
    pub fn symbol(&self) -> char {
        use ChannelChange::*;
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
        use ChannelChange::*;
        match self {
            Key(_, p)
            | ChangeBan(_, p)
            | ChangeException(_, p)
            | ChangeInvitation(_, p)
            | ChangeOperator(_, p)
            | ChangeHalfop(_, p)
            | ChangeVoice(_, p) => Some(p),
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
/// # use ellidri_tokens::mode::{self, Error, ChannelChange};
/// let mut query = mode::channel_query("-olX+kmv", &["admin", "secret_key"]);
///
/// assert_eq!(query.next(), Some(Ok(ChannelChange::ChangeOperator(false, "admin"))));
/// assert_eq!(query.next(), Some(Ok(ChannelChange::UserLimit(None))));
/// assert_eq!(query.next(), Some(Err(Error::Unknown('X', false))));
/// assert_eq!(query.next(), Some(Ok(ChannelChange::Key(true, "secret_key"))));
/// assert_eq!(query.next(), Some(Ok(ChannelChange::Moderated(true))));
/// assert_eq!(query.next(), Some(Err(Error::MissingParam('v', true))));
/// assert_eq!(query.next(), None);
/// ```
pub fn channel_query<'a, I, S>(
    modes: &'a str,
    params: I,
) -> impl Iterator<Item = Result<ChannelChange<'a>>>
where
    I: IntoIterator<Item = &'a S> + 'a,
    S: AsRef<str> + 'a,
{
    let mut params = params
        .into_iter()
        .map(|p| p.as_ref())
        .filter(|p| !p.is_empty());
    SimpleQuery::new(modes).map(move |(value, mode)| {
        use ChannelChange::*;
        match mode {
            'i' => Ok(InviteOnly(value)),
            'm' => Ok(Moderated(value)),
            'n' => Ok(NoPrivMsgFromOutside(value)),
            's' => Ok(Secret(value)),
            't' => Ok(TopicRestricted(value)),
            'k' => {
                if let Some(param) = params.next() {
                    Ok(Key(value, param))
                } else if !value {
                    // Accept "MODE -k" since freenode does it this way
                    Ok(Key(false, "*"))
                } else {
                    Err(Error::MissingParam('k', value))
                }
            }
            'l' => {
                if value {
                    if let Some(param) = params.next() {
                        Ok(UserLimit(Some(param)))
                    } else {
                        Err(Error::MissingParam('l', value))
                    }
                } else {
                    Ok(UserLimit(None))
                }
            }
            'b' => {
                if let Some(param) = params.next() {
                    Ok(ChangeBan(value, param))
                } else {
                    Ok(GetBans)
                }
            }
            'e' => {
                if let Some(param) = params.next() {
                    Ok(ChangeException(value, param))
                } else {
                    Ok(GetExceptions)
                }
            }
            'I' => {
                if let Some(param) = params.next() {
                    Ok(ChangeInvitation(value, param))
                } else {
                    Ok(GetInvitations)
                }
            }
            'o' => {
                if let Some(param) = params.next() {
                    Ok(ChangeOperator(value, param))
                } else {
                    Err(Error::MissingParam('o', value))
                }
            }
            'h' => {
                if let Some(param) = params.next() {
                    Ok(ChangeHalfop(value, param))
                } else {
                    Err(Error::MissingParam('h', value))
                }
            }
            'v' => {
                if let Some(param) = params.next() {
                    Ok(ChangeVoice(value, param))
                } else {
                    Err(Error::MissingParam('v', value))
                }
            }
            other => Err(Error::Unknown(other, value)),
        }
    })
}

/// Same as `channel_query`, but with no mode parameters.
pub fn simple_channel_query(modes: &str) -> impl Iterator<Item = Result<ChannelChange<'_>>> {
    channel_query::<_, String>(modes, &[])
}

/// Whether the given string is a valid channel MODE query.
///
/// **Note:** the string must not contain spaces nor mode params.
///
/// # Example
///
/// ```rust
/// # use ellidri_tokens::mode;
/// assert!(mode::is_channel_mode_string("+nt"));
/// assert!(!mode::is_channel_mode_string("+X"));
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
        assert_eq!(q.next(), Some((true, 'a')));
        assert_eq!(q.next(), Some((true, 'b')));
        assert_eq!(q.next(), Some((true, 'C')));
        assert_eq!(q.next(), Some((true, 'D')));
        assert_eq!(q.next(), Some((true, 'E')));
        assert_eq!(q.next(), Some((false, 'f')));
        assert_eq!(q.next(), Some((false, 'g')));
        assert_eq!(q.next(), Some((false, 'h')));
        assert_eq!(q.next(), None);

        let mut q = SimpleQuery::new("a");
        assert_eq!(q.next(), Some((true, 'a')));
        assert_eq!(q.next(), None);

        let mut q = SimpleQuery::new("");
        assert_eq!(q.next(), None);

        let mut q = SimpleQuery::new(" ");
        assert_eq!(q.next(), Some((true, ' ')));
        assert_eq!(q.next(), None);
    }

    // Taken from oragono <3
    #[test]
    fn test_chanmode_key() {
        let mut q = channel_query::<_, String>("+k", &[]);
        assert_eq!(q.next(), Some(Err(Error::MissingParam('k', true))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+k", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(true, "beer"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query::<_, String>("-k", &[]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(false, "*"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-k", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(false, "beer"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+kb", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(true, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelChange::GetBans)));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-kb", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelChange::GetBans)));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+bk", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::ChangeBan(true, "beer"))));
        assert_eq!(q.next(), Some(Err(Error::MissingParam('k', true))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-bk", &["beer"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::ChangeBan(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(false, "*"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+kb", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(true, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelChange::ChangeBan(true, "wine"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-kb", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelChange::ChangeBan(false, "wine"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("+bk", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::ChangeBan(true, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(true, "wine"))));
        assert_eq!(q.next(), None);

        let mut q = channel_query("-bk", &["beer", "wine"]);
        assert_eq!(q.next(), Some(Ok(ChannelChange::ChangeBan(false, "beer"))));
        assert_eq!(q.next(), Some(Ok(ChannelChange::Key(false, "wine"))));
        assert_eq!(q.next(), None);
    }
} // mod tests
