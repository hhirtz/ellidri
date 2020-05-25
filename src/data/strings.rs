use super::Error;
use crate::util;
use ellidri_unicase::{u, UniCase};
use std::convert::TryFrom;
use std::marker::PhantomData;

fn is_namespace(c: char) -> bool {
    c == '#' || c == '&'
}

fn is_wildcard(c: char) -> bool {
    c == '?' || c == '*'
}

fn is_prefix(c: char) -> bool {
    c == '~' || c == '&' || c == '@' || c == '%' || c == '+'
}

fn is_valid(c: char) -> bool {
    c != ' ' && c != ',' && c != ':'
}

fn is_valid_mask(s: &str) -> bool {
    s.chars().next().map_or(false, |first| {
        is_valid(first) && s.chars().skip(1).all(|c| is_valid(c) && !is_namespace(c))
    })
}

fn is_valid_name(s: &str) -> bool {
    s.chars().next().map_or(false, |first| {
        !is_prefix(first)
            && s.chars()
                .all(|c| is_valid(c) && !is_namespace(c) && !is_wildcard(c))
    })
}

fn is_valid_channel_name(s: &str) -> bool {
    s.chars()
        .next()
        .map_or(false, |first| is_namespace(first) && is_valid_name(&s[1..]))
}

fn is_restricted_nickname(s: &str) -> bool {
    s.len() < 9 && s.ends_with("Serv")
}

#[derive(Clone, Copy, Debug)]
pub struct Mask<'a>(&'a str);

impl Mask<'_> {
    pub fn get(&self) -> &str {
        self.0
    }

    pub fn u(&self) -> &UniCase<str> {
        u(self.0)
    }

    pub fn is_channel(&self) -> bool {
        let first = self.0.chars().next().unwrap();
        is_namespace(first)
    }

    pub fn is_match(&self, s: &str) -> bool {
        util::match_mask(self.0, s)
    }
}

impl<'a> TryFrom<&'a str> for Mask<'a> {
    type Error = Error<'a>;

    fn try_from(val: &'a str) -> Result<Self, Self::Error> {
        if is_valid_mask(val) {
            Ok(Self(val))
        } else {
            Err(Error::NoSuchNick(val))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Nickname<'a>(&'a str);

impl Nickname<'_> {
    pub fn get(&self) -> &str {
        self.0
    }

    pub fn u(&self) -> &UniCase<str> {
        u(self.0)
    }
}

impl<'a> TryFrom<&'a str> for Nickname<'a> {
    type Error = Error<'a>;

    fn try_from(val: &'a str) -> Result<Self, Self::Error> {
        if is_valid_name(val) && !is_restricted_nickname(val) {
            Ok(Self(val))
        } else {
            Err(Error::NoSuchNick(val))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ChannelName<'a>(&'a str);

impl ChannelName<'_> {
    pub fn get(&self) -> &str {
        self.0
    }

    pub fn u(&self) -> &UniCase<str> {
        u(self.0)
    }
}

impl<'a> TryFrom<&'a str> for ChannelName<'a> {
    type Error = Error<'a>;

    fn try_from(val: &'a str) -> Result<Self, Self::Error> {
        if is_valid_channel_name(val) {
            Ok(Self(val))
        } else {
            Err(Error::NoSuchChannel(val))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Key<'a>(&'a str);

impl Key<'_> {
    pub fn get(&self) -> &str {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for Key<'a> {
    type Error = ();

    fn try_from(val: &'a str) -> Result<Self, Self::Error> {
        if is_valid_name(val) {
            Ok(Self(val))
        } else {
            Err(())
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HostName<'a>(&'a str);

impl HostName<'_> {
    pub fn get(&self) -> &str {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for HostName<'a> {
    type Error = ();

    fn try_from(val: &'a str) -> Result<Self, Self::Error> {
        if is_valid_name(val) {
            Ok(Self(val))
        } else {
            Err(())
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct List<'a, T>(&'a str, char, PhantomData<T>);

impl<'a, T> List<'a, T> {
    pub fn new(raw: &'a str, sep: char) -> List<'a, T> {
        List(raw, sep, PhantomData)
    }
}

impl<'a, T> List<'a, T>
where
    T: TryFrom<&'a str> + 'a,
{
    pub fn iter(&self) -> impl Iterator<Item = T> + 'a {
        self.0.split(self.1).flat_map(T::try_from)
    }
}

#[derive(Clone, Debug)]
pub struct JoinList<'a>(List<'a, ChannelName<'a>>, List<'a, Key<'a>>);

impl<'a> JoinList<'a> {
    pub fn new(names: &'a str, keys: &'a str) -> Self {
        let names = List::new(names, ',');
        let keys = List::new(keys, ',');
        Self(names, keys)
    }

    pub fn iter(&self) -> impl Iterator<Item = (ChannelName<'a>, Option<Key<'a>>)> {
        let keys = self
            .1
            .iter()
            .map(Option::Some)
            .chain(std::iter::repeat(Option::None));
        self.0.iter().zip(keys)
    }
}
