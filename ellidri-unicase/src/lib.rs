//! Wrapper around str that makes ASCII comparisons case-insensitive.
//!
//! Intended for use within a `HashMap`.  Actually used by ellidri's `State`.
//!
//! It's made for IRC.  It doesn't need to support Unicode case-folding.

#![warn(clippy::all, rust_2018_idioms)]
#![allow(clippy::filter_map, clippy::find_map, clippy::shadow_unrelated, clippy::use_self)]

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

#[repr(transparent)]
pub struct UniCase<S: ?Sized>(pub S);

impl<'a> From<&'a str> for &'a UniCase<str> {
    fn from(s: &'a str) -> &'a UniCase<str> {
        // Because of #[repr(transparent)],
        // Unicase<str> and str have the same memory representation
        // So the cast `as *const Unicase<str>` must work.
        unsafe { &*(s as *const str as *const UniCase<str>) }
    }
}

pub fn u(s: &str) -> &UniCase<str> {
    s.into()
}

impl<S> AsRef<str> for UniCase<S>
    where S: AsRef<str>,
{
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<S> Hash for UniCase<S>
    where S: AsRef<str> + ?Sized,
{
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.0.as_ref().bytes().map(|b| b.to_ascii_lowercase())
            .for_each(|b| hasher.write_u8(b));
    }
}

impl<S1> PartialEq for UniCase<S1>
    where S1: Borrow<str> + ?Sized,
{
    fn eq(&self, other: &UniCase<S1>) -> bool {
        self.0.borrow().eq_ignore_ascii_case(other.0.borrow())
    }
}

impl<S> Eq for UniCase<S>
    where S: Borrow<str> + ?Sized,
{}

impl Borrow<UniCase<str>> for UniCase<String> {
    fn borrow(&self) -> &UniCase<str> {
        self.0.as_str().into()
    }
}
