//! Wrapper around str that makes ASCII comparisons case-insensitive.
//!
//! Intended for use within a `HashMap`.  Actually used by ellidri's `State`.
//!
//! It doesn't support Unicode case-folding for now.

#![warn(clippy::all, rust_2018_idioms)]
#![allow(clippy::filter_map, clippy::find_map, clippy::shadow_unrelated, clippy::use_self)]

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

/// Case-insensitive wrapper.
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

/// Converts a `&str` into a `&UniCase<str>`.
///
/// Shorthand for `<&Unicase<str>>::from`.
pub fn u(s: &str) -> &UniCase<str> {
    s.into()
}

impl<S> AsRef<str> for UniCase<S>
    where S: AsRef<str> + ?Sized,
{
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<S> Hash for UniCase<S>
    where S: AsRef<str> + ?Sized,
{
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        let bytes = self.0.as_ref().as_bytes();
        for byte in bytes {
            hasher.write_u8(byte.to_ascii_lowercase());
        }
    }
}

impl<S1, S2> PartialEq<UniCase<S2>> for UniCase<S1>
    where S1: AsRef<str> + ?Sized,
          S2: AsRef<str> + ?Sized,
{
    fn eq(&self, other: &UniCase<S2>) -> bool {
        self.0.as_ref().eq_ignore_ascii_case(other.0.as_ref())
    }
}

impl<S> Eq for UniCase<S>
    where S: AsRef<str> + ?Sized,
{}

impl Borrow<UniCase<str>> for UniCase<String> {
    fn borrow(&self) -> &UniCase<str> {
        self.0.as_str().into()
    }
}
