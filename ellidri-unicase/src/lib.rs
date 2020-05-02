//! Wrapper around str that makes comparisons case-insensitive.
//!
//! Intended for use within a `HashMap`.  Actually used by ellidri's `State`.  It doesn't support
//! Unicode case-folding for now.
//!
//! The wrapper is named `UniCase`.  It implements traits so that `&UniCase<str>` behaves like
//! `&str`, and `UniCase<String>` behaves like `String`, except for the comparisons of course,
//! which are case-insensitive.
//!
//! "Case-insensitivity" is defined by the `CaseMapping` trait.  This trait defines how characters
//! and bytes should match.  Currently, the following case mappings are available:
//!
//! - `Ascii` (default): matches ascii lower case letters with their ascii upper case counterparts,
//! - `Rfc1459`: same as `Ascii`, but also matches `{}|^` with `[]\~`.
//! - `Rfc1459Strict`: same as `Ascii`, but also matches `{}|` with `[]\`.
//!
//! Currently, `rfc7613` is not implemented.
//!
//! # Usage
//!
//! ```rust
//! use ellidri_unicase::{u, UniCase};
//! use std::collections::HashSet;
//!
//! let mut channels = HashSet::new();
//! channels.insert(UniCase::new("#Games".to_owned()));
//!
//! assert!(channels.contains(u("#gameS")));
//! assert!(!channels.contains(u("#Gaming")));
//!
//! assert_eq!(u("hello!"), u("HELLO!"));
//! ```

#![warn(clippy::all, rust_2018_idioms)]
#![allow(
    clippy::filter_map,
    clippy::find_map,
    clippy::shadow_unrelated,
    clippy::use_self
)]

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// Definition of case mappings.
pub trait CaseMapping {
    /// For the given byte, returns an arbitrary byte that will be the same for all bytes that
    /// match the given byte.
    ///
    /// Easy, right?
    ///
    /// It means that, for all bytes that should match, this function returns the same byte.  If
    /// two bytes don't match, this function will return two different bytes.  In practice, it
    /// converts bytes to their lowercase equivalent.
    ///
    /// # Example
    ///
    /// With the Ascii case mapping,
    ///
    /// ```rust
    /// # use ellidri_unicase::{Ascii, CaseMapping};
    /// assert!(Ascii::canonical_byte(b'a') == Ascii::canonical_byte(b'A'));
    /// assert!(Ascii::canonical_byte(b'a') != Ascii::canonical_byte(b'B'));
    /// ```
    fn canonical_byte(b: u8) -> u8;
}

/// ASCII case mapping.
#[derive(Debug)]
pub struct Ascii;

impl CaseMapping for Ascii {
    fn canonical_byte(b: u8) -> u8 {
        b.to_ascii_lowercase()
    }
}

/// rfc1459-strict case mapping.
pub struct Rfc1459Strict;

impl CaseMapping for Rfc1459Strict {
    fn canonical_byte(b: u8) -> u8 {
        match b {
            b'[' => b'{',
            b']' => b'}',
            b'\\' => b'\\',
            b => Ascii::canonical_byte(b),
        }
    }
}

/// rfc1459 case mapping.
pub struct Rfc1459;

impl CaseMapping for Rfc1459 {
    fn canonical_byte(b: u8) -> u8 {
        match b {
            b'~' => b'^',
            b => Rfc1459Strict::canonical_byte(b),
        }
    }
}

/// Case-insensitive wrapper around strings.
///
/// See the crate-level documentation for more information and usage examples.
#[repr(transparent)]
pub struct UniCase<S: ?Sized, C: CaseMapping = Ascii>(PhantomData<C>, S);

impl<S, C> UniCase<S, C>
where
    C: CaseMapping,
{
    /// Wraps the given value into `UniCase`, and "make it" case-insensitive.
    ///
    /// Use this to make `UniCase<String>` for example.  If you need to wrap a `&str`, you might
    /// want to use `u` instead, or `&UniCase<str>::from`.
    pub fn new(s: S) -> Self {
        UniCase(PhantomData, s)
    }

    /// Consume the case-insensitive wrapper and returns the underlying value.
    pub fn into_inner(self) -> S {
        self.1
    }
}

impl<S, C> UniCase<S, C>
where
    S: ?Sized,
    C: CaseMapping,
{
    /// Returns a reference to the underlying value.
    pub fn get(&self) -> &S {
        &self.1
    }
}

impl<'a, C> From<&'a str> for &'a UniCase<str, C>
where
    C: CaseMapping,
{
    fn from(s: &'a str) -> &'a UniCase<str, C> {
        // Because of #[repr(transparent)],
        // Unicase<str> and str have the same memory representation
        // So the cast `as *const Unicase<str>` must work.
        unsafe { &*(s as *const str as *const UniCase<str, C>) }
    }
}

/// Converts a `&str` into a `&UniCase<str, Ascii>`.
///
/// Shorthand for `<&Unicase<str, Ascii>>::from`.
pub fn u(s: &str) -> &UniCase<str> {
    s.into()
}

impl<S, C> AsRef<UniCase<str, C>> for UniCase<S, C>
where
    S: AsRef<str> + ?Sized,
    C: CaseMapping,
{
    fn as_ref(&self) -> &UniCase<str, C> {
        self.1.as_ref().into()
    }
}

impl<S, C> Borrow<UniCase<str, C>> for UniCase<S, C>
where
    S: Borrow<str>,
    C: CaseMapping,
{
    fn borrow(&self) -> &UniCase<str, C> {
        self.1.borrow().into()
    }
}

impl<S, C> Hash for UniCase<S, C>
where
    S: AsRef<str> + ?Sized,
    C: CaseMapping,
{
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        let bytes = self.1.as_ref().as_bytes();
        for &byte in bytes {
            hasher.write_u8(C::canonical_byte(byte));
        }
    }
}

impl<S1, S2, C> PartialEq<UniCase<S2, C>> for UniCase<S1, C>
where
    S1: AsRef<str> + ?Sized,
    S2: AsRef<str> + ?Sized,
    C: CaseMapping,
{
    fn eq(&self, other: &UniCase<S2, C>) -> bool {
        let me = self.1.as_ref().as_bytes();
        let you = other.1.as_ref().as_bytes();
        me.len() == you.len()
            && me
                .iter()
                .zip(you)
                .all(|(&a, &b)| C::canonical_byte(a) == C::canonical_byte(b))
    }
}

impl<S, C> Eq for UniCase<S, C>
where
    S: AsRef<str> + ?Sized,
    C: CaseMapping,
{
}

impl<S> fmt::Debug for UniCase<S, Ascii>
where
    S: fmt::Debug + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniCase<Ascii>({:?})", &self.1)
    }
}

impl<S> fmt::Debug for UniCase<S, Rfc1459>
where
    S: fmt::Debug + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniCase<Rfc1459>({:?})", &self.1)
    }
}

impl<S> fmt::Debug for UniCase<S, Rfc1459Strict>
where
    S: fmt::Debug + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniCase<Rfc1459Strict>({:?})", &self.1)
    }
}
