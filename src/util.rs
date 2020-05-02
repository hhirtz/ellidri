use ellidri_unicase::u;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use regex as re;
use std::cell::RefCell;
use std::{iter, time};

thread_local! {
    static RNG: RefCell<ChaChaRng> = RefCell::new(ChaChaRng::from_entropy());
    static REGEX: RefCell<String> = RefCell::new(String::new());
}

const REGEX_SIZE: usize = 4096;

fn build_regexset(mut b: re::RegexSetBuilder) -> re::RegexSet {
    b.case_insensitive(true)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_SIZE)
        .build()
        .unwrap()
}

fn build_regex(mut b: re::RegexBuilder) -> re::Regex {
    b.case_insensitive(true)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_SIZE)
        .build()
        .unwrap()
}

fn convert_mask(dest: &mut String, mask: &str) {
    dest.reserve(mask.len());
    for c in mask.chars() {
        match c {
            '*' => dest.push_str(".*"),
            '?' => dest.push('.'),
            c if regex_syntax::is_meta_character(c) => {
                dest.push('\\');
                dest.push(c);
            }
            c => dest.push(c),
        }
    }
}

pub fn mask_to_regex(mask: &str) -> re::Regex {
    REGEX.with(|s| {
        let mut s = s.borrow_mut();
        s.clear();
        convert_mask(&mut s, mask);
        build_regex(re::RegexBuilder::new(&s))
    })
}

#[allow(clippy::into_iter_on_ref)]
pub fn regexset_add(set: &mut re::RegexSet, mask: &str) {
    REGEX.with(|s| {
        let mut s = s.borrow_mut();
        s.clear();
        convert_mask(&mut s, mask);
        let new_patterns = set
            .patterns()
            .into_iter()
            .map(AsRef::as_ref)
            .chain(iter::once(s.as_str()));
        let new_set = build_regexset(re::RegexSetBuilder::new(new_patterns));
        *set = new_set;
    });
}

pub fn regexset_remove(set: &mut re::RegexSet, mask: &str) {
    REGEX.with(|s| {
        let mut s = s.borrow_mut();
        s.clear();
        convert_mask(&mut s, mask);
        let s = u(s.as_str());
        let new_patterns = set
            .patterns()
            .into_iter()
            .map(AsRef::as_ref)
            .filter(|p| u(p) != s);
        let new_set = build_regexset(re::RegexSetBuilder::new(new_patterns));
        *set = new_set;
    });
}

pub fn new_message_id() -> String {
    let mut bytes = [0x0; 24];
    RNG.with(|rng| {
        rng.borrow_mut().fill_bytes(&mut bytes);
    });

    let mut encoded = [0x0; 24 * 4 / 3];
    base64::encode_config_slice(&bytes, base64::STANDARD_NO_PAD, &mut encoded);

    std::str::from_utf8(&encoded).unwrap().to_owned()
}

pub fn time_precise() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn time_str() -> String {
    chrono::Local::now().to_rfc2822()
}

pub fn time() -> u64 {
    match time::SystemTime::now().duration_since(time::UNIX_EPOCH) {
        Ok(unix_time) => unix_time.as_secs(),
        Err(_) => {
            log::error!("Computer clock set before 01/01/1970?");
            0
        }
    }
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingStream;

#[cfg(not(unix))]
impl PendingStream {
    pub fn recv(self) -> impl Future<Output = Option<()>> {
        futures::future::pending()
    }
}
