use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::cell::RefCell;
use std::time;

thread_local! {
    static RNG: RefCell<ChaChaRng> = RefCell::new(ChaChaRng::seed_from_u64(time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs()));
}

pub type Masks<'a> = std::str::Split<'a, char>;

pub struct MaskSet {
    raw: String,
}

impl MaskSet {
    pub fn new() -> Self {
        MaskSet { raw: String::new() }
    }

    pub fn is_match(&self, s: &str) -> bool {
        self.raw.split(',').any(|mask| match_mask(mask, s))
    }

    /// Returns whether mask has been inserted.
    pub fn insert(&mut self, mask: &str) -> bool {
        if self.raw.split(',').any(|m| m == mask) {
            return false;
        }

        if !self.raw.is_empty() {
            self.raw.push(',');
        }
        self.raw.push_str(mask);

        true
    }

    /// Returns whether mask has been removed.
    pub fn remove(&mut self, mask: &str) -> bool {
        if let Some(removed) = self.raw.split(',').find(|m| *m == mask) {
            let start = removed.as_ptr() as usize - self.raw.as_ptr() as usize;

            let mut end = start + removed.len();
            if end < self.raw.len() {
                end += 1;
            }

            self.raw.replace_range(start..end, "");

            return true;
        }

        false
    }

    pub fn masks(&self) -> Masks<'_> {
        self.raw.split(',')
    }
}

// Taken from <https://golang.org/src/path/match.go?s=1084:1142#L28>
pub fn match_mask(mut mask: &str, mut s: &str) -> bool {
    'pattern: while !mask.is_empty() {
        let (star, chunk) = scan_chunk(&mut mask);
        if star && chunk.is_empty() {
            return true;
        }

        let (rest, ok) = match_chunk(chunk, s);
        if ok && (rest.is_empty() || !mask.is_empty()) {
            s = rest;
            continue;
        }

        if star {
            for i in 0..s.len() {
                let (rest, ok) = match_chunk(chunk, &s[i + 1..]);
                if ok {
                    if mask.is_empty() && !rest.is_empty() {
                        continue;
                    }
                    s = rest;
                    continue 'pattern;
                }
            }
        }

        return false;
    }

    s.is_empty()
}

fn scan_chunk<'a>(mask: &mut &'a str) -> (bool, &'a str) {
    let initial_len = mask.len();
    *mask = mask.trim_start_matches('*');
    let star = mask.len() < initial_len;

    let i = mask.find('*').unwrap_or(mask.len());
    let chunk = &mask[..i];
    *mask = &mask[i..];
    (star, chunk)
}

fn match_chunk<'a>(chunk: &str, mut s: &'a str) -> (&'a str, bool) {
    for fc in chunk.chars() {
        let mut it = s.chars();
        let fs = match it.next() {
            Some(fs) => fs,
            None => return ("", false),
        };

        if fc != '?' && fc != fs {
            return ("", false);
        }
        s = it.as_str();
    }

    (s, true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_match() {
        let cases = [
            ("abc", "abc", true),
            ("*", "abc", true),
            ("*c", "abc", true),
            ("a*", "a", true),
            ("a*", "abc", true),
            ("a*/b", "abc/b", true),
            ("a*b?c*x", "abxbbxdbxebxczzx", true),
            ("a*b?c*x", "abxbbxdbxebxczzy", false),
            ("a?b", "a☺b", true),
            ("a???b", "a☺b", false),
            ("*x", "xxx", true),
        ];

        for (mask, s, is_match) in &cases {
            assert_eq!(
                match_mask(mask, s),
                *is_match,
                "match_mask({:?}, {:?})",
                mask,
                s
            );
        }
    }
} // mod tests
