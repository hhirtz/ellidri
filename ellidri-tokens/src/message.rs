use crate::Command;

/// The recommended length of a message.
///
/// `Message::parse` can parse messages longer than that.  It is used by `Buffer` to avoid multiple
/// allocations when building the same message.
pub const MESSAGE_LENGTH: usize = 512;

/// The number of elements in `Message::params`.
pub const PARAMS_LENGTH: usize = 15;

/// Returns `(word, rest)` where `word` is the first word of the given string and `rest` is the
/// substring starting at the first character of the second word.
///
/// Word boundaries here are spaces only.
fn parse_word(s: &str) -> (&str, &str) {
    let mut split = s.splitn(2, ' ').map(str::trim).filter(|s| !s.is_empty());
    (split.next().unwrap_or(""), split.next().unwrap_or(""))
}

/// Parses the first word of the string the same way as `parse_word`, and then wrap it in a `Tags`
/// iterator.
fn parse_tags(buf: &str) -> (&str, &str) {
    if buf.starts_with('@') {
        let (tags, rest) = parse_word(buf);
        (&tags[1..], rest)
    } else {
        ("", buf)
    }
}

/// If the given string starts with a prefix, returns `(Some(prefix), rest)` where `rest` starts
/// from the first word after the prefix.
///
/// Otherwise returns `(None, rest)` where `rest` is the substring starting from the first word of
/// the given string.
fn parse_prefix(buf: &str) -> (Option<&str>, &str) {
    if buf.starts_with(':') {
        let (prefix, rest) = parse_word(buf);
        (Some(&prefix[1..]), rest)
    } else {
        (None, buf.trim_start())
    }
}

/// Parses the first word of the string the same way as `parse_word`, and then tries to parse it as
/// a command.
///
/// On success, it returns `(Ok(command), rest)`.  On failure, when the command is not a variant of
/// `Command`, it returns `(Err(unknown_command), rest)`.
fn parse_command(buf: &str) -> (Result<Command, &str>, &str) {
    let (command_string, rest) = parse_word(buf);
    (Command::parse(command_string).ok_or(command_string), rest)
}

/// Match a tag escape with its meaningful character.
///
/// # Example
///
/// ```rust
/// # use ellidri_tokens::tag_escape;
/// assert_eq!(tag_escape(':'), ';');  // "\:" is ";"
/// assert_eq!(tag_escape('b'), 'b');  // "\b" is "b"
/// ```
pub fn tag_escape(c: char) -> char {
    match c {
        ':' => ';',
        's' => ' ',
        'r' => '\r',
        'n' => '\n',
        c => c,
    }
}

/// A message tag.
///
/// Message tagging is an addition of an IRCv3 specification.  Refer to the following page for
/// more details on message tags: <https://ircv3.net/specs/extensions/message-tags>.
#[derive(Clone, Debug, PartialEq)]
pub struct Tag<'a> {
    /// The key of the tag.
    pub key: &'a str,

    /// The value of the tag, or `None` when the tag has no value.
    pub value: Option<&'a str>,
}

impl<'a> Tag<'a> {
    /// Parse a message tag.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::Tag;
    /// let tag = Tag::parse("label=123456");
    ///
    /// assert_eq!(tag.key, "label");
    /// assert_eq!(tag.value, Some("123456"));
    /// ```
    pub fn parse(buf: &'a str) -> Self {
        let mut split = buf.splitn(2, '=');
        let key = split.next().unwrap();
        let value = match split.next() {
            Some("") | None => None,
            Some(value) => Some(value),
        };
        Self { key, value }
    }

    /// Whether the tag is a client-only tag.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::Tag;
    /// let msgid = Tag::parse("msgid=42");
    /// let reply = Tag::parse("+example.pizza/beer");
    ///
    /// assert_eq!(msgid.is_client(), false);
    /// assert_eq!(reply.is_client(), true);
    /// ```
    pub fn is_client(&self) -> bool {
        self.key.starts_with('+')
    }

    /// Returns the unescaped version of the tag's value.
    ///
    /// Tag escaping is defined here: <https://ircv3.net/specs/extensions/message-tags.html> (look
    /// for "Escaping values").
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::Tag;
    /// let label = Tag::parse(r"label=Newline:\s\nBackslash-n:\s\\n");
    ///
    /// assert_eq!(&label.unescape_value(), "Newline: \nBackslash-n: \\n");
    /// ```
    pub fn unescape_value(&self) -> String {
        let mut res = String::new();
        self.unescape_value_into(&mut res);
        res
    }

    /// Appends the unescaped value of the tag to the given String.
    ///
    /// If the string is already allocated and has enough space, then this function will not
    /// allocate.  It is therefore preferable to use it if you already have a `String`.  See
    /// `Tag::unescape_value` for doc about tag escaping.
    pub fn unescape_value_into(&self, buf: &mut String) {
        let value = match self.value {
            Some(value) => value,
            None => return,
        };
        buf.reserve(value.len());
        let mut escape = false;
        for c in value.chars() {
            if c == '\\' && !escape {
                escape = true;
            } else {
                buf.push(if escape { tag_escape(c) } else { c });
                escape = false;
            }
        }
    }
}

/// An iterator over the tags of a string.
///
/// # Example
///
/// ```rust
/// # use ellidri_tokens::{Tag, tags};
/// let mut my_tags = tags("label=007;+custom=");
///
/// assert_eq!(my_tags.next(), Some(Tag { key: "label", value: Some("007") }));
/// assert_eq!(my_tags.next(), Some(Tag { key: "+custom", value: None }));
/// assert_eq!(my_tags.next(), None);
/// ```
pub fn tags(s: &str) -> impl Iterator<Item = Tag<'_>> {
    s.split(';')
        .filter(|item| !item.is_empty() && !item.starts_with('=') && !item.starts_with("+="))
        .map(|item| Tag::parse(item))
}

/// An IRC message.
///
/// See `Message::parse` for documentation on how to read IRC messages, and `Buffer` for
/// how to create messages.
///
/// See the RFC 2812 for a complete description of IRC messages:
/// <https://tools.ietf.org/html/rfc2812.html#section-2.3>.
#[derive(Clone, Debug)]
pub struct Message<'a> {
    /// The string containing all the tags.
    ///
    /// Message tagging is an addition of an IRCv3 specification.  Refer to the following page for
    /// more details on message tags: <https://ircv3.net/specs/extensions/message-tags>.
    pub tags: &'a str,

    /// The prefix of the message.
    pub prefix: Option<&'a str>,

    /// The command of the message.
    ///
    /// It can either be a valid command in the form of `Ok(Command::_)`, or a simple string.
    /// `Message::parse` sets this field to `Err(_)` if the command is not a variant of `Command`.
    pub command: Result<Command, &'a str>,

    /// The number of parameters, and the number of valid elements in `Message::params`.
    pub num_params: usize,

    /// The actual parameters of the message.
    ///
    /// Only the `num_params` first elements are valid.  Other elements are empty strings at the
    /// time of writing.
    pub params: [&'a str; PARAMS_LENGTH],
}

impl<'a> Message<'a> {
    /// Parses a string and returns information about the IRC message.
    ///
    /// Relevant source of information:
    /// <https://tools.ietf.org/html/rfc2812.html#section-2.3>.
    ///
    /// # Examples
    ///
    /// Here's an example of message parsing:
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Message};
    /// let privmsg = Message::parse(":ser PRIVMSG #fosdem :I'm Simon Sir\r\n").unwrap();
    ///
    /// assert_eq!(privmsg.prefix, Some("ser"));
    /// assert_eq!(privmsg.command, Ok(Command::PrivMsg));
    /// assert_eq!(privmsg.num_params, 2);
    /// assert_eq!(privmsg.params[0], "#fosdem");
    /// assert_eq!(privmsg.params[1], "I'm Simon Sir");
    /// ```
    ///
    /// If the command is unknown, it is stored as `Err(command_string)`, where `command_string` is
    /// taken from the input string:
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Message};
    /// let unknown = Message::parse("Typo arg1\r\n").unwrap();
    ///
    /// assert_eq!(unknown.prefix, None);
    /// assert_eq!(unknown.command, Err("Typo"));
    /// assert_eq!(unknown.num_params, 1);
    /// assert_eq!(unknown.params[0], "arg1");
    /// ```
    ///
    /// # Return value
    ///
    /// Returns `Some(msg)` when the message is correctly formed, `None` otherwise.  Correctly
    /// formed means the message has a command.
    ///
    /// ```rust
    /// # use ellidri_tokens::Message;
    /// let empty = Message::parse("  \r \n \t ");
    /// let no_command = Message::parse(":prefix");
    ///
    /// assert!(empty.is_none());
    /// assert!(no_command.is_none());
    /// ```
    pub fn parse(s: &'a str) -> Option<Message<'a>> {
        let mut buf = s.trim();
        if buf.is_empty() || buf.contains('\0') {
            return None;
        }

        let (tags, rest) = parse_tags(buf);
        buf = rest;
        let (prefix, rest) = parse_prefix(buf);
        buf = rest;
        let (command, rest) = parse_command(buf);
        buf = rest;

        if let Err("") = command {
            return None;
        }

        let mut params = [""; PARAMS_LENGTH];
        let mut num_params = 0;
        while num_params < PARAMS_LENGTH {
            if buf.is_empty() {
                break;
            }
            if buf.starts_with(':') {
                params[num_params] = &buf[1..];
                buf = "";
            } else {
                let (word, rest) = parse_word(buf);
                params[num_params] = word;
                buf = rest;
            }
            num_params += 1;
        }

        Some(Message {
            tags,
            prefix,
            command,
            num_params,
            params,
        })
    }

    /// Returns true if the message has enough parameters for its command.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::Message;
    /// let nick = Message::parse("NICK hello there").unwrap();
    /// assert_eq!(nick.has_enough_params(), true);
    ///
    /// let nick = Message::parse("NICK :").unwrap();
    /// assert_eq!(nick.has_enough_params(), true);
    ///
    /// let nick = Message::parse("NICK").unwrap();
    /// assert_eq!(nick.has_enough_params(), false);
    /// ```
    pub fn has_enough_params(&self) -> bool {
        match self.command {
            Ok(cmd) => cmd.required_params() <= self.num_params,
            Err(_) => false,
        }
    }

    pub fn tags(&self) -> impl Iterator<Item = Tag<'_>> {
        tags(self.tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Thank you oragono for the test cases! yum

    #[test]
    fn test_tag_parse() {
        let mut ts = tags("");
        assert_eq!(ts.next(), None);

        let mut ts = tags("time=12732;re");
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "time",
                value: Some("12732")
            })
        );
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "re",
                value: None
            })
        );
        assert_eq!(ts.next(), None);

        let mut ts = tags("+time=12732;re=;+asdf=5678");
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "+time",
                value: Some("12732")
            })
        );
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "re",
                value: None
            })
        );
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "+asdf",
                value: Some("5678")
            })
        );
        assert_eq!(ts.next(), None);

        let mut ts = tags("=these;time=12732;+=shouldbe;re=;asdf=5678;=ignored");
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "time",
                value: Some("12732")
            })
        );
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "re",
                value: None
            })
        );
        assert_eq!(
            ts.next(),
            Some(Tag {
                key: "asdf",
                value: Some("5678")
            })
        );
        assert_eq!(ts.next(), None);
    }

    #[test]
    fn test_unescape() {
        let tests = &[
            ["te\\n\\kst", "te\nkst"],
            ["te\\n\\kst\\", "te\nkst"],
            ["te\\\\nst", "te\\nst"],
            ["te😃st", "te😃st"],
            ["te😃\\st", "te😃 t"],
            ["0\\n1\\n2\\n3\\n4\\n5\\n6\\n\\", "0\n1\n2\n3\n4\n5\n6\n"],
            ["test\\", "test"],
            ["te\\:st\\", "te;st"],
            ["te\\:\\st\\", "te; t"],
            ["\\\\te\\:\\st", "\\te; t"],
            ["test\\", "test"],
            ["\\", ""],
            ["", ""],
        ];

        let mut buf = String::new();
        for [test, expected] in tests {
            let tag = Tag {
                key: "",
                value: Some(test),
            };
            buf.clear();
            tag.unescape_value_into(&mut buf);
            assert_eq!(&buf, expected);
        }
    }
} // mod tests
