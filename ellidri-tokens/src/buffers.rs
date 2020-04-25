use crate::{Command, MESSAGE_LENGTH};
use std::fmt;
use std::cell::RefCell;

/// Helper to build an IRC message.
///
/// Use with `Buffer::message`.
pub struct MessageBuffer<'a> {
    buf: &'a mut String,
}

impl<'a> MessageBuffer<'a> {
    fn with_prefix(buf: &'a mut String, prefix: &str, command: impl Into<Command>) -> Self {
        if !prefix.is_empty() {
            buf.push(':');
            buf.push_str(prefix);
            buf.push(' ');
        }
        buf.push_str(command.into().as_str());
        MessageBuffer { buf }
    }

    /// Appends a parameter to the message.
    ///
    /// The parameter is trimmed before insertion.  If `param` is whitespace, it is not appended.
    ///
    /// **Note**: It is up to the caller to make sure there is no remaning whitespace or newline in
    /// the parameter.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Buffer};
    /// let mut response = Buffer::new();
    ///
    /// response.message("nick!user@127.0.0.1", Command::Quit)
    ///     .param("")
    ///     .param("  chiao ");
    ///
    /// assert_eq!(&response.build(), ":nick!user@127.0.0.1 QUIT chiao\r\n");
    /// ```
    pub fn param(self, param: &str) -> Self {
        let param = param.trim();
        if param.is_empty() {
            return self;
        }
        self.buf.push(' ');
        self.buf.push_str(param);
        self
    }

    /// Formats, then appends a parameter to the message.
    ///
    /// The parameter is **NOT** trimmed before insertion, is appended even if it's empty.  Use
    /// `Buffer::param` to append strings, especially untrusted ones.
    ///
    /// **Note**: It is up to the caller to make sure there is no remaning whitespace or newline in
    /// the parameter.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Buffer};
    /// let mut response = Buffer::new();
    ///
    /// response.message("", Command::PrivMsg)
    ///     .fmt_param("  #space ")
    ///     .fmt_param(42);
    ///
    /// assert_eq!(&response.build(), "PRIVMSG   #space  42\r\n");
    /// ```
    pub fn fmt_param(self, param: &dyn fmt::Display) -> Self {
        use std::fmt::Write as _;

        self.buf.push(' ');
        let _ = write!(self.buf, "{}", param);
        self
    }

    /// Appends the traililng parameter to the message and consumes the buffer.
    ///
    /// Contrary to `MessageBuffer::param`, the parameter is not trimmed before insertion.  Even if
    /// `param` is just whitespace, it is appended.
    ///
    /// **Note**: It is up to the caller to make sure there is no newline in the parameter.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Buffer};
    /// let mut response = Buffer::new();
    ///
    /// response.message("nick!user@127.0.0.1", Command::Quit)
    ///     .trailing_param("long quit message");
    ///
    /// assert_eq!(&response.build(), ":nick!user@127.0.0.1 QUIT :long quit message\r\n");
    /// ```
    pub fn trailing_param(self, param: &str) {
        self.buf.push(' ');
        self.buf.push(':');
        self.buf.push_str(param);
    }

    /// Returns a buffer the caller can use to append characters to an IRC message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Buffer};
    /// let mut response = Buffer::new();
    /// {
    ///     let mut msg = response.message("nick!user@127.0.0.1", Command::Mode)
    ///         .param("#my_channel");
    ///     let mut param = msg.raw_param();
    ///     param.push('+');
    ///     param.push('n');
    ///     param.push('t');
    /// }
    ///
    /// assert_eq!(&response.build(), ":nick!user@127.0.0.1 MODE #my_channel +nt\r\n");
    /// ```
    pub fn raw_param(&mut self) -> &mut String {
        self.buf.push(' ');
        self.buf
    }

    /// Returns a buffer the caller can use to append characters to an IRC message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Buffer, rpl};
    /// let mut response = Buffer::new();
    /// {
    ///     let mut msg = response.message("ellidri.dev", rpl::NAMREPLY)
    ///         .param("ser");
    ///     let mut param = msg.raw_trailing_param();
    ///     param.push_str("@RandomChanOp");
    ///     param.push(' ');
    ///     param.push_str("RandomUser");
    /// }
    ///
    /// assert_eq!(&response.build(), ":ellidri.dev 353 ser :@RandomChanOp RandomUser\r\n");
    /// ```
    pub fn raw_trailing_param(&mut self) -> &mut String {
        self.buf.push(' ');
        self.buf.push(':');
        self.buf
    }
}

impl Drop for MessageBuffer<'_> {
    /// Auto-magically append "\r\n" when the `MessageBuffer` is dropped.
    fn drop(&mut self) {
        self.buf.push('\r');
        self.buf.push('\n');
    }
}

thread_local! {
    static UNESCAPED_VALUE: RefCell<String> = RefCell::new(String::new());
}

fn write_escaped(buf: &mut String, value: &dyn fmt::Display) {
    use fmt::Write;

    UNESCAPED_VALUE.with(|s| {
        let mut s = s.borrow_mut();

        s.clear();
        let _ = write!(s, "{}", value);

        buf.reserve(s.len());
        for c in s.chars() {
            match c {
                ';' => buf.push_str("\\:"),
                ' ' => buf.push_str("\\s"),
                '\r' => buf.push_str("\\r"),
                '\n' => buf.push_str("\\n"),
                '\\' => buf.push_str("\\\\"),
                c => buf.push(c),
            }
        }
    });
}

/// Helper to build the tags of an IRC message.
pub struct TagBuffer<'a> {
    buf: &'a mut String,
    tag_start: usize,
}

impl<'a> TagBuffer<'a> {
    /// Creates a new tag buffer.  This function is private, because it is meant to be called by
    /// `Buffer`.
    fn new(buf: &'a mut String) -> Self {
        buf.reserve(MESSAGE_LENGTH);
        let tag_start = buf.len();
        buf.push('@');
        TagBuffer {
            buf,
            tag_start,
        }
    }

    /// Whether the buffer has tags in it or not.
    pub fn is_empty(&self) -> bool {
        self.buf.len() == self.tag_start + 1
    }

    /// Adds a new tag to the buffer, with the given `key` and `value`.
    pub fn tag(self, key: &str, value: Option<&dyn fmt::Display>) -> Self {
        if !self.is_empty() {
            self.buf.push(';');
        }
        self.buf.push_str(key);
        if let Some(value) = value {
            self.buf.push('=');
            write_escaped(self.buf, value);
        }
        self
    }

    /// Adds the tag string `s`.
    fn raw_tag(self, s: &str) -> Self {
        if !self.is_empty() {
            self.buf.push(';');
        }
        self.buf.push_str(s);
        self
    }

    /// Writes the length of tags in `out`.
    ///
    /// Use this to know the start of the prefix or command.
    pub fn save_tags_len(self, out: &mut usize) -> Self {
        if self.buf.ends_with('@') {
            *out = 0;
        } else {
            *out = self.buf.len() + 1 - self.tag_start;
        }
        self
    }

    /// Starts building a message with the given prefix and command.
    pub fn prefixed_command(self, prefix: &str, cmd: impl Into<Command>) -> MessageBuffer<'a> {
        if self.is_empty() {
            self.buf.pop();
        } else {
            self.buf.push(' ');
        }
        MessageBuffer::with_prefix(self.buf, prefix, cmd)
    }
}

/// Helper to build IRC messages.
///
/// The `Buffer` is used to ease the creation of strings representing valid IRC messages.
///
/// # Example
///
/// ```rust
/// # use ellidri_tokens::{Command, Buffer, rpl};
/// let mut response = Buffer::new();
///
/// response.message("nick!user@127.0.0.1", Command::Topic)
///     .param("#hall")
///     .trailing_param("Welcome to new users!");
/// response.message("ellidri.dev", rpl::TOPIC)
///     .param("nickname")
///     .param("#hall")
///     .trailing_param("Welcome to new users!");
///
/// let result = response.build();
/// assert_eq!(&result, ":nick!user@127.0.0.1 TOPIC #hall :Welcome to new users!\r\n\
/// :ellidri.dev 332 nickname #hall :Welcome to new users!\r\n");
/// ```
#[derive(Debug)]
pub struct Buffer {
    buf: String,
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl From<String> for Buffer {
    fn from(val: String) -> Self {
        Self { buf: val }
    }
}

impl Buffer {
    /// Creates a `Buffer`.  Does not allocate.
    pub fn new() -> Self {
        Self { buf: String::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: String::with_capacity(capacity) }
    }

    /// Whether the buffer is empty.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Buffer};
    /// let empty = Buffer::new();
    /// let mut not_empty = Buffer::new();
    ///
    /// not_empty.message("ellidri.dev", Command::Motd);
    ///
    /// assert_eq!(empty.is_empty(), true);
    /// assert_eq!(not_empty.is_empty(), false);
    /// ```
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns a reference to the underlying `String`.
    pub fn get(&self) -> &str {
        &self.buf
    }

    /// Empties the buffer.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    pub fn reserve(&mut self, capacity: usize) {
        self.buf.reserve(capacity);
    }

    /// Appends an IRC message with a prefix to the buffer.
    ///
    /// This function may allocate to reserve space for the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, Buffer};
    /// let mut response = Buffer::new();
    ///
    /// response.message("unneeded_prefix", Command::Admin);
    ///
    /// assert_eq!(&response.build(), ":unneeded_prefix ADMIN\r\n");
    /// ```
    pub fn message(&mut self, prefix: &str, command: impl Into<Command>) -> MessageBuffer<'_> {
        MessageBuffer::with_prefix(&mut self.buf, prefix, command)
    }

    /// Start building an IRC message with tags.
    ///
    /// Server tags are filtered from `client_tags`, so that only tags with the client prefix `+`
    /// are appended to the buffer.
    ///
    /// The length of the resulting tags (`@` and ` ` included) is written to `tags_len`.
    ///
    /// TODO example
    pub fn tagged_message(&mut self, client_tags: &str) -> TagBuffer<'_> {
        client_tags.split(';')
            .filter(|s| s.starts_with('+') && !s.starts_with("+="))
            .fold(TagBuffer::new(&mut self.buf), |buf, tag| buf.raw_tag(tag))
    }

    /// Consumes the `Buffer` and returns the underlying `String`.
    pub fn build(self) -> String {
        self.buf
    }
}
