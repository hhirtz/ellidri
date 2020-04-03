use crate::{Command, MESSAGE_LENGTH};
use std::fmt;
use std::cell::RefCell;

/// Helper to build an IRC message.
///
/// Use with `Buffer::message` and `ReplyBuffer::message`.
pub struct MessageBuffer<'a> {
    buf: &'a mut String,
}

impl<'a> MessageBuffer<'a> {
    fn with_prefix<C>(buf: &'a mut String, prefix: &str, command: C) -> Self
        where C: Into<Command>
    {
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
    pub fn fmt_param<T>(self, param: T) -> Self
        where T: fmt::Display
    {
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
        // TODO move this into Buffer (with checks for "\n" at the end of the buffer or something)
        self.buf.push('\r');
        self.buf.push('\n');
    }
}

thread_local! {
    static UNESCAPED_VALUE: RefCell<String> = RefCell::new(String::new());
}

fn write_escaped<T>(buf: &mut String, value: T)
    where T: fmt::Display
{
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
    /// `Buffer` and `ReplyBuffer`.
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
    pub fn tag<T>(self, key: &str, value: Option<T>) -> Self
        where T: fmt::Display
    {
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
    pub fn prefixed_command<C>(self, prefix: &str, cmd: C) -> MessageBuffer<'a>
        where C: Into<Command>
    {
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
/// The `Buffer` is used to ease the creation of strings representing valid IRC messages.  If you
/// mainly need to send replies, `ReplyBuffer` might be a better fit for you.
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
///
/// # On allocation
///
/// Allocation only occurs on `Buffer::message` calls.  These functions reseve `MESSAGE_LENGTH`
/// prior to writing on the internal buffer.
#[derive(Debug)]
pub struct Buffer {
    buf: String,
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Buffer {
    /// Creates a `Buffer`.  Does not allocate.
    pub fn new() -> Self {
        Self {
            buf: String::new(),
        }
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
    pub fn message<C>(&mut self, prefix: &str, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        self.buf.reserve(MESSAGE_LENGTH);
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

thread_local! {
    static DOMAIN: RefCell<String> = RefCell::new(String::new());
    static NICKNAME: RefCell<String> = RefCell::new(String::new());
    static LABEL: RefCell<String> = RefCell::new(String::new());
}

/// An helper to build responses meant for clients.
///
/// While `Buffer` is able to build any kind of IRC message, `ReplyBuffer` allows for easy creation
/// of IRC replies (messages that have the domain of the server as prefix, and the nickname of the
/// client as first parameter), and easy label/batch handling.
///
/// If you're looking for something simple, try `Buffer` first.
///
/// # Example
///
/// ```rust
/// # use ellidri_tokens::{Command, ReplyBuffer, rpl};
/// let mut response = ReplyBuffer::new("ellidri.dev", "nickname", Some("client-label"));
///
/// // Start a labeled-response batch.
/// response.start_lr_batch();
///
/// // Normal message, same API as `Buffer`.
/// response.message("nick!user@127.0.0.1", Command::Topic)
///     .param("#hall")
///     .trailing_param("Welcome to new users!");
///
/// // A reply.  It adds ":ellidri.dev" and "nickname" automatically.
/// response.reply(rpl::TOPIC)
///     .param("#hall")
///     .trailing_param("Welcome to new users!");
///
/// // End the labeled-response.
/// response.end_lr();
///
/// let result = response.build();
/// assert_eq!(&result, "@label=client-label :ellidri.dev BATCH +0 labeled-response\r\n\
/// @batch=0 :nick!user@127.0.0.1 TOPIC #hall :Welcome to new users!\r\n\
/// @batch=0 :ellidri.dev 332 nickname #hall :Welcome to new users!\r\n\
/// :ellidri.dev BATCH -0\r\n");
/// ```
///
/// # Usage note
///
/// This buffer uses thread-local storage to store the domain, the nickname and the label, to
/// reduce the number of allocations.  Therefore, the user must not make two `ReplyBuffer`s at the
/// same time on the same thread, otherwise nicknames, domains and labels will be mixed.
pub struct ReplyBuffer {
    buf: Buffer,
    batch: Option<u8>,
    has_label: bool,
}

impl ReplyBuffer {
    /// Creates a new `ReplyBuffer` and initialize the thread-local storage with the given domain,
    /// nickname and label.
    pub fn new(domain: &str, nickname: &str, label: Option<&str>) -> Self {
        DOMAIN.with(|s| {
            let mut s = s.borrow_mut();
            s.clear();
            s.push_str(domain);
        });
        if let Some(label) = label {
            LABEL.with(|s| {
                let mut s = s.borrow_mut();
                s.clear();
                s.push_str(label);
            });
        }
        let mut res = Self {
            buf: Buffer::new(),
            batch: None,
            has_label: label.is_some(),
        };
        res.set_nick(nickname);
        res
    }

    /// Whether the buffer has messages in it or not.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{ReplyBuffer, rpl};
    /// let empty = ReplyBuffer::new("ellidri.dev", "ser", None);
    /// let mut not_empty = ReplyBuffer::new("ellidri.dev", "ser", None);
    ///
    /// not_empty.reply(rpl::ERR_NOMOTD);
    ///
    /// assert_eq!(empty.is_empty(), true);
    /// assert_eq!(not_empty.is_empty(), false);
    /// ```
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Changes the nickname.
    ///
    /// Internally, it changes the thread-local storage associated with the nickname.
    pub fn set_nick(&mut self, nickname: &str) {
        NICKNAME.with(|n| {
            let mut n = n.borrow_mut();
            n.clear();
            n.push_str(nickname);
        });
    }

    /// Starts a batch with the given name.
    pub fn start_batch(&mut self, name: &str) {
        use fmt::Write;

        let new_batch = self.new_batch();
        let mut msg = self.prefixed_message("BATCH");
        let _ = write!(msg.raw_param(), "+{}", new_batch);
        msg.param(name);
    }

    /// Ends the inner-most batch.
    pub fn end_batch(&mut self) {
        use fmt::Write;

        let old_batch = self.batch.unwrap();
        self.batch = if old_batch == 0 {None} else {Some(old_batch - 1)};

        let mut msg = self.prefixed_message("BATCH");
        let _ = write!(msg.raw_param(), "-{}", old_batch);
    }

    /// Starts a labeled-response batch.
    pub fn start_lr_batch(&mut self) {
        use fmt::Write;

        if !self.has_label {
            return;
        }
        self.has_label = false;

        let new_batch = self.new_batch();
        LABEL.with(|label| DOMAIN.with(|domain| {
            let label = label.borrow();
            let domain = domain.borrow();
            let mut msg = self.buf.tagged_message("")
                .tag("label", Some(&label))
                .prefixed_command(&domain, "BATCH");
            let _ = write!(msg.raw_param(), "+{}", new_batch);
            msg.param("labeled-response");
        }));
    }

    /// Ends the labeled-response.
    ///
    /// If the buffer is empty, appends an ACK message.
    pub fn end_lr(&mut self) {
        if !self.has_label && self.batch.is_none() {
            return;
        }
        if self.batch.is_some() {
            self.end_batch();
        }
        if let Some(batch) = self.batch {
            panic!("ReplyBuffer: has an ongoing batch {} after the end of the labeled response",
                   batch);
        }
        if self.is_empty() {
            self.prefixed_message("ACK");
        }
        self.has_label = false;
    }

    /// Appends a reply to the buffer.
    ///
    /// This will push the domain, the reply and the nickname of the client, and then return the
    /// resulting `MessageBuffer`.
    ///
    /// This function appends the `@label` tag if necessary, and may allocate to reserve space for
    /// the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, ReplyBuffer, rpl};
    /// let mut response = ReplyBuffer::new("ellidri.dev", "ser", None);
    ///
    /// response.reply(rpl::WELCOME).trailing_param("Welcome to IRC, ser");
    ///
    /// assert_eq!(&response.build(), ":ellidri.dev 001 ser :Welcome to IRC, ser\r\n");
    /// ```
    pub fn reply<C>(&mut self, r: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        let msg = self.prefixed_message(r);
        NICKNAME.with(|s| msg.param(&s.borrow()))
    }

    /// Appends a command to the buffer, with the domain prefix, but without the nickname parameter.
    ///
    /// This function adds the `@label` tag if necessary, and may allocate to reserve space for the
    /// message.
    pub fn prefixed_message<C>(&mut self, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        DOMAIN.with(move |s| self.message(&s.borrow(), command))
    }

    /// Appends a prefixed message like you would do with a `Buffer`.
    ///
    /// If the given `prefix` is empty, no prefix is added.  This function adds the `@label` tag if
    /// necessary, and may allocate to reserve space for the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri_tokens::{Command, ReplyBuffer};
    /// let mut response = ReplyBuffer::new("ellidri.dev", "ser", None);
    ///
    /// response.message("unneeded_prefix", Command::Admin);
    /// response.message("", Command::Info);
    ///
    /// assert_eq!(&response.build(), ":unneeded_prefix ADMIN\r\nINFO\r\n");
    /// ```
    pub fn message<C>(&mut self, prefix: &str, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        self.tagged_message("").prefixed_command(prefix, command)
    }

    /// Starts building a tagged message.
    ///
    /// This function behaves like `Buffer::tagged_message`.  Neither the domain nor the prefix
    /// will be added.  However it still adds the `@label` tag if necessary, and may allocate to
    /// reserve space for the message.
    pub fn tagged_message(&mut self, tags: &str) -> TagBuffer<'_> {
        if self.has_label {
            self.has_label = false;
            LABEL.with(move |s| {
                self.buf.tagged_message(tags)
                    .tag("label", Some(&s.borrow()))
            })
        } else if let Some(batch) = self.batch {
            self.buf.tagged_message(tags)
                .tag("batch", Some(batch))
        } else {
            self.buf.tagged_message(tags)
        }
    }

    /// Consumes the buffer and returns the underlying `String`.
    pub fn build(self) -> String {
        self.buf.build()
    }

    /// Private function that sets up the internal state for a new batch, and returns the
    /// identitifier of this new batch.
    fn new_batch(&mut self) -> u8 {
        let new_batch = self.batch.map_or(0, |old_batch| old_batch + 1);
        self.batch = Some(new_batch);
        new_batch
    }
}
