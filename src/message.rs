//! Message parsing and building.

pub use rpl::Reply;

/// The recommended length of a message.
///
/// `Message::parse` can parse messages longer than that.  It is used by `ResponseBuffer` to avoid
/// multiple allocations when building the same message.
pub const MAX_MESSAGE_LENGTH: usize = 512;

/// The number of elements in `Message::params`.
pub const MAX_PARAMS: usize = 15;

/// The list of IRC replies.
///
/// All reply must have the client's nick as first parameter.
///
/// Source: <https://tools.ietf.org/html/rfc2812.html#section-5>
pub mod rpl {
    pub type Reply = &'static str;

    pub const WELCOME: Reply   = "001";  // :Welcome message
    pub const YOURHOST: Reply  = "002";  // :Your host is...
    pub const CREATED: Reply   = "003";  // :This server was created...
    pub const MYINFO: Reply    = "004";  // <servername> <version> <umodes> <chan modes> <chan modes with a parameter>
    pub const ISUPPORT: Reply  = "005";  // 1*13<TOKEN[=value]> :are supported by this server

    pub const UMODEIS: Reply       = "221";  // <modes>
    pub const LUSERCLIENT: Reply   = "251";  // :<int> users and <int> services on <int> servers
    pub const LUSEROP: Reply       = "252";  // <int> :operator(s) online
    pub const LUSERUNKNOWN: Reply  = "253";  // <int> :unknown connection(s)
    pub const LUSERCHANNELS: Reply = "254";  // <int> :channels formed
    pub const LUSERME: Reply       = "255";  // :I have <int> clients and <int> servers
    pub const ADMINME: Reply       = "256";  // <server> :Admin info
    pub const ADMINLOC1: Reply     = "257";  // :<info>
    pub const ADMINLOC2: Reply     = "258";  // :<info>
    pub const ADMINMAIL: Reply     = "259";  // :<info>

    pub const WHOISUSER: Reply       = "311";  // <nick> <user> <host> * :<realname>
    pub const WHOISSERVER: Reply     = "312";  // <nick> <server> :<server info>
    pub const WHOISOPERATOR: Reply   = "313";  // <nick> :is an IRC operator
    pub const ENDOFWHO: Reply        = "315";  // <name> :End of WHO list
    pub const WHOISIDLE: Reply       = "317";  // <nick> <integer> [<integer>] :seconds idle [, signon time]
    pub const ENDOFWHOIS: Reply      = "318";  // <nick> :End of WHOIS list
    pub const WHOISCHANNELS: Reply   = "319";  // <nick> :*( (@/+) <channel> " " )
    pub const LIST: Reply            = "322";  // <channel> <# of visible members> <topic>
    pub const LISTEND: Reply         = "323";  // :End of list
    pub const CHANNELMODEIS: Reply   = "324";  // <channel> <modes> <modeparams>
    pub const NOTOPIC: Reply         = "331";  // <channel> :No topic set
    pub const TOPIC: Reply           = "332";  // <channel> <topic>
    pub const INVITING: Reply        = "341";  // <channel> <nick>
    pub const INVITELIST: Reply      = "346";  // <channel> <invite mask>
    pub const ENDOFINVITELIST: Reply = "347";  // <channel> :End of invite list
    pub const EXCEPTLIST: Reply      = "348";  // <channel> <exception mask>
    pub const ENDOFEXCEPTLIST: Reply = "349";  // <channel> :End of exception list
    pub const VERSION: Reply         = "351";  // <version> <servername> :<comments>
    pub const WHOREPLY: Reply        = "352";  // <channel> <user> <host> <server> <nick> "H"/"G" ["*"] [("@"/"+")] :<hopcount> <nick>
    pub const NAMREPLY: Reply        = "353";  // <=/*/@> <channel> :1*(@/ /+user)
    pub const ENDOFNAMES: Reply      = "366";  // <channel> :End of names list
    pub const BANLIST: Reply         = "367";  // <channel> <ban mask>
    pub const ENDOFBANLIST: Reply    = "368";  // <channel> :End of ban list
    pub const INFO: Reply            = "371";  // :<info>
    pub const MOTD: Reply            = "372";  // :- <text>
    pub const ENDOFINFO: Reply       = "374";  // :End of INFO
    pub const MOTDSTART: Reply       = "375";  // :- <servername> Message of the day -
    pub const ENDOFMOTD: Reply       = "376";  // :End of MOTD command
    pub const YOUREOPER: Reply       = "381";  // :You are now an operator
    pub const TIME: Reply            = "391";  // <servername> :<time in whatever format>

    pub const ERR_NOSUCHNICK: Reply       = "401";  // <nick> :No such nick/channel
    pub const ERR_NOSUCHCHANNEL: Reply    = "403";  // <channel> :No such channel
    pub const ERR_CANNOTSENDTOCHAN: Reply = "404";  // <channel> :Cannot send to channel
    pub const ERR_INVALIDCAPCMD: Reply    = "410";  // <command> :Unknown cap command
    pub const ERR_NORECIPIENT: Reply      = "411";  // :No recipient given
    pub const ERR_NOTEXTTOSEND: Reply     = "412";  // :No text to send
    pub const ERR_UNKNOWNCOMMAND: Reply   = "421";  // <command> :Unknown command
    pub const ERR_NOMOTD: Reply           = "422";  // :MOTD file missing
    pub const ERR_NONICKNAMEGIVEN: Reply  = "431";  // :No nickname given
    pub const ERR_ERRONEUSNICKNAME: Reply = "432";  // <nick> :Erroneous nickname
    pub const ERR_NICKNAMEINUSE: Reply    = "433";  // <nick> :Nickname in use
    pub const ERR_USERNOTINCHANNEL: Reply = "441";  // <nick> <channel> :User not in channel
    pub const ERR_NOTONCHANNEL: Reply     = "442";  // <channel> :You're not on that channel
    pub const ERR_NOTREGISTERED: Reply    = "451";  // :You have not registered
    pub const ERR_NEEDMOREPARAMS: Reply   = "461";  // <command> :Not enough parameters
    pub const ERR_ALREADYREGISTRED: Reply = "462";  // :Already registered
    pub const ERR_PASSWDMISMATCH: Reply   = "464";  // :Password incorrect
    pub const ERR_YOUREBANNEDCREEP: Reply = "465";  // :You're banned from this server
    pub const ERR_KEYSET: Reply           = "467";  // <channel> :Channel key already set
    pub const ERR_CHANNELISFULL: Reply    = "471";  // <channel> :Cannot join channel (+l)
    pub const ERR_UNKNOWNMODE: Reply      = "472";  // <char> :Don't know this mode for <channel>
    pub const ERR_INVITEONLYCHAN: Reply   = "473";  // <channel> :Cannot join channel (+I)
    pub const ERR_BANNEDFROMCHAN: Reply   = "474";  // <channel> :Cannot join channel (+b)
    pub const ERR_BADCHANKEY: Reply       = "475";  // <channel> :Cannot join channel (+k)
    pub const ERR_CHANOPRIVSNEEDED: Reply = "482";  // <channel> :You're not an operator

    pub const ERR_UMODEUNKNOWNFLAG: Reply = "501";  // :Unknown mode flag
    pub const ERR_USERSDONTMATCH: Reply   = "502";  // :Can't change mode for other users
}

/// Returns `(word, rest)` where `word` is the first word of the given string and `rest` is the
/// substring starting at the first character of the second word.
///
/// Word boundaries here are spaces only.
fn parse_word(s: &str) -> (&str, &str) {
    let mut split = s.splitn(2, ' ')
        .map(str::trim)
        .filter(|s| !s.is_empty());
    (split.next().unwrap_or(""), split.next().unwrap_or(""))
}

/// Parses the first word of the string the same way as `parse_word`, and then wrap it in a `Tags`
/// iterator.
fn parse_tags(buf: &str) -> (Tags<'_>, &str) {
    if buf.starts_with('@') {
        let (tags, rest) = parse_word(buf);
        (Tags { buf: &tags[1..] }, rest)
    } else {
        (Tags { buf: "" }, buf)
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

/// A message tag.
///
/// Message tagging is an addition of an IRCv3 specification.  Refer to the following page for
/// more details on message tags: <https://ircv3.net/specs/extensions/message-tags>.
pub struct Tag<'a> {
    /// The key of the tag.
    pub key: &'a str,

    /// The value of the tag, or `None` when the tag has no value.
    pub value: Option<&'a str>,

    /// Whether this is a client tag (has `+` prepended to its key).
    pub is_client: bool,
}

impl<'a> Tag<'a> {
    pub fn parse(buf: &'a str) -> Tag<'a> {
        let mut split = buf.splitn(2, '=');
        let key = split.next().unwrap();
        let value = split.next();
        let is_client = key.starts_with('+');
        Tag {
            key: if is_client {&key[1..]} else {key},
            value,
            is_client,
        }
    }
}

/// An iterator over message tags.
///
/// Message tagging is an addition of an IRCv3 specification.  Refer to the following page for
/// more details on message tags: <https://ircv3.net/specs/extensions/message-tags>.
pub struct Tags<'a> {
    buf: &'a str,
}

impl<'a> Iterator for Tags<'a> {
    type Item = Tag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let mut split = self.buf.splitn(2, ';');
        let tag = Tag::parse(split.next().unwrap());
        self.buf = split.next().unwrap_or("");
        Some(tag)
    }
}

macro_rules! commands {
    ( $( $cmd:ident => $n:expr, )* ) => {
        /// The list of commands, generated by `commands!`.
        ///
        /// Unknown commands and replies are supported by `Message` directly, this enum just
        /// contains the supported commands.
        #[derive(Clone, Copy, Debug, PartialEq)]
        pub enum Command {
            $( $cmd, )*
            Reply(Reply),
        }

        impl Command {
            /// From a given command string, returns the corresponding command, or `None`
            /// otherwise.
            ///
            /// It ignores the case of its argument.
            ///
            /// # Example
            ///
            /// ```rust
            /// # use ellidri::message::Command;
            /// let join = Command::parse("join");
            /// let join2 = Command::parse("JOIN");
            /// let not_join = Command::parse("jjoin");
            ///
            /// assert_eq!(join, Some(Command::Join));
            /// assert_eq!(join2, Some(Command::Join));
            /// assert_eq!(not_join, None);
            /// ```
            pub fn parse(s: &str) -> Option<Command> {
                $( if s.eq_ignore_ascii_case(stringify!($cmd)) {
                    Some(Command::$cmd)
                } else )* {
                    None
                }
            }

            /// Returns the number of required arguments for the command.
            ///
            /// The command may accept more arguments.
            ///
            /// # Example
            ///
            /// ```rust
            /// # use ellidri::message::Command;
            /// let privmsg = Command::parse("Privmsg").unwrap();
            /// let topic = Command::parse("TOPIC").unwrap();
            ///
            /// assert_eq!(privmsg.required_params(), 2);
            /// assert_eq!(topic.required_params(), 1);
            /// ```
            pub fn required_params(&self) -> usize {
                match self {
                $(
                    Command::$cmd => $n,
                )*
                    Command::Reply(_) => 0,
                }
            }

            /// Returns the command string. It is not the string that have been parsed.
            ///
            /// # Example
            ///
            /// ```rust
            /// # use ellidri::message::Command;
            /// let quit = Command::parse("QUIT").unwrap();
            ///
            /// assert_eq!(quit.as_str(), "Quit");
            /// ```
            pub fn as_str(&self) -> &'static str {
                match self {
                $(
                    Command::$cmd => stringify!($cmd),
                )*
                    Command::Reply(s) => s,
                }
            }
        }

        impl From<&'static str> for Command {
            /// `&'static str`s are converted to the `Command::Reply` variant.
            ///
            /// This trait is used by `ResponseBuffer` to accept both `Command` and `Reply` when
            /// building messages.
            fn from(reply: &'static str) -> Command {
                Command::Reply(reply)
            }
        }
    }
}

commands! {
    Admin => 0,
    Cap => 1,
    Info => 0,
    Invite => 2,
    Join => 1,
    Kick => 2,
    List => 0,
    Lusers => 0,
    Mode => 1,
    Motd => 0,
    Names => 0,
    Nick => 1,
    Notice => 2,
    Oper => 2,
    Part => 1,
    Pass => 1,
    Ping => 1,
    Pong => 1,
    PrivMsg => 2,
    Quit => 0,
    Time => 0,
    Topic => 1,
    User => 4,
    Version => 0,
    Who => 0,
    Whois => 1,
}

/// An IRC message.
///
/// See `Message::parse` for documentation on how to read IRC messages, and `ResponseBuffer` for
/// how to create messages.
///
/// See the RFC 2812 for a complete description of IRC messages:
/// <https://tools.ietf.org/html/rfc2812.html#section-2.3>.
pub struct Message<'a> {
    /// An iterator over the tags of the message.
    ///
    /// Message tagging is an addition of an IRCv3 specification.  Refer to the following page for
    /// more details on message tags: <https://ircv3.net/specs/extensions/message-tags>.
    pub tags: Tags<'a>,

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
    pub params: [&'a str; MAX_PARAMS],
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
    /// # use ellidri::message::{Command, Message};
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
    /// # use ellidri::message::{Command, Message};
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
    /// Returns `Some(msg)` when the message is correctly formed, `None` otherwise.
    ///
    ///
    /// ```rust
    /// # use ellidri::message::Message;
    /// let empty = Message::parse("  \r \n \t ");
    /// let no_command = Message::parse(":prefix");
    ///
    /// assert!(empty.is_none());
    /// assert!(no_command.is_none());
    /// ```
    pub fn parse(s: &'a str) -> Option<Message<'a>>
    {
        let mut buf = s.trim();
        if buf.is_empty() {
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

        let mut params = [""; MAX_PARAMS];
        let mut num_params = 0;
        while num_params < MAX_PARAMS {
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

        Some(Message { tags, prefix, command, num_params, params })
    }

    /// Returns true if the message has enough parameters for its command.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::Message;
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
}

/// Helper to build an IRC message.
///
/// Created by `ResponseBuffer::message` and `ResponseBuffer::prefixed_message`.
pub struct MessageBuffer<'a> {
    buf: &'a mut String,
}

impl<'a> MessageBuffer<'a> {
    fn new<C>(buf: &'a mut String, command: C) -> MessageBuffer<'a>
        where C: Into<Command>
    {
        buf.push_str(command.into().as_str());
        MessageBuffer { buf }
    }

    fn with_prefix<C>(buf: &'a mut String, prefix: &str, command: C) -> MessageBuffer<'a>
        where C: Into<Command>
    {
        buf.push(':');
        buf.push_str(prefix);
        buf.push(' ');
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
    /// # use ellidri::message::{Command, ResponseBuffer};
    /// let mut response = ResponseBuffer::new();
    ///
    /// response.message(Command::Quit)
    ///     .param("  chiao ");
    ///
    /// assert_eq!(&response.build(), "Quit chiao\r\n");
    /// ```
    pub fn param(self, param: &str) -> MessageBuffer<'a>
    {
        let param = param.trim();
        if param.is_empty() {
            return self;
        }
        self.buf.push(' ');
        self.buf.push_str(param);
        self
    }

    /// Appends the traililng parameter to the message and consumes the buffer.
    ///
    /// Contrary to `MessageBuffer::param`, the parameter is not trimmed before insertion.  Even if
    /// `param` is whitespace, it is not appended.
    ///
    /// **Note**: It is up to the caller to make sure there is no newline in the parameter.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{Command, ResponseBuffer};
    /// let mut response = ResponseBuffer::new();
    ///
    /// response.message(Command::Quit)
    ///     .trailing_param("long quit message");
    ///
    /// assert_eq!(&response.build(), "Quit :long quit message\r\n");
    /// ```
    pub fn trailing_param(self, param: &str)
    {
        self.buf.push(' ');
        self.buf.push(':');
        self.buf.push_str(param);
    }

    /// Returns a buffer the caller can use to append characters to an IRC message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{Command, ResponseBuffer};
    /// let mut response = ResponseBuffer::new();
    /// {
    ///     let mut msg = response.message(Command::Mode)
    ///         .param("#my_channel");
    ///     let mut param = msg.raw_param();
    ///     param.push('+');
    ///     param.push('n');
    ///     param.push('t');
    /// }
    ///
    /// assert_eq!(&response.build(), "Mode #my_channel +nt\r\n");
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
    /// # use ellidri::message::{ResponseBuffer, rpl};
    /// let mut response = ResponseBuffer::new();
    /// {
    ///     let mut msg = response.prefixed_message("ellidri.dev", rpl::NAMREPLY)
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

impl<'a> Drop for MessageBuffer<'a> {
    /// Automagically append "\r\n" when the `MessageBuffer` is dropped.
    fn drop(&mut self) {
        // TODO move this into ResponseBuffer (with checks for "\n" at the end of the buffer or something)
        self.buf.push('\r');
        self.buf.push('\n');
    }
}

/// Helper to build IRC messages.
///
/// The `ResponseBuffer` is used to ease the creation of strings representing valid IRC messages.
///
/// # Example
///
/// ```rust
/// # use ellidri::message::{Command, ResponseBuffer, rpl};
/// let mut response = ResponseBuffer::new();
///
/// response.message(Command::Topic).param("#hall");
/// response.prefixed_message("ellidri.dev", rpl::TOPIC)
///     .param("nickname")
///     .param("#hall")
///     .trailing_param("Welcome to new users!");
///
/// let result = response.build();
/// assert_eq!(&result, "Topic #hall\r\n:ellidri.dev 332 nickname #hall :Welcome to new users!\r\n");
/// ```
///
/// # On allocation
///
/// Allocation only occurs on `ResponseBuffer::message` and `ResponseBuffer::prefixed_message`
/// calls.  These functions reserve
#[derive(Debug)]
pub struct ResponseBuffer {
    buf: String,
}

impl Default for ResponseBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseBuffer {
    /// Creates a `ResponseBuffer`.  Does not allocate.
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
    /// # use ellidri::message::{Command, ResponseBuffer};
    /// let empty = ResponseBuffer::new();
    /// let mut not_empty = ResponseBuffer::new();
    ///
    /// not_empty.message(Command::Motd);
    ///
    /// assert_eq!(empty.is_empty(), true);
    /// assert_eq!(not_empty.is_empty(), false);
    /// ```
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Appends an IRC message to the buffer.
    ///
    /// This function may allocate to reserve space for the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{Command, ResponseBuffer};
    /// let mut response = ResponseBuffer::new();
    ///
    /// response.message(Command::Motd);
    ///
    /// assert_eq!(&response.build(), "Motd\r\n");
    /// ```
    pub fn message<C>(&mut self, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        self.buf.reserve(MAX_MESSAGE_LENGTH);
        MessageBuffer::new(&mut self.buf, command)
    }

    /// Appends an IRC message with a prefix to the buffer.
    ///
    /// This function may allocate to reserve space for the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{Command, ResponseBuffer};
    /// let mut response = ResponseBuffer::new();
    ///
    /// response.prefixed_message("unneeded_prefix", Command::Admin);
    ///
    /// assert_eq!(&response.build(), ":unneeded_prefix Admin\r\n");
    /// ```
    pub fn prefixed_message<C>(&mut self, prefix: &str, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        self.buf.reserve(MAX_MESSAGE_LENGTH);
        MessageBuffer::with_prefix(&mut self.buf, prefix, command)
    }

    /// Maybe this should be reworked.
    ///
    /// It's used to print ban/invite/except lists.
    pub fn reply_list<I, F>(&mut self, prefix: &str, item_reply: Reply, end_reply: Reply,
                            end_line: &str, list: I, mut map: F)
        where I: IntoIterator,
              I::Item: AsRef<str>,
              F: FnMut(MessageBuffer<'_>) -> MessageBuffer<'_>
    {
        for item in list {
            map(self.prefixed_message(prefix, item_reply))
                .param(item.as_ref());
        }
        map(self.prefixed_message(prefix, end_reply))
            .trailing_param(end_line);
    }

    /// Consumes the `ResponseBuffer` and returns the underlying `String`.
    pub fn build(self) -> String {
        self.buf
    }
}
