//! Message parsing, with the list of commands and replies.
//!
//! See the documentation of `Message` for more details.

use std::borrow::Cow;
use std::ops::Range;
use std::sync::Arc;

pub use rpl::Reply;
use std::{fmt, iter, mem};

/// The maximum length of an IRC message.
///
/// Used by `Message` constructors.
const MAX_MESSAGE_LENGTH: usize = 512;

/// The list of IRC replies.
///
/// Source: https://tools.ietf.org/html/rfc2812.html#section-5
pub mod rpl {
    /// The type used for all replies in this module.
    ///
    /// Used to ease any BrEaKiNg ChAnGe that may happen.
    pub type Reply = &'static str;

    // All reply must have the client's nick as first parameter.

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
    pub const NAMREPLY: Reply        = "353";  // <=/*/@> <channel> :1*(@/ /+user)
    pub const ENDOFNAMES: Reply      = "366";  // <channel> :End of names list
    pub const BANLIST: Reply         = "367";  // <channel> <ban mask>
    pub const ENDOFBANLIST: Reply    = "368";  // <channel> :End of ban list
    pub const MOTD: Reply            = "372";  // :- <text>
    pub const MOTDSTART: Reply       = "375";  // :- <servername> Message of the day -
    pub const ENDOFMOTD: Reply       = "376";  // :End of MOTD command
    pub const YOUREOPER: Reply       = "381";  // :You are now an operator
    pub const TIME: Reply            = "391";  // <servername> :<time in whatever format>

    pub const ERR_NOSUCHNICK: Reply       = "401";  // <nick> :No such nick/channel
    pub const ERR_NOSUCHCHANNEL: Reply    = "403";  // <channel> :No such channel
    pub const ERR_CANNOTSENDTOCHAN: Reply = "404";  // <channel> :Cannot send to channel
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

    #[cfg(feature = "irdille")] pub const IRDILLE_MODIFIEDPRIVMSG: Reply = "802";
}

/// Code generation for the list of commands.
///
/// # Usage
///
/// ```rust
/// commands! {
///     CommandIdentifier => num_params,
///     // ...
/// }
/// ```
///
/// `num_params` is the number of required parameters for this command.
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
            /// use ellidri::message::Command;
            ///
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
            /// # Example
            ///
            /// ```rust
            /// use ellidri::message::Command;
            ///
            /// let privmsg = Command::parse("Privmsg").unwrap();
            /// let join = Command::parse("JOIN").unwrap();
            ///
            /// assert_eq!(privmsg.required_params(), 2);
            /// assert_eq!(join.required_params(), 1);
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
            /// use ellidri::message::Command;
            ///
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

        impl fmt::Display for Command {
            /// Simply writes the output of `Command::as_str`. Used by `Message::new`.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl From<&'static str> for Command {
            fn from(reply: &'static str) -> Command {
                Command::Reply(reply)
            }
        }
    }
}

commands! {
    Admin => 0,
    Invite => 2,
    Join => 1,
    List => 0,
    Lusers => 0,
    Mode => 1,
    Motd => 0,
    Names => 0,
    Nick => 1,
    Notice => 2,
    Oper => 2,
    Part => 1,
    Ping => 1,
    Pong => 1,
    PrivMsg => 2,
    Quit => 0,
    Time => 0,
    Topic => 1,
    User => 4,
    Version => 0,
}

/// For the given `word`, that is part of the given `buf`, returns the matching `Command`, or the
/// index of `word` in `buf` otherwise.
///
/// `word` must be part (i.e. a word of) of `buf`, otherwise this function might panic (a.k.a.
/// undefined behavior)...
fn parse_message_command(word: &str, buf: &str) -> Result<Command, Range<usize>> {
    Command::parse(word).ok_or_else(|| range_of(word, buf))
}

/// Returns the index of the `inner` string in the `outer` string.
///
/// If `inner` is not "inside" `outer` in memory, this function has undefined behavior (panics if
/// `inner` is before `outer` in memory, returns nonsense otherwise).
///
/// # Example
///
/// ```rust,ignore
/// let outer = "Hello world!";
/// let inner = &outer[0..5];  // "Hello"
/// assert_eq!(range_of(inner, outer), 0..5);
/// ```
fn range_of(inner: &str, outer: &str) -> Range<usize> {
    let inner_len = inner.len();
    let inner = inner.as_ptr() as usize;
    let outer = outer.as_ptr() as usize;
    let start = inner - outer;
    let end = start + inner_len;
    start..end
}

/// An iterator over the parameters of a message. Use with `Message::params`.
pub struct Params<'a> {
    /// What is left to be parsed. Must be trimmed.
    buf: &'a str,
}

impl<'a> Iterator for Params<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        if self.buf.is_empty() {
            None
        } else if self.buf.as_bytes()[0] == b':' {
            self.buf = &self.buf[1..];  // Discard the ':'
            Some(mem::replace(&mut self.buf, ""))
        } else {
            let mut words = self.buf.splitn(2, char::is_whitespace);
            let next = words.next().unwrap();
            self.buf = words.next().unwrap_or("").trim_start();
            Some(next)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.buf.is_empty() {
            (0, Some(0))
        } else {
            (1, None)
        }
    }
}

impl iter::FusedIterator for Params<'_> {}

/// Represents an IRC message, with its prefix (source), command and parameters.
///
/// This type is a wrapper around a string. It means that when `Message::parse` is called, the
/// string is kept intact, and each component of the message are stored as indexes of the string.
/// The parameters are parsed lazily by an iterator.
///
/// See `Message::new` and `Message::parse` for usage examples.
#[derive(Clone, Debug)]
pub struct Message<'a> {
    /// Message buffer. Instead of having a string for the source, the command, and each parameter,
    /// there's only one string. The other struct members refer to indexes in the string (not
    /// unicode points).
    buf: Cow<'a, str>,

    /// The source of the message.
    prefix: Option<Range<usize>>,

    /// Either a known `Command`, or the range of indexes in `self.buf` where the command string
    /// is.
    ///
    /// Either this is `Ok(c)`, and the command string is `c.as_str()`, or this is `Err(Range {
    /// start, end })`, and the command string is `self.buf[start..end]`.
    command: Result<Command, Range<usize>>,

    /// The index of the first parameter. Used to create a `Params` instance.
    first_param_index: usize,
}

impl Message<'static> {
    /// Starts building a new message.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ellidri::message::{Command, Message};
    ///
    /// let ping = Message::with_prefix("ellidri.org", Command::Ping)
    ///     .param("42")  // Add a parameter.
    ///     .build();     // Returns the Message from the MessageBuilder.
    ///
    /// assert_eq!(ping.as_ref(), &b":ellidri.org Ping 42\r\n"[..]);
    ///
    /// let privmsg = Message::with_prefix("admin", Command::PrivMsg)
    ///     .param("#agora")
    ///     .trailing_param("The server is back up!");
    ///
    /// assert_eq!(privmsg.as_ref(),
    ///            &b":admin PrivMsg #agora :The server is back up!\r\n"[..]);
    /// ```
    pub fn with_prefix(prefix: &str, command: Command) -> MessageBuilder {
        MessageBuilder::with_prefix(prefix, command)
    }
}

impl<'a> Message<'a> {
    /// Wraps the given string into a `Message` type, that allows to get its source, the command
    /// and each parameter.
    ///
    /// This function accepts strings with or without "\r\n", or any whitespace.
    ///
    /// Relevant source of information:
    /// https://tools.ietf.org/html/rfc2812.html#section-2.3
    ///
    /// # Example
    ///
    /// ```rust
    /// use ellidri::message::{Command, Message};
    ///
    /// let msg = Message::parse(":kawai PRIVMSG #kekbab :You must be joking!")
    ///     .unwrap()   // The message was parsed successfully.
    ///     .unwrap();  // The message is not empty.
    /// let mut params = msg.params();
    ///
    /// assert_eq!(msg.prefix(), Some("kawai"));
    /// assert_eq!(msg.command(), Ok(Command::PrivMsg));
    /// assert_eq!(params.next(), Some("#kekbab"));  // First parameter.
    /// assert_eq!(params.next(), Some("You must be joking!"));  // Second parameter.
    /// assert_eq!(params.next(), None);  // There is no third parameter.
    ///
    /// let unknown = Message::parse("waitwhat #admin hello there")
    ///     .unwrap().unwrap();
    ///
    /// assert_eq!(unknown.prefix(), None);
    /// assert_eq!(unknown.command(), Err("waitwhat"));  // Unknown command.
    /// ```
    ///
    /// # Return value
    ///
    /// Returns `Ok(Some(msg))` when the message is correctly formed, `Ok(None)` when the message
    /// is empty (see note below), and `Err(())` when the message is invalid (has a prefix but no
    /// command).
    ///
    /// **Note:** An empty message doesn't mean just "\r\n", but actually any whitespace string.
    /// For example:
    ///
    /// ```rust
    /// use ellidri::message::Message;
    ///
    /// let empty = Message::parse("  \r \n \t ");
    ///
    /// assert!(empty.unwrap().is_none());
    /// ```
    pub fn parse<S>(s: S) -> Result<Option<Message<'a>>, ()>
        where S: Into<Cow<'a, str>>
    {
        let buf = s.into();

        // Split the buffer into words. This takes care of triming the "\r\n" at the end of `buf`,
        // and any additional whitespace between parameters, the command or the source.
        let mut words = buf.split_whitespace();

        let mut prefix = None;
        let command = if let Some(word) = words.next() {
            if word.starts_with(':') {
                // The first word is the prefix.
                let mut prefix_range = range_of(word, &buf);
                prefix_range.start += 1;  // Exclude the ':'
                prefix = Some(prefix_range);
                let word = words.next().ok_or(())?;
                parse_message_command(word, &buf)
            } else {
                // The first word is the command.
                parse_message_command(word, &buf)
            }
        } else {
            // There is no first word, the string is just whitespace.
            return Ok(None);
        };

        let first_param_index = if let Some(word) = words.next() {
            range_of(word, &buf).start
        } else {
            buf.len()
        };

        Ok(Some(Message {
            buf,
            prefix,
            command,
            first_param_index,
        }))
    }

    /// Returns the source of the message, if any.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ellidri::message::Message;
    ///
    /// let with = Message::parse(":botte PRIVMSG #agora :I'm listening")
    ///     .unwrap().unwrap();
    /// let without = Message::parse("JOIN #agora")
    ///     .unwrap().unwrap();
    ///
    /// assert_eq!(with.prefix(), Some("botte"));
    /// assert_eq!(without.prefix(), None);
    /// ```
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_ref().map(|range| &self.buf[range.clone()])
    }

    /// Either returns the `Command` variant of this message, or returns the raw command string if
    /// it's unknown.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ellidri::message::{Command, Message};
    ///
    /// let known = Message::parse("JOIN #minecraft")
    ///     .unwrap().unwrap();
    /// let unknown = Message::parse("MaliCIOUS #h4ck3R")
    ///     .unwrap().unwrap();
    ///
    /// assert_eq!(known.command(), Ok(Command::Join));
    /// // The case is the same because it's a reference
    /// // to the string passed to `Message::parse`.
    /// assert_eq!(unknown.command(), Err("MaliCIOUS"));
    /// ```
    pub fn command(&self) -> Result<Command, &str> {
        match self.command {
            Ok(cmd) => Ok(cmd),
            Err(ref range) => Err(&self.buf[range.clone()]),
        }
    }

    /// Returns an iterator over the parameters.
    ///
    /// The iterator parses parts of the message buffer at each `.next()` call, returning the next
    /// parameter.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ellidri::message::{Command, Message, rpl};
    ///
    /// let msg = Message::with_prefix("server.org", Command::Reply(rpl::WELCOME))
    ///     .param("*")
    ///     .trailing_param("Welcome, user");
    /// let mut params = msg.params();
    ///
    /// assert_eq!(params.next(), Some("*"));
    /// assert_eq!(params.next(), Some("Welcome, user"));
    /// assert_eq!(params.next(), None);
    /// ```
    pub fn params(&self) -> Params<'_> {
        Params {
            buf: self.buf[self.first_param_index..].trim_end(),
        }
    }

    /// Returns true if the message has enough parameters for its command.
    ///
    /// Also returns true if the message has too much parameters for its command. false is only
    /// returned when there's not enough of them.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ellidri::message::Message;
    ///
    /// let nick = Message::parse("NICK i suck dice").unwrap().unwrap();
    /// assert_eq!(nick.has_enough_params(), true);
    ///
    /// let nick = Message::parse("NICK :").unwrap().unwrap();
    /// assert_eq!(nick.has_enough_params(), true);
    ///
    /// let nick = Message::parse("NICK").unwrap().unwrap();
    /// assert_eq!(nick.has_enough_params(), false);
    /// ```
    pub fn has_enough_params(&self) -> bool {
        match self.command {
            Ok(cmd) => cmd.required_params() <= self.params().count(),
            Err(_) => false,
        }
    }

    /// Unwraps the underlying string, and clone it if it is not owned.
    pub fn into_bytes(self) -> Arc<[u8]> {
        self.buf.into_owned().into_bytes().into()
    }
}

impl fmt::Display for Message<'_> {
    /// Displays the message as a correctly formed message. Used for logging.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.buf.trim_end())
    }
}

const SANITIZED_CHAR: char = '_';

fn sanitize_param(c: char) -> char {
    match c {
        w if w.is_whitespace() => SANITIZED_CHAR,
        c => c,
    }
}

fn sanitize_trailing_param(c: char) -> char {
    match c {
        '\r' | '\n' => SANITIZED_CHAR,
        c => c,
    }
}

/// Helper to build progressively an IRC message. Use with `Message::with_prefix`.
pub struct MessageBuilder {
    buf: String,
    prefix: Option<Range<usize>>,
    command: Command,
    first_param_index: usize,
}

impl MessageBuilder {
    fn with_prefix(prefix: &str, command: Command) -> MessageBuilder {
        let mut buf = String::with_capacity(MAX_MESSAGE_LENGTH);
        buf.push(':');
        buf.push_str(prefix);
        let prefix = Some(1..buf.len());
        buf.push(' ');
        buf.push_str(command.as_str());
        MessageBuilder {
            buf,
            prefix,
            command,
            first_param_index: 0,
        }
    }

    /// Returns the built message.
    pub fn build(mut self) -> Message<'static> {
        self.buf.push('\r');
        self.buf.push('\n');
        Message {
            buf: self.buf.into(),
            prefix: self.prefix,
            command: Ok(self.command),
            first_param_index: self.first_param_index,
        }
    }

    /// Add a middle (not trailing) parameter to the message.
    ///
    /// # Panics
    ///
    /// Panics if the parameter contains whitespace or starts with ':'.
    pub fn param<S>(mut self, param: S) -> MessageBuilder
        where S: AsRef<str>
    {
        let param = param.as_ref();
        if param.is_empty() {
            return self;
        }
        self.buf.push(' ');
        if self.first_param_index == 0 {
            self.first_param_index = self.buf.len();
        }
        if param.starts_with(':') {
            self.buf.push('_');
        } else {
            self.buf.push(param.chars().next().unwrap());
        }
        self.buf.extend(param.chars().skip(1).map(sanitize_param));
        self
    }

    /// Add a trailing parameter and build the message.
    pub fn trailing_param<S>(mut self, trailing: S) -> Message<'static>
        where S: AsRef<str>
    {
        let trailing = trailing.as_ref();
        self.buf.push(' ');
        self.buf.push(':');
        if self.first_param_index == 0 {
            self.first_param_index = self.buf.len();
        }
        self.buf.extend(trailing.chars().map(sanitize_trailing_param));
        self.build()
    }
}

pub struct MessageBuffer<'a> {
    buf: &'a mut String,
}

impl<'a> MessageBuffer<'a> {
    fn with_prefix<C>(buf: &'a mut String, prefix: &str, command: C) -> MessageBuffer<'a>
        where C: Into<Command>
    {
        buf.push(':');
        buf.push_str(prefix);
        buf.push(' ');
        buf.push_str(command.into().as_str());
        MessageBuffer { buf }
    }

    pub fn build(self) {
        self.buf.push('\r');
        self.buf.push('\n');
    }

    pub fn param<S>(self, param: S) -> MessageBuffer<'a>
        where S: AsRef<str>
    {
        let param = param.as_ref();
        if param.is_empty() {
            return self;
        }
        self.buf.push(' ');
        if param.starts_with(':') {
            self.buf.push('_');
        } else {
            self.buf.push(param.chars().next().unwrap());
        }
        self.buf.extend(param.chars().skip(1).map(sanitize_param));
        self
    }

    pub fn trailing_param<S>(self, param: S)
        where S: AsRef<str>
    {
        let param = param.as_ref();
        self.buf.push(' ');
        self.buf.push(':');
        self.buf.extend(param.chars().map(sanitize_trailing_param));
        self.build()
    }

    pub fn raw_param(&mut self) -> &mut String {
        self.buf.push(' ');
        &mut self.buf
    }

    pub fn raw_trailing_param(&mut self) -> &mut String {
        self.buf.push(' ');
        self.buf.push(':');
        &mut self.buf
    }
}

#[derive(Debug, Default)]
pub struct ResponseBuffer {
    buf: String,
}

impl ResponseBuffer {
    pub fn new() -> ResponseBuffer {
        ResponseBuffer::default()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn message<C>(&mut self, prefix: &str, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        MessageBuffer::with_prefix(&mut self.buf, prefix, command)
    }

    pub fn list<I, F>(&mut self, prefix: &str, item_reply: Reply, end_reply: Reply,
                      end_line: &str, list: I, mut map: F)
        where I: IntoIterator,
              I::Item: AsRef<str>,
              F: FnMut(MessageBuffer<'_>) -> MessageBuffer<'_>
    {
        for item in list {
            map(self.message(prefix, item_reply))
                .param(item)
                .build();
        }
        map(self.message(prefix, end_reply))
            .trailing_param(end_line);
    }

    pub fn build(self) -> Arc<[u8]> {
        // TODO don't fcking vv clone vv the fucking whole buffer just to have a god damn Arc
        self.buf.into_bytes()  .into()
    }
}
