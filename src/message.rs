//! Message parsing and building.

pub use rpl::Reply;
use std::cell::RefCell;
use std::fmt;

/// The recommended length of a message.
///
/// `Message::parse` can parse messages longer than that.  It is used by `Buffer` to avoid multiple
/// allocations when building the same message.
pub const MESSAGE_LENGTH: usize = 512;

/// The number of elements in `Message::params`.
pub const PARAMS_LENGTH: usize = 15;

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

    pub const AWAY: Reply            = "301";  // <nick> :<away message>
    pub const UNAWAY: Reply          = "305";  // :You are no longer marked as being away
    pub const NOWAWAY: Reply         = "306";  // :You have been marked as being away
    pub const WHOISUSER: Reply       = "311";  // <nick> <user> <host> * :<realname>
    pub const WHOISSERVER: Reply     = "312";  // <nick> <server> :<server info>
    pub const WHOISOPERATOR: Reply   = "313";  // <nick> :is an IRC operator
    pub const ENDOFWHO: Reply        = "315";  // <name> :End of WHO list
    pub const WHOISIDLE: Reply       = "317";  // <nick> <integer> [<integer>] :seconds idle [, signon time]
    pub const ENDOFWHOIS: Reply      = "318";  // <nick> :End of WHOIS list
    pub const WHOISCHANNELS: Reply   = "319";  // <nick> :*( (@/+) <channel> " " )
    pub const LIST: Reply            = "322";  // <channel> <# of visible members> <topic>
    pub const LISTEND: Reply         = "323";  // :End of list
    pub const CHANNELMODEIS: Reply   = "324";  // <channel> <modes> <mode params>
    pub const NOTOPIC: Reply         = "331";  // <channel> :No topic set
    pub const TOPIC: Reply           = "332";  // <channel> <topic>
    pub const INVITING: Reply        = "341";  // <nick> <channel>
    pub const INVITELIST: Reply      = "346";  // <channel> <invite mask>
    pub const ENDOFINVITELIST: Reply = "347";  // <channel> :End of invite list
    pub const EXCEPTLIST: Reply      = "348";  // <channel> <exception mask>
    pub const ENDOFEXCEPTLIST: Reply = "349";  // <channel> :End of exception list
    pub const VERSION: Reply         = "351";  // <version> <servername> :<comments>
    pub const WHOREPLY: Reply        = "352";  // <channel> <user> <host> <server> <nick> "H"/"G" ["*"] [("@"/"+")] :<hop count> <nick>
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
    pub const ERR_INPUTTOOLONG: Reply     = "417";  // :Input line was too long
    pub const ERR_UNKNOWNCOMMAND: Reply   = "421";  // <command> :Unknown command
    pub const ERR_NOMOTD: Reply           = "422";  // :MOTD file missing
    pub const ERR_NONICKNAMEGIVEN: Reply  = "431";  // :No nickname given
    pub const ERR_ERRONEUSNICKNAME: Reply = "432";  // <nick> :Erroneous nickname
    pub const ERR_NICKNAMEINUSE: Reply    = "433";  // <nick> :Nickname in use
    pub const ERR_USERNOTINCHANNEL: Reply = "441";  // <nick> <channel> :User not in channel
    pub const ERR_NOTONCHANNEL: Reply     = "442";  // <channel> :You're not on that channel
    pub const ERR_USERONCHANNEL: Reply    = "443";  // <user> <channel> :is already on channel
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

    pub const LOGGEDIN: Reply        = "900";  // <nick> <nick>!<ident>@<host> <account> :You are now logged in as <user>
    pub const LOGGEDOUT: Reply       = "901";  // <nick> <nick>!<ident>@<host> :You are now logged out
    pub const ERR_NICKLOCKED: Reply  = "902";  // :You must use a nick assigned to you
    pub const SASLSUCCESS: Reply     = "903";  // :SASL authentication successful
    pub const ERR_SASLFAIL: Reply    = "904";  // :SASL authentication failed
    pub const ERR_SASLTOOLONG: Reply = "905";  // :SASL message too long
    pub const ERR_SASLABORTED: Reply = "906";  // :SASL authentication aborted
    pub const ERR_SASLALREADY: Reply = "907";  // :You have already authenticated using SASL
    pub const SASLMECHS: Reply       = "908";  // <mechanisms> :are available SASL mechanisms
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

// TODO tag_value_unescape

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
    pub fn parse(buf: &'a str) -> Self {
        let mut split = buf.splitn(2, '=');
        let key = split.next().unwrap();
        let value = match split.next() {
            Some("") | None => None,
            Some(other) => if other.ends_with('\\') {
                Some(&other[..other.len() - 1])
            } else {
                Some(other)
            }
        };
        let is_client = key.starts_with('+');
        Self {
            key: if is_client {&key[1..]} else {key},
            value,
            is_client,
        }
    }
}

pub fn tags(s: &str) -> impl Iterator<Item=Tag<'_>> {
    s.split(';').map(|item| Tag::parse(item))
}

macro_rules! commands {
    ( $( $cmd:ident $cmd_str:literal $n:literal )* ) => {
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
            /// let not_join = Command::parse("not_join");
            ///
            /// assert_eq!(join, Some(Command::Join));
            /// assert_eq!(join2, Some(Command::Join));
            /// assert_eq!(not_join, None);
            /// ```
            pub fn parse(s: &str) -> Option<Self> {
                $( if s.eq_ignore_ascii_case($cmd_str) {
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
            /// let quit = Command::parse("Quit").unwrap();
            ///
            /// assert_eq!(quit.as_str(), "QUIT");
            /// ```
            pub fn as_str(&self) -> &'static str {
                match self {
                $(
                    Command::$cmd => $cmd_str,
                )*
                    Command::Reply(s) => s,
                }
            }
        }

        impl From<&'static str> for Command {
            /// `&'static str`s are converted to the `Command::Reply` variant.
            ///
            /// This trait is used by `Buffer` to accept both `Command` and `Reply` when
            /// building messages.
            fn from(reply: &'static str) -> Self {
                Command::Reply(reply)
            }
        }

        impl fmt::Display for Command {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.as_str().fmt(f)
            }
        }
    }
}

commands! {
//  Ident.   String     Minimum # of params
    Admin    "ADMIN"    0
    Authenticate "AUTHENTICATE" 1
    Away     "AWAY"     0
    Cap      "CAP"      1
    Info     "INFO"     0
    Invite   "INVITE"   2
    Join     "JOIN"     1
    Kick     "KICK"     2
    List     "LIST"     0
    Lusers   "LUSERS"   0
    Mode     "MODE"     1
    Motd     "MOTD"     0
    Names    "NAMES"    0
    Nick     "NICK"     1
    Notice   "NOTICE"   2
    Oper     "OPER"     2
    Part     "PART"     1
    Pass     "PASS"     1
    Ping     "PING"     1
    Pong     "PONG"     1
    PrivMsg  "PRIVMSG"  2
    Quit     "QUIT"     0
    SetName  "SETNAME"  1
    TagMsg   "TAGMSG"   1
    Time     "TIME"     0
    Topic    "TOPIC"    1
    User     "USER"     4
    Version  "VERSION"  0
    Who      "WHO"      0
    Whois    "WHOIS"    1
}

/// Assert all data of a message.
///
/// Empty elements in `params` will not be asserted with their equivalent in `msg.params`, but will
/// still count for the assertion of the number of parameters.
pub fn assert_msg(msg: &Message<'_>, prefix: Option<&str>, command: Result<Command, &str>,
                  params: &[&str])
{
    assert_eq!(msg.prefix, prefix, "prefix of {:?}", msg);
    assert_eq!(msg.command, command, "command of {:?}", msg);
    assert_eq!(msg.num_params, params.len(), "number of parameters of {:?}", msg);
    for (i, (actual, expected)) in msg.params.iter().zip(params.iter()).enumerate() {
        if expected.is_empty() {
            // Some parameters may be of different form every time they are generated (e.g.
            // NAMREPLY params, since the order comes from `HashMap::iter`), so we skip them.
            continue;
        }
        assert_eq!(actual, expected, "parameter #{} of {:?}", i, msg);
    }
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
/// Created by `Buffer::message` and `Buffer::message`.
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
    /// # use ellidri::message::{Command, Buffer};
    /// let mut response = Buffer::new();
    ///
    /// response.message("nick!user@127.0.0.1", Command::Quit)
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
    /// # use ellidri::message::{Command, Buffer};
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
    /// `param` is whitespace, it is not appended.
    ///
    /// **Note**: It is up to the caller to make sure there is no newline in the parameter.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{Command, Buffer};
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
    /// # use ellidri::message::{Command, Buffer};
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
    /// # use ellidri::message::{Buffer, rpl};
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

pub struct TagBuffer<'a> {
    buf: &'a mut String,
    tag_start: usize,
}

impl<'a> TagBuffer<'a> {
    fn new(buf: &'a mut String) -> Self {
        buf.reserve(MESSAGE_LENGTH);
        let tag_start = buf.len();
        buf.push('@');
        TagBuffer {
            buf,
            tag_start,
        }
    }

    fn is_empty(&self) -> bool {
        self.buf.len() == self.tag_start + 1
    }

    pub fn tag(self, key: &str, value: Option<&str>) -> Self {
        if !self.is_empty() {
            self.buf.push(';');
        }
        self.buf.push_str(key);
        if let Some(value) = value {
            self.buf.push('=');
            self.buf.push_str(value);
        }
        self
    }

    fn raw_tag(self, s: &str) -> Self {
        if !self.is_empty() {
            self.buf.push(';');
        }
        self.buf.push_str(s);
        self
    }

    pub fn save_tags_len(self, out: &mut usize) -> Self {
        if self.buf.ends_with('@') {
            *out = 0;
        } else {
            *out = self.buf.len() + 1 - self.tag_start;
        }
        self
    }

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
/// # use ellidri::message::{Command, Buffer, rpl};
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
    /// # use ellidri::message::{Command, Buffer};
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
    /// # use ellidri::message::{Command, Buffer};
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
            .filter(|s| s.starts_with('+'))
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
}

/// An helper to build IRC replies.
///
/// IRC replies are IRC messages that have the domain of the server as prefix, and the nickname of
/// the client as first parameter.
///
/// # Example
///
/// ```rust
/// # use ellidri::message::{Command, ReplyBuffer, rpl};
/// let mut response = ReplyBuffer::new("ellidri.dev", "nickname");
///
/// response.message("nick!user@127.0.0.1", Command::Topic)
///     .param("#hall")
///     .trailing_param("Welcome to new users!");
/// response.reply(rpl::TOPIC)
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
/// Allocation only occurs on `ReplyBuffer::reply` and `ReplyBuffer::message` calls.  These
/// functions reseve `MESSAGE_LENGTH` prior to writing on the internal buffer.
///
/// # Usage note
///
/// This buffer uses thread-local storage to store the domain and the nickname, to reduce the
/// number of allocations.  Therefore, the user must not make two `ReplyBuffer`s at the same time,
/// otherwise nicknames and domains will be mixed.
pub struct ReplyBuffer {
    buf: Buffer,
}

impl ReplyBuffer {
    /// Creates a new `ReplyBuffer` and initialize the thread-local storage with the given domain
    /// and nickname.
    pub fn new(domain: &str, nickname: &str) -> Self {
        DOMAIN.with(|s| {
            let mut s = s.borrow_mut();
            s.clear();
            s.push_str(domain);
        });
        let mut res = Self {
            buf: Buffer::new(),
        };
        res.set_nick(nickname);
        res
    }

    /// Whether the buffer has messages in it or not.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{ReplyBuffer, rpl};
    /// let empty = ReplyBuffer::new("ellidri.dev", "ser");
    /// let mut not_empty = ReplyBuffer::new("ellidri.dev", "ser");
    ///
    /// not_empty.reply(rpl::ERR_NOMOTD);
    ///
    /// assert_eq!(empty.is_empty(), true);
    /// assert_eq!(not_empty.is_empty(), false);
    /// ```
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn set_nick(&mut self, nickname: &str) {
        NICKNAME.with(|n| {
            let mut n = n.borrow_mut();
            n.clear();
            n.push_str(nickname);
        });
    }

    /// Appends a reply to the buffer.
    ///
    /// This will push the domain, the reply and the nickname of the client, and then return the
    /// resulting `MessageBuffer`.
    ///
    /// This function may allocate to reserve space for the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{Command, ReplyBuffer, rpl};
    /// let mut response = ReplyBuffer::new("ellidri.dev", "ser");
    ///
    /// response.reply(rpl::WELCOME).trailing_param("Welcome to IRC, ser");
    ///
    /// assert_eq!(&response.build(), ":ellidri.dev 001 ser :Welcome to IRC, ser\r\n");
    /// ```
    pub fn reply<C>(&mut self, r: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        let msg = DOMAIN.with(move |s| self.buf.message(&s.borrow(), r));
        NICKNAME.with(|s| msg.param(&s.borrow()))
    }

    /// Appends a prefixed message like you would do with a `Buffer`.
    ///
    /// This function may allocate to reserve space for the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use ellidri::message::{Command, ReplyBuffer};
    /// let mut response = ReplyBuffer::new("ellidri.dev", "ser");
    ///
    /// response.message("unneeded_prefix", Command::Admin);
    ///
    /// assert_eq!(&response.build(), ":unneeded_prefix ADMIN\r\n");
    /// ```
    pub fn message<C>(&mut self, prefix: &str, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        self.buf.message(prefix, command)
    }

    /// Consumes the buffer and returns the underlying `String`.
    pub fn build(self) -> String {
        self.buf.build()
    }
}
