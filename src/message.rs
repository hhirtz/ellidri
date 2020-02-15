pub use rpl::Reply;

const MAX_MESSAGE_LENGTH: usize = 512;
const MAX_PARAMS: usize = 15;

/// The list of IRC replies.
///
/// Source: <https://tools.ietf.org/html/rfc2812.html#section-5>
pub mod rpl {
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

    pub const ENDOFWHO: Reply        = "315";  // <name> :End of WHO list
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

fn parse_word(s: &str) -> (&str, &str) {
    let mut split = s.splitn(2, ' ')
        .map(str::trim)
        .filter(|s| !s.is_empty());
    (split.next().unwrap_or(""), split.next().unwrap_or(""))
}

fn parse_tags(buf: &str) -> (Tags<'_>, &str) {
    if buf.starts_with('@') {
        let (tags, rest) = parse_word(buf);
        (Tags { buf: &tags[1..] }, rest)
    } else {
        (Tags { buf: "" }, buf)
    }
}

fn parse_prefix(buf: &str) -> (Option<&str>, &str) {
    if buf.starts_with(':') {
        let (prefix, rest) = parse_word(buf);
        (Some(&prefix[1..]), rest)
    } else {
        (None, buf.trim_start())
    }
}

fn parse_command(buf: &str) -> (Result<Command, &str>, &str) {
    let (command_string, rest) = parse_word(buf);
    (Command::parse(command_string).ok_or(command_string), rest)
}

pub struct Tag<'a> {
    pub key: &'a str,
    pub value: Option<&'a str>,
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

        impl From<&'static str> for Command {
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
}

pub struct Message<'a> {
    pub tags: Tags<'a>,
    pub prefix: Option<&'a str>,
    pub command: Result<Command, &'a str>,
    pub num_params: usize,
    pub params: [&'a str; MAX_PARAMS],
}

impl<'a> Message<'a> {
    /// Parse a string and store information about the IRC message.
    ///
    /// Relevant source of information:
    /// https://tools.ietf.org/html/rfc2812.html#section-2.3
    ///
    /// # Return value
    ///
    /// Returns `Ok(Some(msg))` when the message is correctly formed, `Ok(None)` when the message
    /// is empty (see note below), and `Err(())` when the message is invalid (has no command).
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
    /// use ellidri::message::Message;
    ///
    /// let nick = Message::parse("NICK hello there").unwrap().unwrap();
    /// assert_eq!(nick.has_enough_params(), true);
    ///
    /// let nick = Message::parse("NICK :").unwrap().unwrap();
    /// assert_eq!(nick.has_enough_params(), false);
    ///
    /// let nick = Message::parse("NICK").unwrap().unwrap();
    /// assert_eq!(nick.has_enough_params(), false);
    /// ```
    pub fn has_enough_params(&self) -> bool {
        match self.command {
            Ok(cmd) => cmd.required_params() <= self.num_params,
            Err(_) => false,
        }
    }
}

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

    pub fn trailing_param(self, param: &str)
    {
        self.buf.push(' ');
        self.buf.push(':');
        self.buf.push_str(param);
    }

    pub fn raw_param(&mut self) -> &mut String {
        self.buf.push(' ');
        self.buf
    }

    pub fn raw_trailing_param(&mut self) -> &mut String {
        self.buf.push(' ');
        self.buf.push(':');
        self.buf
    }
}

impl<'a> Drop for MessageBuffer<'a> {
    fn drop(&mut self) {
        self.buf.push('\r');
        self.buf.push('\n');
    }
}

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
    pub fn new() -> Self {
        Self {
            buf: String::with_capacity(MAX_MESSAGE_LENGTH),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn message<C>(&mut self, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        MessageBuffer::new(&mut self.buf, command)
    }

    pub fn prefixed_message<C>(&mut self, prefix: &str, command: C) -> MessageBuffer<'_>
        where C: Into<Command>
    {
        MessageBuffer::with_prefix(&mut self.buf, prefix, command)
    }

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

    pub fn build(self) -> Vec<u8> {
        self.buf.into_bytes()
    }
}
