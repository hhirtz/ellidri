use std::fmt;

macro_rules! commands {
    ( $( $cmd:ident $cmd_str:literal $n:literal )* ) => {
        /// The list of known commands.
        ///
        /// Unknown commands and replies are supported by `Message` directly, this enum just
        /// contains the supported commands.
        #[derive(Clone, Copy, Debug, PartialEq)]
        pub enum Command {
            $( $cmd, )*
            Reply(&'static str),
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
            /// # use ellidri_tokens::Command;
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
            /// # use ellidri_tokens::Command;
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
            /// # use ellidri_tokens::Command;
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
    Rehash   "REHASH"   0
    SetName  "SETNAME"  1
    TagMsg   "TAGMSG"   1
    Time     "TIME"     0
    Topic    "TOPIC"    1
    User     "USER"     4
    Version  "VERSION"  0
    Who      "WHO"      0
    Whois    "WHOIS"    1
}
