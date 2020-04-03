//! The list of IRC replies.
//!
//! Each reply must have the client's nick as first parameter.
//!
//! Sources:
//!
//! - <https://tools.ietf.org/html/rfc2812.html#section-5>
//! - <https://modern.ircdocs.horse/#numerics>

pub const WELCOME: &str   = "001";  // :Welcome message
pub const YOURHOST: &str  = "002";  // :Your host is...
pub const CREATED: &str   = "003";  // :This server was created...
pub const MYINFO: &str    = "004";  // <servername> <version> <umodes> <chan modes> <chan modes with a parameter>
pub const ISUPPORT: &str  = "005";  // 1*13<TOKEN[=value]> :are supported by this server

pub const UMODEIS: &str       = "221";  // <modes>
pub const LUSERCLIENT: &str   = "251";  // :<int> users and <int> services on <int> servers
pub const LUSEROP: &str       = "252";  // <int> :operator(s) online
pub const LUSERUNKNOWN: &str  = "253";  // <int> :unknown connection(s)
pub const LUSERCHANNELS: &str = "254";  // <int> :channels formed
pub const LUSERME: &str       = "255";  // :I have <int> clients and <int> servers
pub const ADMINME: &str       = "256";  // <server> :Admin info
pub const ADMINLOC1: &str     = "257";  // :<info>
pub const ADMINLOC2: &str     = "258";  // :<info>
pub const ADMINMAIL: &str     = "259";  // :<info>

pub const AWAY: &str            = "301";  // <nick> :<away message>
pub const UNAWAY: &str          = "305";  // :You are no longer marked as being away
pub const NOWAWAY: &str         = "306";  // :You have been marked as being away
pub const WHOISUSER: &str       = "311";  // <nick> <user> <host> * :<realname>
pub const WHOISSERVER: &str     = "312";  // <nick> <server> :<server info>
pub const WHOISOPERATOR: &str   = "313";  // <nick> :is an IRC operator
pub const ENDOFWHO: &str        = "315";  // <name> :End of WHO list
pub const WHOISIDLE: &str       = "317";  // <nick> <integer> [<integer>] :seconds idle [, signon time]
pub const ENDOFWHOIS: &str      = "318";  // <nick> :End of WHOIS list
pub const WHOISCHANNELS: &str   = "319";  // <nick> :*( (@/+) <channel> " " )
pub const LIST: &str            = "322";  // <channel> <# of visible members> <topic>
pub const LISTEND: &str         = "323";  // :End of list
pub const CHANNELMODEIS: &str   = "324";  // <channel> <modes> <mode params>
pub const NOTOPIC: &str         = "331";  // <channel> :No topic set
pub const TOPIC: &str           = "332";  // <channel> <topic>
pub const INVITING: &str        = "341";  // <nick> <channel>
pub const INVITELIST: &str      = "346";  // <channel> <invite mask>
pub const ENDOFINVITELIST: &str = "347";  // <channel> :End of invite list
pub const EXCEPTLIST: &str      = "348";  // <channel> <exception mask>
pub const ENDOFEXCEPTLIST: &str = "349";  // <channel> :End of exception list
pub const VERSION: &str         = "351";  // <version> <servername> :<comments>
pub const WHOREPLY: &str        = "352";  // <channel> <user> <host> <server> <nick> "H"/"G" ["*"] [("@"/"+")] :<hop count> <nick>
pub const NAMREPLY: &str        = "353";  // <=/*/@> <channel> :1*(@/ /+user)
pub const ENDOFNAMES: &str      = "366";  // <channel> :End of names list
pub const BANLIST: &str         = "367";  // <channel> <ban mask>
pub const ENDOFBANLIST: &str    = "368";  // <channel> :End of ban list
pub const INFO: &str            = "371";  // :<info>
pub const MOTD: &str            = "372";  // :- <text>
pub const ENDOFINFO: &str       = "374";  // :End of INFO
pub const MOTDSTART: &str       = "375";  // :- <servername> Message of the day -
pub const ENDOFMOTD: &str       = "376";  // :End of MOTD command
pub const YOUREOPER: &str       = "381";  // :You are now an operator
pub const TIME: &str            = "391";  // <servername> :<time in whatever format>

pub const ERR_NOSUCHNICK: &str       = "401";  // <nick> :No such nick/channel
pub const ERR_NOSUCHCHANNEL: &str    = "403";  // <channel> :No such channel
pub const ERR_CANNOTSENDTOCHAN: &str = "404";  // <channel> :Cannot send to channel
pub const ERR_INVALIDCAPCMD: &str    = "410";  // <command> :Unknown cap command
pub const ERR_NORECIPIENT: &str      = "411";  // :No recipient given
pub const ERR_NOTEXTTOSEND: &str     = "412";  // :No text to send
pub const ERR_INPUTTOOLONG: &str     = "417";  // :Input line was too long
pub const ERR_UNKNOWNCOMMAND: &str   = "421";  // <command> :Unknown command
pub const ERR_NOMOTD: &str           = "422";  // :MOTD file missing
pub const ERR_NONICKNAMEGIVEN: &str  = "431";  // :No nickname given
pub const ERR_ERRONEUSNICKNAME: &str = "432";  // <nick> :Erroneous nickname
pub const ERR_NICKNAMEINUSE: &str    = "433";  // <nick> :Nickname in use
pub const ERR_USERNOTINCHANNEL: &str = "441";  // <nick> <channel> :User not in channel
pub const ERR_NOTONCHANNEL: &str     = "442";  // <channel> :You're not on that channel
pub const ERR_USERONCHANNEL: &str    = "443";  // <user> <channel> :is already on channel
pub const ERR_NOTREGISTERED: &str    = "451";  // :You have not registered
pub const ERR_NEEDMOREPARAMS: &str   = "461";  // <command> :Not enough parameters
pub const ERR_ALREADYREGISTRED: &str = "462";  // :Already registered
pub const ERR_PASSWDMISMATCH: &str   = "464";  // :Password incorrect
pub const ERR_YOUREBANNEDCREEP: &str = "465";  // :You're banned from this server
pub const ERR_KEYSET: &str           = "467";  // <channel> :Channel key already set
pub const ERR_CHANNELISFULL: &str    = "471";  // <channel> :Cannot join channel (+l)
pub const ERR_UNKNOWNMODE: &str      = "472";  // <char> :Don't know this mode for <channel>
pub const ERR_INVITEONLYCHAN: &str   = "473";  // <channel> :Cannot join channel (+I)
pub const ERR_BANNEDFROMCHAN: &str   = "474";  // <channel> :Cannot join channel (+b)
pub const ERR_BADCHANKEY: &str       = "475";  // <channel> :Cannot join channel (+k)
pub const ERR_CHANOPRIVSNEEDED: &str = "482";  // <channel> :You're not an operator

pub const ERR_UMODEUNKNOWNFLAG: &str = "501";  // :Unknown mode flag
pub const ERR_USERSDONTMATCH: &str   = "502";  // :Can't change mode for other users

pub const LOGGEDIN: &str        = "900";  // <nick> <nick>!<ident>@<host> <account> :You are now logged in as <user>
pub const LOGGEDOUT: &str       = "901";  // <nick> <nick>!<ident>@<host> :You are now logged out
pub const ERR_NICKLOCKED: &str  = "902";  // :You must use a nick assigned to you
pub const SASLSUCCESS: &str     = "903";  // :SASL authentication successful
pub const ERR_SASLFAIL: &str    = "904";  // :SASL authentication failed
pub const ERR_SASLTOOLONG: &str = "905";  // :SASL message too long
pub const ERR_SASLABORTED: &str = "906";  // :SASL authentication aborted
pub const ERR_SASLALREADY: &str = "907";  // :You have already authenticated using SASL
pub const SASLMECHS: &str       = "908";  // <mechanisms> :are available SASL mechanisms
