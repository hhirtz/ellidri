use ellidri_tokens::Command;
use std::convert::TryFrom;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V300,
    V302,
}

impl<'a> From<&'a str> for Version {
    fn from(val: &'a str) -> Self {
        match val {
            "302" => Self::V302,
            _ => Self::V300,
        }
    }
}

macro_rules! caps {
    ( $( $cap:ident    $cap_str:literal    $cap_member:ident    )* |
      $( $specap:ident $specap_str:literal $specap_member:ident )*
    ) => {
        $( pub const $cap: &str = $cap_str; )*
        $( pub const $specap: &str = $specap_str; )*

        const _LS_COMMON: &str = concat!( $( $cap_str, " " ),* );

        pub fn ls_common() -> &'static str {
            &_LS_COMMON[.._LS_COMMON.len() - 1]
        }

        pub fn query(buf: &str) -> impl Iterator<Item=(&str, bool)> {
            buf.split_whitespace().map(|word| {
                if word.starts_with('-') {
                    (&word[1..], false)
                } else {
                    (word, true)
                }
            })
        }

        #[derive(Clone, Copy, Debug, Default)]
        pub struct Diff {
            $( pub $cap_member: Option<bool>, )*
            $( pub $specap_member: Option<bool>, )*
        }

        impl Diff {
            pub fn write(&self, buf: &mut String) {
                let len = buf.len();
            $(
                if let Some(enable) = self.$cap_member {
                    if !enable {
                        buf.push('-');
                    }
                    buf.push_str($cap);
                    buf.push(' ');
                }
            )*
            $(
                if let Some(enable) = self.$specap_member {
                    if !enable {
                        buf.push('-');
                    }
                    buf.push_str($specap);
                    buf.push(' ');
                }
            )*
                if len < buf.len() { buf.pop(); }
            }
        }

        impl<'a> TryFrom<&'a str> for Diff {
            type Error = super::Error<'static>;

            fn try_from(val: &'a str) -> Result<Self, Self::Error> {
                let mut res = Self::default();
                for (capability, enable) in query(val) {
                    match capability {
                    $(
                        $cap => res.$cap_member = Some(enable),
                    )*
                    $(
                        $specap => res.$specap_member = Some(enable),
                    )*
                        _ => return Err(super::Error::InvalidCap),
                    }
                }
                Ok(res)
            }
        }

        #[derive(Clone, Copy, Default)]
        pub struct Capabilities {
            $( pub $cap_member: bool, )*
            $( pub $specap_member: bool, )*
        }

        impl Capabilities {
            pub fn update(&mut self, diff: Diff) {
            $(
                if let Some(change) = diff.$cap_member {
                    self.$cap_member = change;
                }
            )*
            $(
                if let Some(change) = diff.$specap_member {
                    self.$specap_member = change;
                }
            )*
            }

            pub fn write(&self, buf: &mut String) {
                let len = buf.len();
            $(
                if self.$cap_member {
                    buf.push_str($cap);
                    buf.push(' ');
                }
            )*
            $(
                if self.$specap_member {
                    buf.push_str($specap);
                    buf.push(' ');
                }
            )*
                if len < buf.len() { buf.pop(); }
            }
        }
    };
}

caps! {
    ACCOUNT_NOTIFY    "account-notify"     account_notify
    ACCOUNT_TAG       "account-tag"        account_tag
    AWAY_NOTIFY       "away-notify"        away_notify
    BATCH             "batch"              batch
    CAP_NOTIFY        "cap-notify"         cap_notify
    ECHO_MESSAGE      "echo-message"       echo_message
    EXTENDED_JOIN     "extended-join"      extended_join
    INVITE_NOTIFY     "invite-notify"      invite_notify
    LABELED_RESPONSE  "labeled-response"   labeled_response
    MESSAGE_TAGS      "message-tags"       message_tags
    MULTI_PREFIX      "multi-prefix"       multi_prefix
    SERVER_TIME       "server-time"        server_time
    SETNAME           "setname"            setname
    USERHOST_IN_NAMES "userhost-in-names"  userhost_in_names
    |
    SASL "sasl" sasl
}

impl Capabilities {
    pub fn has_message_tags(&self) -> bool {
        self.message_tags || self.server_time
    }

    pub fn is_capable_of(&self, command: Command) -> bool {
        match command {
            Command::Authenticate => self.sasl,
            Command::SetName => self.setname,
            Command::TagMsg => self.message_tags,
            _ => true,
        }
    }
}
