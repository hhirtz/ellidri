use crate::message::{MessageBuffer, Reply, rpl};
use crate::modes;
use std::collections::{HashMap, HashSet};

/// Modes applied to clients on a per-channel basis.
///
/// <https://tools.ietf.org/html/rfc2811.html#section-4.1>
#[derive(Clone, Copy, Default)]
pub struct MemberModes {
    pub founder: bool,
    pub protected: bool,
    pub operator: bool,
    pub halfop: bool,
    pub voice: bool,
}

impl MemberModes {
    pub fn all_symbols(self, out: &mut String) {
        if self.founder { out.push('~'); }
        if self.protected { out.push('&'); }
        if self.operator { out.push('@'); }
        if self.halfop { out.push('%'); }
        if self.voice { out.push('+'); }
    }

    pub fn symbol(self) -> Option<char> {
        if self.founder {
            Some('~')
        } else if self.protected {
            Some('&')
        } else if self.operator {
            Some('@')
        } else if self.halfop {
            Some('%')
        } else if self.voice {
            Some('+')
        } else {
            None
        }
    }

    pub fn is_at_least_op(self) -> bool {
        self.operator || self.founder
    }

    pub fn is_at_least_halfop(self) -> bool {
        self.halfop || self.operator || self.founder
    }

    pub fn has_voice(self) -> bool {
        self.voice || self.halfop || self.operator || self.protected || self.founder
    }

    pub fn can_change(self, modes: &str) -> bool {
        use modes::ChannelModeChange::*;

        modes::simple_channel_query(modes).all(|mode| match mode {
            Err(_) => true,
            Ok(GetBans) | Ok(GetExceptions) | Ok(GetInvitations) => true,
            Ok(Moderated(_)) | Ok(TopicRestricted(_)) | Ok(UserLimit(_)) |
                Ok(ChangeBan(_, _)) | Ok(ChangeException(_, _)) |
                Ok(ChangeInvitation(_, _)) | Ok(ChangeVoice(_, _)) => self.is_at_least_halfop(),
            Ok(InviteOnly(_)) | Ok(NoPrivMsgFromOutside(_)) | Ok(Secret(_)) | Ok(Key(_, _)) |
                Ok(ChangeOperator(_, _)) | Ok(ChangeHalfop(_, _)) => self.is_at_least_op(),
        })
    }
}

/// Channel data.
#[derive(Default)]
pub struct Channel {
    /// Set of channel members, identified by their socket address, and associated with their
    /// channel mode.
    pub members: HashMap<usize, MemberModes>,

    /// Set of invited clients (via INVITE).
    pub invites: HashSet<usize>,

    /// The topic.
    pub topic: Option<String>,

    pub user_limit: Option<usize>,
    pub key: Option<String>,

    // TODO test performance with BTreeSet instead of HashSet

    // https://tools.ietf.org/html/rfc2811.html#section-4.3
    pub ban_mask: HashSet<String>,
    pub exception_mask: HashSet<String>,
    pub invitation_mask: HashSet<String>,

    // Modes: https://tools.ietf.org/html/rfc2811.html#section-4.2
    pub invite_only: bool,
    pub moderated: bool,
    pub no_privmsg_from_outside: bool,
    pub secret: bool,
    pub topic_restricted: bool,
}

impl Channel {
    /// Creates a channel with the given modes set.
    pub fn new(modes: &str) -> Self {
        let mut channel = Self::default();
        for change in modes::simple_channel_query(modes).filter_map(Result::ok) {
            channel.apply_mode_change(change, |_| "").unwrap();
        }
        channel
    }

    /// Adds a member with the default mode.
    pub fn add_member(&mut self, id: usize) {
        let modes = if self.members.is_empty() {
            MemberModes {
                founder: false,
                protected: false,
                operator: true,
                halfop: false,
                voice: false,
            }
        } else {
            MemberModes::default()
        };
        self.members.insert(id, modes);
        self.invites.remove(&id);
    }

    pub fn list_entry(&self, msg: MessageBuffer<'_>) {
        msg.param(&self.members.len().to_string())
            .trailing_param(self.topic.as_ref().map_or("", |s| s.as_ref()));
    }

    pub fn is_banned(&self, nick: &str) -> bool {
        self.ban_mask.contains(nick)
            && !self.exception_mask.contains(nick)
            && !self.invitation_mask.contains(nick)
    }

    pub fn is_invited(&self, id: usize, nick: &str) -> bool {
        !self.invite_only || self.invites.contains(&id) || self.invitation_mask.contains(nick)
    }

    pub fn can_talk(&self, id: usize) -> bool {
        if self.moderated {
            self.members.get(&id).map_or(false, |m| m.has_voice())
        } else {
            !self.no_privmsg_from_outside || self.members.contains_key(&id)
        }
    }

    pub fn can_invite(&self, id: usize) -> bool {
        let member = match self.members.get(&id) {
            Some(member) => member,
            None => return false,
        };
        if self.invite_only {
            member.is_at_least_halfop()
        } else {
            true
        }
    }

    pub fn modes(&self, mut out: MessageBuffer<'_>, full_info: bool) {
        let modes = out.raw_param();
        modes.push('+');
        if self.invite_only { modes.push('i'); }
        if self.moderated { modes.push('m'); }
        if self.no_privmsg_from_outside { modes.push('n'); }
        if self.secret { modes.push('s'); }
        if self.topic_restricted { modes.push('t'); }
        if self.user_limit.is_some() { modes.push('l'); }
        if self.key.is_some() { modes.push('k'); }

        if full_info {
            if let Some(user_limit) = self.user_limit {
                out = out.param(&user_limit.to_string());
            }
            if let Some(ref key) = self.key {
                out.param(&key.to_owned());
            }
        }
    }

    // TODO use MessageBuffer
    pub fn apply_mode_change<'a, F>(&mut self, change: modes::ChannelModeChange<'_>,
                                    nick_of: F) -> Result<bool, Reply>
        where F: Fn(&usize) -> &'a str
    {
        use modes::ChannelModeChange::*;
        let mut applied = false;
        match change {
            InviteOnly(value) => {
                applied = self.invite_only != value;
                self.invite_only = value;
            },
            Moderated(value) => {
                applied = self.moderated != value;
                self.moderated = value;
            },
            NoPrivMsgFromOutside(value) => {
                applied = self.no_privmsg_from_outside != value;
                self.no_privmsg_from_outside = value;
            },
            Secret(value) => {
                applied = self.secret != value;
                self.secret = value;
            },
            TopicRestricted(value) => {
                applied = self.topic_restricted != value;
                self.topic_restricted = value;
            },
            Key(value, key) => if value {
                if self.key.is_some() {
                    return Err(rpl::ERR_KEYSET);
                } else {
                    applied = true;
                    self.key = Some(key.to_owned());
                }
            } else if let Some(ref chan_key) = self.key {
                if key == chan_key {
                    applied = true;
                    self.key = None;
                }
            },
            UserLimit(Some(s)) => if let Ok(limit) = s.parse() {
                applied = self.user_limit.map_or(true, |chan_limit| chan_limit != limit);
                self.user_limit = Some(limit);
            },
            UserLimit(None) => {
                applied = self.user_limit.is_some();
                self.user_limit = None;
            },
            ChangeBan(value, param) => {
                applied = if value {
                    self.ban_mask.insert(param.to_owned())
                } else {
                    self.ban_mask.remove(param)
                };
            },
            ChangeException(value, param) => {
                applied = if value {
                    self.exception_mask.insert(param.to_owned())
                } else {
                    self.exception_mask.remove(param)
                };
            },
            ChangeInvitation(value, param) => {
                applied = if value {
                    self.invitation_mask.insert(param.to_owned())
                } else {
                    self.invitation_mask.remove(param)
                };
            },
            ChangeOperator(value, param) => {
                let mut has_it = false;
                for (member, modes) in &mut self.members {
                    if nick_of(member) == param {
                        has_it = true;
                        applied = modes.operator != value;
                        modes.operator = value;
                        break;
                    }
                }
                if !has_it {
                    return Err(rpl::ERR_USERNOTINCHANNEL);
                }
            },
            ChangeHalfop(value, param) => {
                let mut has_it = false;
                for (member, modes) in &mut self.members {
                    if nick_of(member) == param {
                        has_it = true;
                        applied = modes.halfop != value;
                        modes.halfop = value;
                        break;
                    }
                }
                if !has_it {
                    return Err(rpl::ERR_USERNOTINCHANNEL);
                }
            },
            ChangeVoice(value, param) => {
                // TODO don't allow halfop to change voice of halfop/operator/etc
                let mut has_it = false;
                for (member, modes) in &mut self.members {
                    if nick_of(member) == param {
                        has_it = true;
                        applied = modes.voice != value;
                        modes.voice = value;
                        break;
                    }
                }
                if !has_it {
                    return Err(rpl::ERR_USERNOTINCHANNEL);
                }
            },
            _ => {},
        }
        Ok(applied)
    }

    pub fn symbol(&self) -> &'static str {
        if self.secret {
            "@"
        } else {
            "="
        }
    }
}
