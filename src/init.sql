CREATE TABLE IF NOT EXISTS users
  ( id        INTEGER PRIMARY KEY AUTOINCREMENT
  , username  VARCHAR NOT NULL
  , password  CHAR(64)
  , cert_fp   CHAR(64)
  , op_level  INTEGER
  , hostname  VARCHAR

  , CHECK (password IS NOT NULL  OR  cert_fp IS NOT NULL)
  );


CREATE TABLE IF NOT EXISTS channels
  ( id           INTEGER PRIMARY KEY AUTOINCREMENT
  , name         VARCHAR NOT NULL
  , founder      INTEGER REFERENCES users
  , user_limit   INTEGER
  , secret_key   VARCHAR
  , invite_only  INTEGER DEFAULT 0
  , moderated    INTEGER DEFAULT 0
  , secret       INTEGER DEFAULT 0
  , no_msg_from_outside  INTEGER DEFAULT 0
  , topic_restricted     INTEGER DEFAULT 0

  , CHECK (invite_only = 0  OR  invite_only = 1)
  , CHECK (moderated = 0  OR  moderated = 1)
  , CHECK (no_msg_from_outside = 0  OR  no_msg_from_outside = 1)
  , CHECK (secret = 0  OR  secret = 1)
  , CHECK (topic_restricted = 0  OR  topic_restricted = 1)
  );


CREATE TABLE IF NOT EXISTS channel_members
  ( channel   INTEGER NOT NULL REFERENCES channels ON DELETE CASCADE
  , member    INTEGER NOT NULL REFERENCES users    ON DELETE CASCADE
  , modes     INTEGER NOT NULL

  , PRIMARY KEY (channel, member)
  );


CREATE TABLE IF NOT EXISTS channel_bans
  ( channel   INTEGER NOT NULL REFERENCES channels ON DELETE CASCADE
  , ban_type  INTEGER NOT NULL -- 0 for ban, 1 for exception, 2 for invex
  , ban_mask  VARCHAR NOT NULL

  , PRIMARY KEY (channel, ban_type, ban_mask)
  , CHECK (ban_type = 0  OR  ban_type = 1  OR  ban_type = 2)
  , CHECK (ban_mask LIKE '%!%@%')
  );
