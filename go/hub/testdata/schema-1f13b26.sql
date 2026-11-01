-- The hub schema at commit 1f13b26 (before stored reply counters), verbatim,
-- plus the index its migrateLogRe created. TestReplyCountBackfill builds a
-- database from it.
CREATE TABLE IF NOT EXISTS objects (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, from_key TEXT NOT NULL,
  ts INTEGER NOT NULL, channel TEXT NOT NULL, token TEXT NOT NULL, recv INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS handles (
  name TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, obj_id TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, principal TEXT NOT NULL, agent TEXT NOT NULL, name TEXT NOT NULL,
  exp INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS grants_principal ON grants(principal);
CREATE TABLE IF NOT EXISTS enrolls (
  id TEXT PRIMARY KEY, agent TEXT NOT NULL, grant_id TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
  ended INTEGER NOT NULL DEFAULT 0, ended_at INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS enrolls_agent ON enrolls(agent);
CREATE INDEX IF NOT EXISTS enrolls_grant ON enrolls(grant_id);
CREATE TABLE IF NOT EXISTS revoked_keys (key TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS allow (owner TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY(owner, key));
CREATE TABLE IF NOT EXISTS inbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, queue TEXT NOT NULL, obj_id TEXT NOT NULL,
  thread TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS inbox_owner ON inbox(owner, queue, seq);
CREATE TABLE IF NOT EXISTS channels (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS slugs (slug TEXT PRIMARY KEY, channel TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS members (
  channel TEXT NOT NULL, key TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(channel, key));
CREATE TABLE IF NOT EXISTS bans (
  channel TEXT NOT NULL, key TEXT NOT NULL, until INTEGER NOT NULL, rank INTEGER NOT NULL,
  PRIMARY KEY(channel, key));
CREATE TABLE IF NOT EXISTS chan_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL, obj_id TEXT NOT NULL,
  author TEXT NOT NULL, recv INTEGER NOT NULL, hidden INTEGER NOT NULL DEFAULT 0, re TEXT);
CREATE INDEX IF NOT EXISTS chan_log_channel ON chan_log(channel, seq);
CREATE TABLE IF NOT EXISTS subs (
  id TEXT PRIMARY KEY, key TEXT NOT NULL, channel TEXT NOT NULL, start_seq INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS subs_live ON subs(key, channel) WHERE revoked=0;
CREATE TABLE IF NOT EXISTS auth_seen (id TEXT PRIMARY KEY, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS chan_log_re ON chan_log(channel, re);
