package hub

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo
)

const schema = `
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
  author TEXT NOT NULL, recv INTEGER NOT NULL, hidden INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS chan_log_channel ON chan_log(channel, seq);
CREATE TABLE IF NOT EXISTS auth_seen (id TEXT PRIMARY KEY, ts INTEGER NOT NULL);
`

// SQLite is a Store backed by modernc.org/sqlite.
type SQLite struct{ db *sql.DB }

// OpenSQLite opens (creating if needed) a SQLite database at path. Use
// "file::memory:?cache=shared" style DSNs or a temp file for tests.
func OpenSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serialises writers anyway, and this avoids
	// SQLITE_BUSY between pooled connections.
	db.SetMaxOpenConns(1)
	for _, p := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db}, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) Tx(ctx context.Context, fn func(Ops) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(sqlOps{tx}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

type sqlOps struct{ tx *sql.Tx }

func (o sqlOps) exec(q string, args ...any) error {
	_, err := o.tx.Exec(q, args...)
	return err
}

// one scans a single row, mapping "no rows" to found=false.
func one(row *sql.Row, dst ...any) (bool, error) {
	err := row.Scan(dst...)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (o sqlOps) PutObject(ob Obj) error {
	return o.exec(`INSERT INTO objects(id,type,from_key,ts,channel,token,recv) VALUES(?,?,?,?,?,?,?)`,
		ob.ID, ob.Type, ob.From, ob.TS, ob.Channel, ob.Token, ob.Recv)
}

func (o sqlOps) Object(id string) (*Obj, error) {
	var ob Obj
	ok, err := one(o.tx.QueryRow(`SELECT id,type,from_key,ts,channel,token,recv FROM objects WHERE id=?`, id),
		&ob.ID, &ob.Type, &ob.From, &ob.TS, &ob.Channel, &ob.Token, &ob.Recv)
	if !ok {
		return nil, err
	}
	return &ob, nil
}

func (o sqlOps) handle(where string, arg string) (*Handle, error) {
	var h Handle
	ok, err := one(o.tx.QueryRow(`SELECT name,key,obj_id,ts FROM handles WHERE `+where+`=?`, arg),
		&h.Name, &h.Key, &h.ObjID, &h.TS)
	if !ok {
		return nil, err
	}
	return &h, nil
}

func (o sqlOps) HandleByName(name string) (*Handle, error) { return o.handle("name", name) }
func (o sqlOps) HandleByKey(key string) (*Handle, error)   { return o.handle("key", key) }

func (o sqlOps) SetHandle(h Handle) error {
	if err := o.exec(`DELETE FROM handles WHERE key=? OR name=?`, h.Key, h.Name); err != nil {
		return err
	}
	return o.exec(`INSERT INTO handles(name,key,obj_id,ts) VALUES(?,?,?,?)`, h.Name, h.Key, h.ObjID, h.TS)
}

func (o sqlOps) DeleteHandle(name string) error {
	return o.exec(`DELETE FROM handles WHERE name=?`, name)
}

func (o sqlOps) PutGrant(g Grant) error {
	return o.exec(`INSERT INTO grants(id,principal,agent,name,exp,revoked) VALUES(?,?,?,?,?,?)`,
		g.ID, g.Principal, g.Agent, g.Name, g.Exp, g.Revoked)
}

func (o sqlOps) Grant(id string) (*Grant, error) {
	var g Grant
	ok, err := one(o.tx.QueryRow(`SELECT id,principal,agent,name,exp,revoked FROM grants WHERE id=?`, id),
		&g.ID, &g.Principal, &g.Agent, &g.Name, &g.Exp, &g.Revoked)
	if !ok {
		return nil, err
	}
	return &g, nil
}

func (o sqlOps) Grants(principal string) ([]Grant, error) {
	rows, err := o.tx.Query(`SELECT id,principal,agent,name,exp,revoked FROM grants
		WHERE principal=? AND revoked=0 ORDER BY rowid`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.Principal, &g.Agent, &g.Name, &g.Exp, &g.Revoked); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (o sqlOps) RevokeGrant(id string) error {
	return o.exec(`UPDATE grants SET revoked=1 WHERE id=?`, id)
}

func (o sqlOps) PutEnroll(e Enroll) error {
	return o.exec(`INSERT INTO enrolls(id,agent,grant_id,revoked) VALUES(?,?,?,?)`, e.ID, e.Agent, e.GrantID, e.Revoked)
}

func (o sqlOps) enrolls(where, arg string) ([]Enroll, error) {
	return o.enrollRows(`SELECT id,agent,grant_id,revoked,ended,ended_at FROM enrolls WHERE `+where+`=? ORDER BY rowid`, arg)
}

// enrollRows scans enroll rows in arrival order.
func (o sqlOps) enrollRows(q string, args ...any) ([]Enroll, error) {
	rows, err := o.tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Enroll
	for rows.Next() {
		var e Enroll
		if err := rows.Scan(&e.ID, &e.Agent, &e.GrantID, &e.Revoked, &e.Ended, &e.EndedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (o sqlOps) EnrollsForGrant(grantID string) ([]Enroll, error) {
	return o.enrolls("grant_id", grantID)
}
func (o sqlOps) EnrollsByAgent(agent string) ([]Enroll, error) { return o.enrolls("agent", agent) }

func (o sqlOps) RevokeEnroll(id string) error {
	return o.exec(`UPDATE enrolls SET revoked=1 WHERE id=?`, id)
}

func (o sqlOps) EndBinding(id string, at int64) error {
	return o.exec(`UPDATE enrolls SET ended=1, ended_at=? WHERE id=?`, at, id)
}

func (o sqlOps) ExpiredBindings(now int64) ([]Enroll, error) {
	return o.enrollRows(`SELECT e.id,e.agent,e.grant_id,e.revoked,e.ended,e.ended_at FROM enrolls e
		JOIN grants g ON g.id=e.grant_id WHERE e.ended=0 AND g.exp>0 AND g.exp<=? ORDER BY e.rowid`, now)
}

func (o sqlOps) RevokeKey(key string) error {
	return o.exec(`INSERT OR IGNORE INTO revoked_keys(key) VALUES(?)`, key)
}

func (o sqlOps) KeyRevoked(key string) (bool, error) {
	var x int
	return one(o.tx.QueryRow(`SELECT 1 FROM revoked_keys WHERE key=?`, key), &x)
}

func (o sqlOps) SetAllow(owner, key string, allowed bool) error {
	if allowed {
		return o.exec(`INSERT OR IGNORE INTO allow(owner,key) VALUES(?,?)`, owner, key)
	}
	return o.exec(`DELETE FROM allow WHERE owner=? AND key=?`, owner, key)
}

func (o sqlOps) ClearAllowFor(key string) error {
	return o.exec(`DELETE FROM allow WHERE key=?`, key)
}

func (o sqlOps) Allowed(owner, key string) (bool, error) {
	var x int
	return one(o.tx.QueryRow(`SELECT 1 FROM allow WHERE owner=? AND key=?`, owner, key), &x)
}

func (o sqlOps) AddInbox(owner, queue, objID, thread string) error {
	return o.exec(`INSERT INTO inbox(owner,queue,obj_id,thread) VALUES(?,?,?,?)`, owner, queue, objID, thread)
}

// entries scans (seq, token, thread) rows.
func (o sqlOps) entries(q string, args ...any) ([]Entry, error) {
	rows, err := o.tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Seq, &e.Token, &e.Thread); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (o sqlOps) Inbox(owner, queue string, after int64, limit int) ([]Entry, error) {
	return o.entries(`SELECT i.seq, ob.token, i.thread FROM inbox i JOIN objects ob ON ob.id=i.obj_id
		WHERE i.owner=? AND i.queue=? AND i.seq>? ORDER BY i.seq LIMIT ?`, owner, queue, after, limit)
}

func (o sqlOps) PutChannel(c Channel) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return o.exec(`INSERT INTO channels(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`,
		c.ID, string(data))
}

func (o sqlOps) Channel(id string) (*Channel, error) {
	var data string
	ok, err := one(o.tx.QueryRow(`SELECT data FROM channels WHERE id=?`, id), &data)
	if !ok {
		return nil, err
	}
	var c Channel
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (o sqlOps) Channels() ([]Channel, error) {
	rows, err := o.tx.Query(`SELECT data FROM channels ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c Channel
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (o sqlOps) SlugChannel(slug string) (string, error) {
	var c string
	_, err := one(o.tx.QueryRow(`SELECT channel FROM slugs WHERE slug=?`, slug), &c)
	return c, err
}

func (o sqlOps) BindSlug(slug, channel string) error {
	return o.exec(`INSERT INTO slugs(slug,channel) VALUES(?,?)`, slug, channel)
}

func (o sqlOps) UnbindSlug(slug string) error {
	return o.exec(`DELETE FROM slugs WHERE slug=?`, slug)
}

func (o sqlOps) Membership(channel, key string) (string, error) {
	var s string
	_, err := one(o.tx.QueryRow(`SELECT state FROM members WHERE channel=? AND key=?`, channel, key), &s)
	return s, err
}

func (o sqlOps) SetMembership(channel, key, state string) error {
	if state == "" {
		return o.exec(`DELETE FROM members WHERE channel=? AND key=?`, channel, key)
	}
	return o.exec(`INSERT INTO members(channel,key,state) VALUES(?,?,?)
		ON CONFLICT(channel,key) DO UPDATE SET state=excluded.state`, channel, key, state)
}

func (o sqlOps) MemberCount(channel string) (int, error) {
	var n int
	_, err := one(o.tx.QueryRow(`SELECT COUNT(*) FROM members WHERE channel=? AND state='member'`, channel), &n)
	return n, err
}

func (o sqlOps) SetBan(channel, key string, until int64, rank int) error {
	return o.exec(`INSERT INTO bans(channel,key,until,rank) VALUES(?,?,?,?)
		ON CONFLICT(channel,key) DO UPDATE SET until=excluded.until, rank=excluded.rank`, channel, key, until, rank)
}

func (o sqlOps) LiftBan(channel, key string) error {
	return o.exec(`DELETE FROM bans WHERE channel=? AND key=?`, channel, key)
}

func (o sqlOps) BanUntil(channel, key string) (int64, int, bool, error) {
	var until int64
	var rank int
	ok, err := one(o.tx.QueryRow(`SELECT until, rank FROM bans WHERE channel=? AND key=?`, channel, key), &until, &rank)
	return until, rank, ok, err
}

func (o sqlOps) AppendLog(channel, objID string, recv int64) error {
	return o.exec(`INSERT INTO chan_log(channel,obj_id,author,recv)
		SELECT ?, id, from_key, ? FROM objects WHERE id=?`, channel, recv, objID)
}

func (o sqlOps) LogEntry(channel, objID string) (string, bool, bool, error) {
	var a string
	var hidden bool
	ok, err := one(o.tx.QueryRow(`SELECT author, hidden FROM chan_log WHERE channel=? AND obj_id=?`, channel, objID),
		&a, &hidden)
	return a, hidden, ok, err
}

func (o sqlOps) HideLog(channel, objID string) error {
	return o.exec(`UPDATE chan_log SET hidden=1 WHERE channel=? AND obj_id=?`, channel, objID)
}

func (o sqlOps) Log(channel string, after int64, limit int) ([]Entry, error) {
	return o.entries(`SELECT l.seq, ob.token, '' FROM chan_log l JOIN objects ob ON ob.id=l.obj_id
		WHERE l.channel=? AND l.hidden=0 AND l.seq>? ORDER BY l.seq LIMIT ?`, channel, after, limit)
}

func (o sqlOps) PostsSince(channel string, since int64) (int, error) {
	var n int
	_, err := one(o.tx.QueryRow(`SELECT COUNT(*) FROM chan_log WHERE channel=? AND hidden=0 AND recv>=?`,
		channel, since), &n)
	return n, err
}

func (o sqlOps) UseAuth(id string, ts int64) (bool, error) {
	res, err := o.tx.Exec(`INSERT OR IGNORE INTO auth_seen(id,ts) VALUES(?,?)`, id, ts)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (o sqlOps) PruneAuth(before int64) error {
	return o.exec(`DELETE FROM auth_seen WHERE ts<?`, before)
}
