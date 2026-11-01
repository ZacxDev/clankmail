package hub

// The stored reply counters (§8.1): maintained on append and remove, equal to
// a recount from the log for any history, recounted on every open (so an
// existing database, or one an older binary wrote to, is repaired), and read
// by the digest without reading any reply.

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// mPost is a channel-log post in a test's own model of the log.
type mPost struct {
	id, ch, from, re string
	hidden           bool
}

// counts is a post's (replies, repliers).
type counts [2]int

// recount applies the §8.1 counting rule to a model log, from scratch: a
// reply to P is a post in P's channel, not hidden, whose re is P's id and
// whose author is not P's author. Bans play no part. Every post gets an
// entry, zero included.
func recount(log []mPost) map[string]counts {
	byKey := map[string]mPost{}
	for _, p := range log {
		byKey[p.ch+"/"+p.id] = p
	}
	out := map[string]counts{}
	who := map[string]map[string]bool{}
	for _, p := range log {
		out[p.id] = counts{}
		who[p.id] = map[string]bool{}
	}
	for _, r := range log {
		parent, ok := byKey[r.ch+"/"+r.re]
		if r.re == "" || !ok || r.hidden || r.from == parent.from {
			continue
		}
		c := out[parent.id]
		c[0]++
		who[parent.id][r.from] = true
		c[1] = len(who[parent.id])
		out[parent.id] = c
	}
	return out
}

// storedCounts reads every log row's stored counters, and checks that
// reply_authors agrees with them: one row per counted replier, n > 0, the
// n summing to replies.
func storedCounts(t *testing.T, db *sql.DB) map[string]counts {
	t.Helper()
	out := map[string]counts{}
	rows, err := db.Query(`SELECT obj_id, replies, repliers FROM chan_log`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		var c counts
		if err := rows.Scan(&id, &c[0], &c[1]); err != nil {
			t.Fatal(err)
		}
		out[id] = c
	}
	rows.Close()
	ra := map[string]counts{}
	rows, err = db.Query(`SELECT post, SUM(n), COUNT(*), MIN(n) FROM reply_authors GROUP BY post`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		var c counts
		var minN int
		if err := rows.Scan(&id, &c[0], &c[1], &minN); err != nil {
			t.Fatal(err)
		}
		if minN <= 0 {
			t.Fatalf("reply_authors holds a row with n=%d for %s", minN, id)
		}
		ra[id] = c
	}
	rows.Close()
	for id, c := range out {
		if c != ra[id] {
			t.Fatalf("%s: chan_log counters %v, reply_authors says %v", id, c, ra[id])
		}
	}
	return out
}

func diffCounts(want, got map[string]counts) string {
	var bad []string
	for id, w := range want {
		if g, ok := got[id]; !ok || g != w {
			bad = append(bad, fmt.Sprintf("%s: stored %v, recount %v", id, got[id], w))
		}
	}
	if len(got) != len(want) {
		bad = append(bad, fmt.Sprintf("%d stored rows, %d posts", len(got), len(want)))
	}
	sort.Strings(bad)
	return strings.Join(bad, "\n")
}

// For seeded random histories submitted through the hub — posts, replies in
// the same and the other channel, self-replies, replies that arrive before
// their parent, removes and re-removes of replies and parents, bans and
// unbans — the stored counters equal a recount after every step batch, and
// the digest equals the reference ranking over the same log.
func TestReplyCountersMatchRecount(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) { counterHistory(t, seed) })
	}
}

func counterHistory(t *testing.T, seed int64) {
	e, s := costEnv(t, unlimited)
	x := e.createChannel(alice, "cnt-x", "public", "anyone", "open", nil)
	y := e.createChannel(alice, "cnt-y", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, x))
	e.mustSubmit(e.subTok(bob, y))
	authors := []ed25519.PrivateKey{bob, carol, dave, eve, scout, alice}
	chans := []string{x, y}
	rng := rand.New(rand.NewSource(seed))
	var log []mPost
	ts := map[string]int64{}
	banned := map[string]bool{} // channel/key
	tried := map[string]int{}

	msgTok := func(k ed25519.PrivateKey, ch, re string) string {
		f := map[string]any{"to": []any{ch}, "body": fmt.Sprintf("b%d", rng.Int63())}
		if re != "" {
			f["re"] = re
		}
		return e.tok(k, "msg", f)
	}
	// submitPost submits a signed post and adds it to the model if accepted.
	submitPost := func(tok string, k ed25519.PrivateKey, ch, re string) {
		r := e.submit(tok)
		e.advance(time.Second)
		if r.status != 200 {
			if !banned[ch+"/"+kid(k)] {
				t.Fatalf("post refused: %d %v", r.status, r.body)
			}
			tried["post refused (banned)"]++
			return
		}
		obj, err := clankmail.Verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		log = append(log, mPost{id: obj.ID, ch: ch, from: kid(k), re: re})
		ts[obj.ID] = obj.Fields["ts"].(int64) // signing time: an orphan's parent is signed early
	}
	recent := func() string {
		if len(log) == 0 {
			return ""
		}
		return log[len(log)-1-rng.Intn(min(len(log), 8))].id
	}
	check := func(step int) {
		t.Helper()
		if d := diffCounts(recount(log), storedCounts(t, s.db)); d != "" {
			t.Fatalf("seed %d step %d: stored counters differ from the recount:\n%s", seed, step, d)
		}
	}
	for step := 0; step < 300; step++ {
		k := authors[rng.Intn(len(authors))]
		ch := chans[rng.Intn(2)]
		switch r := rng.Intn(20); {
		case r < 10: // a post, mostly a reply to a recent post of either channel
			re := ""
			if rng.Intn(4) != 0 {
				re = recent()
			}
			if re != "" {
				tried["reply"]++
			}
			submitPost(msgTok(k, ch, re), k, ch, re)
		case r < 12: // replies that arrive before their parent
			parent := msgTok(k, ch, "")
			pid := idOf(t, parent)
			for i := 0; i < 1+rng.Intn(3); i++ {
				rk := authors[rng.Intn(len(authors))]
				rch := ch
				if rng.Intn(4) == 0 {
					rch = chans[1-rng.Intn(2)]
				}
				n := len(log)
				submitPost(msgTok(rk, rch, pid), rk, rch, pid)
				if len(log) > n && rng.Intn(2) == 0 { // removed before its parent arrives
					e.mustSubmit(e.tok(rk, "remove", map[string]any{"channel": rch, "target": log[n].id}))
					e.advance(time.Second)
					log[n].hidden = true
					tried["orphan removed"]++
				}
			}
			tried["orphan parent"]++
			submitPost(parent, k, ch, "")
		case r < 16: // remove (or remove again) a post, by its author or the owner
			if len(log) == 0 {
				continue
			}
			i := len(log) - 1 - rng.Intn(min(len(log), 12))
			p := log[i]
			signer := alice
			if rng.Intn(2) == 0 {
				for _, a := range authors {
					if kid(a) == p.from {
						signer = a
					}
				}
			}
			res := e.submit(e.tok(signer, "remove", map[string]any{"channel": p.ch, "target": p.id}))
			e.advance(time.Second)
			if res.status == 200 {
				if p.hidden {
					tried["re-remove"]++
				}
				log[i].hidden = true
				tried["remove"]++
			} else if !banned[p.ch+"/"+kid(signer)] {
				t.Fatalf("remove refused: %d %v", res.status, res.body)
			}
		case r < 18: // ban
			if k.Equal(alice) {
				continue
			}
			e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": ch, "member": kid(k)}))
			e.advance(time.Second)
			banned[ch+"/"+kid(k)] = true
			tried["ban"]++
		default: // unban (a ban whose until has passed lifts it)
			if !banned[ch+"/"+kid(k)] {
				continue
			}
			e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": ch, "member": kid(k), "until": e.now.Load() - 1}))
			e.advance(time.Second)
			delete(banned, ch+"/"+kid(k))
			tried["unban"]++
		}
		if step%25 == 24 {
			check(step)
		}
	}
	check(300)
	for _, what := range []string{"reply", "orphan parent", "orphan removed", "remove", "re-remove", "ban", "unban", "post refused (banned)"} {
		if tried[what] == 0 {
			t.Fatalf("seed %d never exercised %q: %v", seed, what, tried)
		}
	}
	// Nonzero counts exist, and so do self-replies and cross-channel replies.
	var nonzero, self, cross int
	byID := map[string]mPost{}
	for _, p := range log {
		byID[p.id] = p
	}
	for _, c := range recount(log) {
		if c[0] > 0 {
			nonzero++
		}
	}
	for _, p := range log {
		if q, ok := byID[p.re]; ok {
			if q.from == p.from {
				self++
			}
			if q.ch != p.ch {
				cross++
			}
		}
	}
	if nonzero < 10 || self == 0 || cross == 0 {
		t.Fatalf("seed %d: weak history: %d posts with replies, %d self-replies, %d cross-channel", seed, nonzero, self, cross)
	}

	// The digest against the reference, with the model's hidden and banned
	// marks: the window is every post not hidden, not bob's, not by a key
	// banned in its channel now.
	var posts []clankmail.DigestPost
	for _, p := range log {
		b := banned[p.ch+"/"+p.from]
		posts = append(posts, clankmail.DigestPost{ID: p.id, Channel: p.ch, From: p.from, TS: ts[p.id], Re: p.re,
			Hidden: p.hidden, Banned: b, Window: !p.hidden && !b && p.from != kid(bob)})
	}
	want, wantOmitted := clankmail.RankDigest(posts, 50, 50)
	var wantItems []dItem
	for _, it := range want {
		wantItems = append(wantItems, dItem{it.ID, it.Repliers, it.Replies})
	}
	got, r := e.digest(bob, "limit=50&per_channel=50")
	if fmt.Sprint(got) != fmt.Sprint(wantItems) || r.body["omitted"].(float64) != float64(wantOmitted) {
		t.Fatalf("seed %d digest:\n got %v omitted %v\nwant %v omitted %d", seed, got, r.body["omitted"], wantItems, wantOmitted)
	}
}

// openOld builds a database with the schema of commit 1f13b26, which had no
// stored counters, and fills it with a random log: posts in two channels,
// replies within and across channels, self-replies, replies whose parent is
// later in the log, and hidden posts. It returns the model of that log.
func openOld(t *testing.T, path string) []mPost {
	t.Helper()
	ddl, err := os.ReadFile("testdata/schema-1f13b26.sql")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(ddl)); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(11))
	const n = 400
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("m_old%04d", i)
	}
	authors := []string{"k_a", "k_b", "k_c", "k_d", "k_e"}
	var log []mPost
	for i := 0; i < n; i++ {
		p := mPost{id: ids[i], ch: []string{"c_x", "c_y"}[rng.Intn(4)/3], from: authors[rng.Intn(len(authors))]}
		switch r := rng.Intn(10); {
		case r < 6 && i > 0:
			p.re = ids[i-1-rng.Intn(min(i, 6))]
		case r < 7 && i < n-1:
			p.re = ids[i+1+rng.Intn(min(n-1-i, 6))] // parent arrives later
		}
		p.hidden = rng.Intn(8) == 0
		log = append(log, p)
		if _, err := db.Exec(`INSERT INTO objects(id,type,from_key,ts,channel,token,recv) VALUES(?,'msg',?,?,?,'v1.x',?)`,
			p.id, p.from, int64(1767225600000+i), p.ch, int64(i)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO chan_log(channel,obj_id,author,recv,hidden,re) VALUES(?,?,?,?,?,?)`,
			p.ch, p.id, p.from, int64(i), p.hidden, p.re); err != nil {
			t.Fatal(err)
		}
	}
	return log
}

// Opening a database written by the 1f13b26 schema adds the counters and
// fills them by the recount. Every later open recounts again: it gets the
// same values from a correct store and replaces whatever a corrupted one
// held, ignoring the earlier build's one-time marker. After the migration,
// appends and removes keep the counters right.
func TestReplyCountBackfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	log := openOld(t, path)
	want := recount(log)
	nonzero := 0
	for _, c := range want {
		if c[0] > 0 {
			nonzero++
		}
	}
	if nonzero < 50 {
		t.Fatalf("weak fixture: %d posts with replies", nonzero)
	}
	open := func() *SQLite {
		t.Helper()
		s, err := OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	s := open()
	if d := diffCounts(want, storedCounts(t, s.db)); d != "" {
		t.Fatalf("first open: back-filled counters differ from the recount:\n%s", d)
	}
	var idx int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_index_info('chan_log_obj')`).Scan(&idx); err != nil || idx != 2 {
		t.Fatalf("migration did not create chan_log_obj(channel, obj_id): %d columns, %v", idx, err)
	}
	s.Close()

	s = open() // second open: recounts, and gets the same values
	if d := diffCounts(want, storedCounts(t, s.db)); d != "" {
		t.Fatalf("second open:\n%s", d)
	}
	// Corrupt what is stored, and plant the marker an earlier build used to
	// skip the recount. Positive control: the comparison sees the damage.
	if _, err := s.db.Exec(`UPDATE chan_log SET replies=replies+7, repliers=repliers+7; UPDATE reply_authors SET n=n+1;
		INSERT INTO reply_authors(post,author,n) VALUES('m_old0000','k_zz',3);
		INSERT OR REPLACE INTO meta(k,v) VALUES('reply_counts','1')`); err != nil {
		t.Fatal(err)
	}
	if d := diffCounts(want, func() map[string]counts {
		got := map[string]counts{}
		rows, _ := s.db.Query(`SELECT obj_id, replies, repliers FROM chan_log`)
		for rows.Next() {
			var id string
			var c counts
			rows.Scan(&id, &c[0], &c[1])
			got[id] = c
		}
		rows.Close()
		return got
	}()); d == "" {
		t.Fatal("control: corrupted counters compare equal")
	}
	s.Close()
	// The next open recounts from scratch whatever was stored, marker or not,
	// and removes the marker.
	s = open()
	if d := diffCounts(want, storedCounts(t, s.db)); d != "" {
		t.Fatalf("reopen after corruption:\n%s", d)
	}
	var marker int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM meta WHERE k='reply_counts'`).Scan(&marker); err != nil || marker != 0 {
		t.Fatalf("old back-fill marker still stored: %d, %v", marker, err)
	}
	// And twice in a row in one transaction.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := recountReplies(tx); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if d := diffCounts(want, storedCounts(t, s.db)); d != "" {
		t.Fatalf("recount twice:\n%s", d)
	}

	// Incremental maintenance on the migrated database: a reply to a post
	// with replies, a reply naming a post not yet in the log and then that
	// post, and the removal of a counted reply.
	var parent mPost
	for _, p := range log {
		if want[p.id][0] > 0 && !p.hidden {
			parent = p
			break
		}
	}
	tx, err = s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ops := sqlOps{tx}
	add := func(p mPost) {
		if _, err := tx.Exec(`INSERT INTO objects(id,type,from_key,ts,channel,token,recv) VALUES(?,'msg',?,0,?,'v1.x',0)`, p.id, p.from, p.ch); err != nil {
			t.Fatal(err)
		}
		if err := ops.AppendLog(p.ch, p.id, p.re, 0); err != nil {
			t.Fatal(err)
		}
		log = append(log, p)
	}
	add(mPost{id: "m_new1", ch: parent.ch, from: "k_new", re: parent.id})
	add(mPost{id: "m_new2", ch: parent.ch, from: "k_new", re: "m_new3"})
	add(mPost{id: "m_new4", ch: parent.ch, from: "k_b", re: "m_new3"})
	if err := ops.HideLog(parent.ch, "m_new4"); err != nil { // hidden before its parent arrives
		t.Fatal(err)
	}
	log[len(log)-1].hidden = true
	add(mPost{id: "m_new3", ch: parent.ch, from: "k_a"})
	if err := ops.HideLog(parent.ch, "m_new1"); err != nil {
		t.Fatal(err)
	}
	for i := range log {
		if log[i].id == "m_new1" {
			log[i].hidden = true
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if d := diffCounts(recount(log), storedCounts(t, s.db)); d != "" {
		t.Fatalf("after incremental changes on the migrated database:\n%s", d)
	}
	if c := storedCounts(t, s.db)["m_new3"]; c != (counts{1, 1}) {
		t.Fatalf("m_new3 (one earlier reply by another key, one earlier hidden): %v", c)
	}
	s.Close()
}

// rawOrphans writes n channel posts whose re names the post id parent, which
// is not yet in the log, straight into the store with no maintenance (a post
// whose parent is absent changes no counter). Authors cycle through 37 keys.
// One statement per table, so building a large log stays fast under -race.
func rawOrphans(t *testing.T, s *SQLite, ch, parent string, n int) {
	t.Helper()
	const gen = `WITH RECURSIVE i(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM i WHERE n+1<?) `
	if _, err := s.db.Exec(gen+`INSERT INTO objects(id,type,from_key,ts,channel,token,recv)
		SELECT printf('m_orphan%07d', n), 'msg', printf('k_replier%02d', n%37), 0, ?, 'v1.r', 0 FROM i`, n, ch); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(gen+`INSERT INTO chan_log(channel,obj_id,author,recv,re)
		SELECT ?, printf('m_orphan%07d', n), printf('k_replier%02d', n%37), 0, ? FROM i`, n, ch, parent); err != nil {
		t.Fatal(err)
	}
}

// The digest's time does not grow with the number of replies to a window
// post. One post with 2 000 replies and one with 200 000, in two hubs; the
// replies predate the subscription, so the digest's scan reads one row (the
// post) in both, and only counting could tell them apart. The 200 000 case
// fails if it takes both more than 2x and more than 10 ms longer than the
// 2 000 case (best of 5 each). Counting at request time costs 0.15–1 µs a
// reply row (measured: a bare COUNT subquery, and 1f13b26's ReplyCounts),
// so 30–200 ms more.
func TestDigestCostIndependentOfReplies(t *testing.T) {
	setup := func(n int) (*env, string) {
		e, s := costEnv(t, unlimited)
		x := e.createChannel(alice, "flat-x", "public", "anyone", "open", nil)
		parent := "m_p000000"
		rawOrphans(t, s, x, parent, n)
		e.mustSubmit(e.subTok(bob, x))
		bulkLog(t, s, x, "p", 1, func(int) string { return kid(carol) }, noRe, "v1.parent")
		return e, x
	}
	best := func(e *env, n int) time.Duration {
		var b time.Duration
		var read []int
		for i := 0; i < 5; i++ {
			start := time.Now()
			var r resp
			read = append(read, rowsRead(t, func() { _, r = e.rawDigest(bob, "limit=50&per_channel=50") })...)
			d := time.Since(start)
			it := r.body["items"].([]any)
			u := it[0].(map[string]any)["unsigned"].(map[string]any)
			if len(it) != 1 || u["replies"].(float64) != float64(n) || u["repliers"].(float64) != 37 {
				t.Fatalf("%d replies: digest %v", n, r.body)
			}
			if i == 0 || d < b {
				b = d
			}
		}
		if fmt.Sprint(read) != "[1 1 1 1 1]" {
			t.Fatalf("%d replies: rows read per digest %v, want 1 each", n, read)
		}
		return b
	}
	small, _ := setup(2_000)
	big, _ := setup(200_000)
	ts, tb := best(small, 2_000), best(big, 200_000)
	t.Logf("digest, best of 5: 2 000 replies %v, 200 000 replies %v", ts, tb)
	if tb > 2*ts && tb-ts > 10*time.Millisecond {
		t.Fatalf("digest time grows with replies: 2 000 replies %v, 200 000 replies %v", ts, tb)
	}
}

// planOf returns the EXPLAIN QUERY PLAN lines of one statement.
func planOf(t *testing.T, db *sql.DB, q string, args []any) []string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		t.Fatalf("explain %q: %v", q, err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, detail)
	}
	return lines
}

// capture runs fn in one store transaction and returns every statement it ran.
func capture(t *testing.T, s *SQLite, fn func(Ops) error) [][2]any {
	t.Helper()
	var got [][2]any
	sqlHook = func(q string, args []any) { got = append(got, [2]any{q, append([]any(nil), args...)}) }
	defer func() { sqlHook = nil }()
	if err := s.Tx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
	return got
}

// planLines is every EXPLAIN QUERY PLAN line of stmts, each explained with
// its own arguments against the database it ran on: deduplicated, sorted.
func planLines(t *testing.T, s *SQLite, stmts [][2]any) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, st := range stmts {
		for _, l := range planOf(t, s.db, st[0].(string), st[1].([]any)) {
			seen[l] = true
		}
	}
	var out []string
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Every statement a digest runs, explained with its real arguments, on a log
// with one post and 200 000 replies after it: chan_log is read only by the
// (channel, seq) range seek of the scan, which is LIMIT-bounded, and by the
// cursor head; no statement seeks replies by re or scans a table. The ledger
// is exact, so a new chan_log reader fails it.
func TestDigestStatementPlans(t *testing.T) {
	e, s := costEnv(t, unlimited)
	x := e.createChannel(alice, "plan-x", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, x))
	posts := bulkLog(t, s, x, "p", 1, func(int) string { return kid(carol) }, noRe, "v1.p")
	bulkLog(t, s, x, "r", 3000, func(i int) string { return fmt.Sprintf("k_r%02d", i%37) }, func(int) string { return posts[0] }, "v1.r")

	var out map[string]any
	stmts := capture(t, s, func(ops Ops) error {
		var err error
		out, err = digest(ops, kid(bob), 0, 50, 50, e.now.Load())
		return err
	})
	first := out["items"].([]digestItem)
	if len(first) == 0 || first[0].Unsigned != (digestUnsigned{37, 3000}) {
		t.Fatalf("digest: %v", out)
	}
	got := planLines(t, s, stmts)
	want := []string{
		"CORRELATED SCALAR SUBQUERY 1", // the scan's live-ban check
		"SEARCH b USING INDEX sqlite_autoindex_bans_1 (channel=? AND key=?)",
		"SEARCH channels USING INDEX sqlite_autoindex_channels_1 (id=?)",
		"SEARCH l USING INDEX chan_log_channel (channel=? AND seq>?)", // the scan: LIMIT-bounded
		"SEARCH ob USING INDEX sqlite_autoindex_objects_1 (id=?)",
		"SEARCH objects USING INDEX sqlite_autoindex_objects_1 (id=?)",
		"SEARCH subs USING INDEX subs_live (key=?)",
		"USE TEMP B-TREE FOR ORDER BY", // the reader's live subs, at most 100
	}
	for _, l := range got {
		if strings.Contains(l, "SCAN") || strings.Contains(l, "chan_log_re") || strings.Contains(l, "reply_authors") {
			t.Errorf("digest plan reads replies or scans: %q", l)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("digest chan_log accesses:\n got %q\nwant %q", got, want)
	}
	var heads int
	for _, st := range stmts {
		if strings.Contains(st[0].(string), "FROM chan_log") && !strings.Contains(st[0].(string), "chan_log l") {
			if st[0].(string) != "SELECT COALESCE(MAX(seq),0) FROM chan_log" {
				t.Errorf("unexpected chan_log statement in the digest: %q", st[0])
			}
			heads++
		}
	}
	if heads > 1 {
		t.Errorf("cursor head read %d times", heads)
	}
}

// Accepting a reply and removing one run on point seeks: the parent by
// (channel, obj_id), its replier row by primary key, and the replies naming
// a new post by (channel, re). Nothing scans a channel's log.
func TestSubmitPathPlans(t *testing.T) {
	e, s := costEnv(t, unlimited)
	x := e.createChannel(alice, "splan-x", "public", "anyone", "open", nil)
	posts := bulkLog(t, s, x, "p", 1, func(int) string { return kid(carol) }, noRe, "v1.p")
	bulkLog(t, s, x, "r", 2000, func(i int) string { return fmt.Sprintf("k_r%02d", i%37) }, func(int) string { return posts[0] }, "v1.r")

	add := func(id, author, re string) func(Ops) error {
		return func(ops Ops) error {
			if err := ops.PutObject(Obj{ID: id, Type: "msg", From: author, Channel: x, Token: "v1.n"}); err != nil {
				return err
			}
			return ops.AppendLog(x, id, re, 0)
		}
	}
	stmts := capture(t, s, add("m_reply", "k_new", posts[0]))
	stmts = append(stmts, capture(t, s, func(ops Ops) error { return ops.HideLog(x, "m_reply") })...)
	stmts = append(stmts, capture(t, s, func(ops Ops) error { return ops.HideLog(x, "m_r000005") })...)
	got := planLines(t, s, stmts)
	want := []string{
		"SCALAR SUBQUERY 1", // the new post's counters from its reply_authors rows
		"SCALAR SUBQUERY 2",
		"SEARCH chan_log USING INDEX chan_log_obj (channel=? AND obj_id=?)", // the post, its parent
		"SEARCH chan_log USING INDEX chan_log_re (channel=? AND re=?)",      // replies that arrived before the post
		"SEARCH objects USING INDEX sqlite_autoindex_objects_1 (id=?)",
		"SEARCH reply_authors USING PRIMARY KEY (post=? AND author=?)",
		"SEARCH reply_authors USING PRIMARY KEY (post=?)",
		"USE TEMP B-TREE FOR GROUP BY", // over those earlier replies only
	}
	for _, l := range got {
		if strings.HasPrefix(l, "SCAN") || strings.Contains(l, "(channel=?)") {
			t.Errorf("submit path scans: %q", l)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("submit-path plan lines:\n got %q\nwant %q", got, want)
	}
	if c := storedCounts(t, s.db)[posts[0]]; c != (counts{1999, 37}) {
		t.Fatalf("parent after one reply added and removed and one old reply removed: %v", c)
	}
}

// inTx runs f against s in one committed transaction.
func inTx(t *testing.T, s *SQLite, f func(sqlOps) error) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := f(sqlOps{tx}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// olderBinaryOpen opens path the way a hub binary from before the stored
// counters did: plain SQL, no migrations, nothing maintained.
func olderBinaryOpen(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// oldPut stores a channel post's object with a token whose payload names re,
// as the hub stores a real one (storedFields reads re from it).
func oldPut(t *testing.T, db interface {
	Exec(string, ...any) (sql.Result, error)
}, p mPost) {
	t.Helper()
	pl := `{}`
	if p.re != "" {
		pl = `{"re":"` + p.re + `"}`
	}
	tok := "v1.h." + base64.RawURLEncoding.EncodeToString([]byte(pl)) + ".s"
	if _, err := db.Exec(`INSERT INTO objects(id,type,from_key,ts,channel,token,recv) VALUES(?,'msg',?,0,?,?,0)`,
		p.id, p.from, p.ch, tok); err != nil {
		t.Fatal(err)
	}
}

// A rollback: the current binary counts, an older binary writes to the same
// database without maintaining the counters, and the current binary opens it
// again. The older writes are those binaries' exact statements: 1f13b26's
// AppendLog (re given), main's AppendLog (no re column, so re is NULL until
// migrateLogRe fills it from the token), and their HideLog (hidden=1 only).
// On reopen the counters equal the recount; removing every reply then leaves
// zeros, and no reply_authors row with n <= 0.
func TestCountersRecountedAfterOlderBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	const ch = "c_roll"
	P := mPost{id: "m_P", ch: ch, from: "k_a"}
	log := []mPost{P,
		{id: "m_r1", ch: ch, from: "k_b", re: P.id},
		{id: "m_r1b", ch: ch, from: "k_e", re: P.id}}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range log {
		oldPut(t, tx, p)
		if err := (sqlOps{tx}).AppendLog(p.ch, p.id, p.re, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if c := storedCounts(t, s.db)[P.id]; c != (counts{2, 2}) {
		t.Fatalf("before rollback: %v, want [2 2]", c)
	}
	s.Close()

	old := olderBinaryOpen(t, path)
	r2 := mPost{id: "m_r2", ch: ch, from: "k_c", re: P.id}
	oldPut(t, old, r2)
	if _, err := old.Exec(`INSERT INTO chan_log(channel,obj_id,author,recv,re)
		SELECT ?, id, from_key, ?, ? FROM objects WHERE id=?`, ch, 0, r2.re, r2.id); err != nil { // 1f13b26
		t.Fatal(err)
	}
	r3 := mPost{id: "m_r3", ch: ch, from: "k_d", re: P.id}
	oldPut(t, old, r3)
	if _, err := old.Exec(`INSERT INTO chan_log(channel,obj_id,author,recv)
		SELECT ?, id, from_key, ? FROM objects WHERE id=?`, ch, 0, r3.id); err != nil { // main: re NULL
		t.Fatal(err)
	}
	if _, err := old.Exec(`UPDATE chan_log SET hidden=1 WHERE channel=? AND obj_id=?`, ch, "m_r1b"); err != nil {
		t.Fatal(err)
	}
	old.Close()
	log = append(log, r2, r3)
	log[2].hidden = true

	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// r1, r2, r3 count (three keys); r1b is hidden. r2 is the 1f13b26 write,
	// r3 the main write that only migrateLogRe gives a re.
	var who []string
	rs, err := s.db.Query(`SELECT author FROM reply_authors WHERE post=? ORDER BY author`, P.id)
	if err != nil {
		t.Fatal(err)
	}
	for rs.Next() {
		var a string
		rs.Scan(&a)
		who = append(who, a)
	}
	rs.Close()
	if strings.Join(who, " ") != "k_b k_c k_d" {
		t.Fatalf("after reopen: P's counted repliers %v, want [k_b k_c k_d]", who)
	}
	if c := storedCounts(t, s.db)[P.id]; c != (counts{3, 3}) {
		t.Fatalf("after reopen: P stored %v, want [3 3] (recount after the older binary's writes)", c)
	}
	if d := diffCounts(recount(log), storedCounts(t, s.db)); d != "" {
		t.Fatalf("after reopen:\n%s", d)
	}

	tx, err = s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"m_r1", "m_r2", "m_r3", "m_r1b"} {
		if err := (sqlOps{tx}).HideLog(ch, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if c := storedCounts(t, s.db)[P.id]; c != (counts{0, 0}) {
		t.Fatalf("after removing every reply: P stored %v, want [0 0]", c)
	}
}

// Removing a reply that was never counted (written by something that did not
// maintain the counters, here straight into the open store) changes nothing:
// no counter goes below zero and no reply_authors row with n <= 0 appears,
// so that key's next reply still counts it as a replier.
func TestCountReplyDecrementFloor(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "floor.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const ch = "c_floor"
	P := mPost{id: "m_P", ch: ch, from: "k_a"}
	oldPut(t, s.db, P)
	inTx(t, s, func(o sqlOps) error { return o.AppendLog(ch, P.id, "", 0) })
	u := mPost{id: "m_uncounted", ch: ch, from: "k_f", re: P.id}
	oldPut(t, s.db, u)
	if _, err := s.db.Exec(`INSERT INTO chan_log(channel,obj_id,author,recv,re)
		SELECT ?, id, from_key, 0, ? FROM objects WHERE id=?`, ch, u.re, u.id); err != nil {
		t.Fatal(err)
	}
	inTx(t, s, func(o sqlOps) error { return o.HideLog(ch, u.id) })
	var rows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM reply_authors WHERE post=?`, P.id).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("removing an uncounted reply: %d reply_authors rows for P, %v (want 0)", rows, err)
	}
	if c := storedCounts(t, s.db)[P.id]; c != (counts{0, 0}) {
		t.Fatalf("removing an uncounted reply: P stored %v, want [0 0]", c)
	}
	again := mPost{id: "m_again", ch: ch, from: "k_f", re: P.id}
	oldPut(t, s.db, again)
	inTx(t, s, func(o sqlOps) error { return o.AppendLog(ch, again.id, again.re, 0) })
	if c := storedCounts(t, s.db)[P.id]; c != (counts{1, 1}) {
		t.Fatalf("a later counted reply by the same key: P stored %v, want [1 1]", c)
	}
}

// Removing a reply that is already removed takes nothing away again, also
// when its author has another counted reply to the same post (the case the
// decrement floor alone would not catch).
func TestReRemoveDecrementsOnce(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "reremove.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const ch = "c_rr"
	P := mPost{id: "m_P", ch: ch, from: "k_a"}
	r1 := mPost{id: "m_r1", ch: ch, from: "k_g", re: P.id}
	r2 := mPost{id: "m_r2", ch: ch, from: "k_g", re: P.id}
	for _, p := range []mPost{P, r1, r2} {
		oldPut(t, s.db, p)
		inTx(t, s, func(o sqlOps) error { return o.AppendLog(ch, p.id, p.re, 0) })
	}
	if c := storedCounts(t, s.db)[P.id]; c != (counts{2, 1}) {
		t.Fatalf("two replies by one key: P stored %v, want [2 1]", c)
	}
	inTx(t, s, func(o sqlOps) error { return o.HideLog(ch, r1.id) })
	inTx(t, s, func(o sqlOps) error { return o.HideLog(ch, r1.id) })
	if c := storedCounts(t, s.db)[P.id]; c != (counts{1, 1}) {
		t.Fatalf("re-removing a reply: P stored %v, want [1 1]", c)
	}
}
