package hub

// The digest's resource bounds (§8.1): memory, rows read per request, the
// cursor passing ineligible rows, query plans, and the digest rate limit.
// Large logs are written straight into the store: these tests are about what
// a digest reads, not about submission.

import (
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// costEnv is a test env whose store the test can write to directly.
func costEnv(t *testing.T, opts ...func(*Config)) (*env, *SQLite) {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "cost.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return newEnv(t, append(opts, func(c *Config) { c.Store = s })...), s
}

// bulkLog appends n posts to ch's log in one transaction, bypassing submit.
// Ids are m_<prefix><i>; author and re are per post; every token is tok.
func bulkLog(t *testing.T, s *SQLite, ch, prefix string, n int, author, re func(int) string, tok string) []string {
	t.Helper()
	return bulkLogIn(t, s, func(int) string { return ch }, prefix, n, author, re, tok)
}

// bulkLogIn is bulkLog with the channel chosen per post.
func bulkLogIn(t *testing.T, s *SQLite, chOf func(int) string, prefix string, n int, author, re func(int) string, tok string) []string {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("m_%s%06d", prefix, i)
		ch := chOf(i)
		if _, err := tx.Exec(`INSERT INTO objects(id,type,from_key,ts,channel,token,recv) VALUES(?,'msg',?,?,?,?,?)`,
			ids[i], author(i), int64(1767225600000+i), ch, tok, int64(i)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO chan_log(channel,obj_id,author,recv,re) VALUES(?,?,?,?,?)`,
			ch, ids[i], author(i), int64(i), re(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func noRe(int) string { return "" }

// rawDigest is e.digest for logs written by bulkLog, whose tokens are
// placeholders: it returns the item tokens unparsed.
func (e *env) rawDigest(k ed25519.PrivateKey, query string) ([]string, resp) {
	e.t.Helper()
	r := e.as(k, "GET", "/v1/digest?"+query, nil)
	wantOK(e.t, r)
	return tokens(r), r
}

// rowsRead runs fn and returns the channel-log rows each digest it served read.
func rowsRead(t *testing.T, fn func()) []int {
	t.Helper()
	var got []int
	digestHook = func(n int) { got = append(got, n) }
	defer func() { digestHook = nil }()
	fn()
	return got
}

// Finding 1: a digest must not load the tokens of the whole window, nor of
// every reply to it. 300 posts and 600 replies (two per post, by the reader,
// so they count but are not window posts) with tokens near the 96 KiB
// maximum: reading them all is about 85 MiB before any copy. The bound is on bytes ALLOCATED during the request,
// an upper bound on its peak heap above the baseline.
func TestDigestMemoryBounded(t *testing.T) {
	e, s := costEnv(t, unlimited)
	x := e.createChannel(alice, "mem-x", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, x))
	tok := "v1." + strings.Repeat("A", 98000)
	posts := bulkLog(t, s, x, "p", 300, func(i int) string { return fmt.Sprintf("k_author%02d", i%37) }, noRe, tok)
	bulkLog(t, s, x, "r", 600, func(int) string { return kid(bob) }, func(i int) string { return posts[i%300] }, tok)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	r := e.as(bob, "GET", "/v1/digest?limit=50&per_channel=50", nil)
	runtime.ReadMemStats(&after)
	wantOK(t, r)
	items := r.body["items"].([]any)
	if len(items) != 50 || r.body["omitted"].(float64) != 250 {
		t.Fatalf("digest: %d items, omitted %v", len(items), r.body["omitted"])
	}
	if u := items[0].(map[string]any)["unsigned"].(map[string]any); u["repliers"].(float64) != 1 || u["replies"].(float64) != 2 {
		t.Fatalf("counts: %v", u)
	}
	const bound = 64 << 20
	if got := after.TotalAlloc - before.TotalAlloc; got > bound {
		t.Fatalf("one digest allocated %.1f MiB, bound %d MiB", float64(got)/(1<<20), bound>>20)
	}
}

// Finding 2, observable without the hook: the cursor moves past posts that
// were not eligible, so an empty window does not leave them to be read again.
func TestDigestCursorPassesIneligible(t *testing.T) {
	e, s := costEnv(t, unlimited)
	m := e.createChannel(alice, "pass-m", "members", "members", "open", nil)
	x := e.createChannel(alice, "pass-x", "public", "anyone", "open", nil)
	e.mustSubmit(e.tok(bob, "join", map[string]any{"channel": m}))
	e.mustSubmit(e.subTok(bob, m))
	e.mustSubmit(e.subTok(bob, x))
	e.mustSubmit(e.tok(bob, "leave", map[string]any{"channel": m})) // the sub survives the leave (§7.4)
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": x, "member": kid(eve)}))
	bulkLog(t, s, m, "u", 1500, func(int) string { return kid(carol) }, noRe, "v1.u")
	bulkLog(t, s, x, "b", 1500, func(int) string { return kid(eve) }, noRe, "v1.b")

	next := ""
	for page := 0; page < 10; page++ {
		items, r := e.rawDigest(bob, "after="+next)
		if len(items) != 0 {
			t.Fatalf("page %d: ineligible posts served: %v", page, items)
		}
		next = r.str("next")
		if r.body["more"] == false {
			break
		}
	}
	if next != "3000" {
		t.Fatalf("cursor after the ineligible rows: %q, want \"3000\"", next)
	}
}

// Finding 2, with the hook: rows read per request. A channel the reader may
// not read is never scanned; banned-author rows are read once, at most 2000
// a request (the budget), and never again once the cursor has passed them.
func TestDigestScanCost(t *testing.T) {
	e, s := costEnv(t, unlimited)
	m := e.createChannel(alice, "cost-m", "members", "members", "open", nil)
	x := e.createChannel(alice, "cost-x", "public", "anyone", "open", nil)
	e.mustSubmit(e.tok(bob, "join", map[string]any{"channel": m}))
	e.mustSubmit(e.subTok(bob, m))
	e.mustSubmit(e.subTok(bob, x))
	e.mustSubmit(e.tok(bob, "leave", map[string]any{"channel": m}))
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": x, "member": kid(eve)}))

	bulkLog(t, s, m, "u", 3000, func(int) string { return kid(carol) }, noRe, "v1.u")
	var r resp
	read := rowsRead(t, func() { _, r = e.rawDigest(bob, "") })
	if fmt.Sprint(read) != "[0]" || r.str("next") != "3000" || r.body["more"] != false {
		t.Fatalf("unreadable channel: read %v, %v", read, r.body)
	}

	bulkLog(t, s, x, "b", 4500, func(int) string { return kid(eve) }, noRe, "v1.b")
	bulkLog(t, s, x, "c", 1, func(int) string { return kid(carol) }, noRe, "v1.carol")
	type page struct {
		read  int
		next  string
		more  any
		items int
	}
	var pages []page
	next := "3000"
	read = rowsRead(t, func() {
		for i := 0; i < 4; i++ {
			items, r := e.rawDigest(bob, "after="+next)
			next = r.str("next")
			pages = append(pages, page{0, next, r.body["more"], len(items)})
			if len(items) == 1 && items[0] != "v1.carol" {
				t.Fatalf("served %v", items)
			}
		}
	})
	for i := range pages {
		pages[i].read = read[i]
	}
	want := []page{{2000, "5000", true, 0}, {2000, "7000", true, 0}, {501, "7501", false, 1}, {0, "7501", false, 0}}
	if fmt.Sprint(pages) != fmt.Sprint(want) {
		t.Fatalf("pages (read, next, more, items):\n got %v\nwant %v", pages, want)
	}
}

// The scan and the reply count run on index seeks: no sort, no full scan.
func TestDigestQueryPlans(t *testing.T) {
	_, s := costEnv(t)
	plan := func(q string, args ...any) string {
		t.Helper()
		rows, err := s.db.Query("EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatal(err)
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
		return strings.Join(lines, "\n")
	}
	scan := plan(digestScanSQL, "k_r", 1, "c_x", 0, 10)
	for _, want := range []string{"SEARCH l USING INDEX chan_log_channel (channel=? AND seq>?)", "SEARCH ob USING INDEX sqlite_autoindex_objects_1 (id=?)", "SEARCH b USING INDEX sqlite_autoindex_bans_1 (channel=? AND key=?)"} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan plan lacks %q:\n%s", want, scan)
		}
	}
	if strings.Contains(scan, "TEMP B-TREE") || strings.Contains(scan, "SCAN ") {
		t.Errorf("scan plan sorts or scans:\n%s", scan)
	}
	// The planner's choice depends on the number of parents (it flipped at
	// 20 before the join order was pinned), so check several chunk sizes,
	// up to the chunk limit.
	for _, n := range []int{1, 2, 20, 200, replyCountChunk} {
		args := []any{}
		for i := 0; i < n; i++ {
			args = append(args, fmt.Sprintf("m_%d", i), "k_a")
		}
		rc := plan(replyCountSQL(n), append(args, "c_x", 1)...)
		if !strings.Contains(rc, "SEARCH r USING INDEX chan_log_re (channel=? AND re=?)") || strings.Contains(rc, "SCAN r") {
			t.Errorf("%d parents: reply-count plan does not seek chan_log_re by (channel, re):\n%s", n, rc)
		}
	}
}

// A timed ban excludes the author's posts and replies while it is live, and
// from the moment until is reached they count again (banLive: until > now).
// The store-side filter (banLiveSQL) must agree with banLive at the boundary.
func TestDigestBanExpiry(t *testing.T) {
	e := newEnv(t, unlimited)
	x := e.createChannel(alice, "exp-x", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, x))
	p := e.post(carol, x, "p", "")
	ev := e.post(eve, x, "eve's post", "")
	er := e.post(eve, x, "eve replies to p", p)
	until := e.now.Load() + 3_600_000
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": x, "member": kid(eve), "until": until}))

	items, _ := e.digest(bob, "")
	wantItems(t, "ban live", items, dItem{p, 0, 0})
	e.now.Store(until - 1)
	items, _ = e.digest(bob, "")
	wantItems(t, "1 ms before until", items, dItem{p, 0, 0})
	e.now.Store(until)
	items, _ = e.digest(bob, "")
	wantItems(t, "at until", items, dItem{p, 1, 1}, dItem{er, 0, 0}, dItem{ev, 0, 0})
}

// Digest pages from after=next cover every eligible post exactly once, across
// interleaved channels, full windows and budget stops: the window sizes add
// up, and at least one page stopped on the budget.
func TestDigestPagesCoverEveryPostOnce(t *testing.T) {
	e, s := costEnv(t, unlimited)
	a := e.createChannel(alice, "pg-a", "public", "anyone", "open", nil)
	b := e.createChannel(alice, "pg-b", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, a))
	e.mustSubmit(e.subTok(bob, b))
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": b, "member": kid(eve)}))
	// Posts alternate a, b. In b every third is by banned eve, except in the
	// middle block, a run of 3000 by eve in b alone, which no page can read
	// past within one budget. Eligible: 1000 + 0 + 600 + 400 = 2000 of 5200.
	alt := func(i int) string {
		if i%2 == 0 {
			return a
		}
		return b
	}
	thirdEve := func(i int) string {
		switch {
		case i%2 == 0:
			return kid(carol)
		case (i/2)%3 == 0:
			return kid(eve)
		}
		return kid(dave)
	}
	bulkLogIn(t, s, alt, "x", 1000, func(i int) string { return []string{kid(carol), kid(dave)}[i%2] }, noRe, "v1.p")
	bulkLog(t, s, b, "y", 3000, func(int) string { return kid(eve) }, noRe, "v1.p")
	bulkLogIn(t, s, alt, "z", 1200, thirdEve, noRe, "v1.p")

	total, pages, next := 0, 0, ""
	read := rowsRead(t, func() {
		for ; pages < 20; pages++ {
			items, r := e.rawDigest(bob, "limit=50&per_channel=50&after="+next)
			total += len(items) + int(r.body["omitted"].(float64))
			next = r.str("next")
			if r.body["more"] == false {
				break
			}
		}
	})
	if total != 2000 || next != "5200" {
		t.Fatalf("pages covered %d eligible posts ending at %q, want 2000 ending at \"5200\" (rows read per page %v)", total, next, read)
	}
	if !strings.Contains(fmt.Sprint(read), "2000") {
		t.Fatalf("no page stopped on the budget: rows read per page %v", read)
	}
}

// The hub's digest equals the reference ranking (clankmail.RankDigest, pinned
// by the vectors) over the same log, for a seeded random log with replies
// within and across channels, self-replies, hidden posts and a ban.
func TestDigestMatchesReference(t *testing.T) {
	e := newEnv(t, unlimited)
	x := e.createChannel(alice, "ref-x", "public", "anyone", "open", nil)
	y := e.createChannel(alice, "ref-y", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, x))
	e.mustSubmit(e.subTok(bob, y))
	authors := []ed25519.PrivateKey{bob, carol, dave, eve, scout, alice}
	rng := rand.New(rand.NewSource(8))
	var log []clankmail.DigestPost
	hidden := map[string]bool{}
	for i := 0; i < 160; i++ {
		ch := x
		if rng.Intn(3) == 0 {
			ch = y
		}
		k := authors[rng.Intn(len(authors))]
		re := ""
		if len(log) > 0 && rng.Intn(3) != 0 {
			// Mostly one of the last few posts, so posts collect several
			// replies and repeat repliers; sometimes in the other channel.
			re = log[len(log)-1-rng.Intn(min(len(log), 6))].ID
		}
		id := e.post(k, ch, fmt.Sprintf("p%d", i), re)
		log = append(log, clankmail.DigestPost{ID: id, Channel: ch, From: kid(k), TS: e.now.Load() - 1000, Re: re})
		if rng.Intn(9) == 0 {
			e.mustSubmit(e.tok(k, "remove", map[string]any{"channel": ch, "target": id}))
			hidden[id] = true
		}
	}
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": y, "member": kid(eve)}))

	var posts []clankmail.DigestPost
	for _, p := range log {
		banned := p.Channel == y && p.From == kid(eve)
		if hidden[p.ID] || banned {
			continue
		}
		p.Window = p.From != kid(bob)
		posts = append(posts, p)
	}
	for _, q := range []struct{ limit, perCh int }{{50, 50}, {20, 5}, {7, 3}} {
		want, wantOmitted := clankmail.RankDigest(posts, q.limit, q.perCh)
		var wantItems []dItem
		for _, it := range want {
			wantItems = append(wantItems, dItem{it.ID, it.Repliers, it.Replies})
		}
		got, r := e.digest(bob, fmt.Sprintf("limit=%d&per_channel=%d", q.limit, q.perCh))
		if fmt.Sprint(got) != fmt.Sprint(wantItems) || r.body["omitted"].(float64) != float64(wantOmitted) {
			t.Fatalf("limit %d per_channel %d:\n got %v omitted %v\nwant %v omitted %d", q.limit, q.perCh, got, r.body["omitted"], wantItems, wantOmitted)
		}
	}
}

// GET /v1/digest is rate-limited per key and per client address (§8.1).
func TestDigestRateLimit(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.KeyLimit = Limit{Burst: 1e9, PerSec: 1e9}
		c.IPLimit = Limit{Burst: 1e9, PerSec: 1e9}
	})
	limited := func(what string, r resp) {
		t.Helper()
		if r.status != 429 || r.str("error") != ERate {
			t.Fatalf("%s: want 429 E_RATE, got %d %v", what, r.status, r.body)
		}
	}
	for i := 0; i < 30; i++ {
		wantOK(t, e.as(bob, "GET", "/v1/digest", nil))
	}
	limited("key burst of 30", e.as(bob, "GET", "/v1/digest", nil))
	wantOK(t, e.as(carol, "GET", "/v1/digest", nil)) // per key
	e.advance(2 * time.Second)                       // refills one at 0.5/s
	wantOK(t, e.as(bob, "GET", "/v1/digest", nil))
	limited("key refill of 0.5/s", e.as(bob, "GET", "/v1/digest", nil))

	// Per address: a burst of 120 from this client, whichever keys sign,
	// charged before auth, refilling at 2/s. Above: 32 charged, +4 refilled
	// over the 2 s, 2 more charged, so 90 are left for fresh keys.
	for i := 0; i < 90; i++ {
		wantOK(t, e.as(key(fmt.Sprintf("digest-ip-%d", i)), "GET", "/v1/digest", nil))
	}
	r := e.as(key("digest-ip-fresh"), "GET", "/v1/digest", nil)
	limited("address burst of 120", r)
	if !strings.Contains(r.str("detail"), "client address") {
		t.Fatalf("want the address limit, got %v", r.body)
	}
}
