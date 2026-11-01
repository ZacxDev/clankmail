package hub

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// ---- subscriptions (§7.4) and the digest (§8.1) ----

func (e *env) subTok(k ed25519.PrivateKey, cid string) string {
	return e.tok(k, "sub", map[string]any{"channel": cid})
}

func (e *env) post(k ed25519.PrivateKey, cid, body, re string) string {
	e.t.Helper()
	f := map[string]any{"to": []any{cid}, "body": body}
	if re != "" {
		f["re"] = re
	}
	id := e.mustSubmit(e.tok(k, "msg", f))
	e.advance(time.Second) // distinct ts, so recency is never a tie
	return id
}

type dItem struct {
	id                string
	repliers, replies int
}

// digest fetches k's digest; it fails the test on a non-200.
func (e *env) digest(k ed25519.PrivateKey, query string) ([]dItem, resp) {
	e.t.Helper()
	r := e.as(k, "GET", "/v1/digest?"+query, nil)
	wantOK(e.t, r)
	var out []dItem
	for _, it := range r.body["items"].([]any) {
		m := it.(map[string]any)
		u := m["unsigned"].(map[string]any)
		out = append(out, dItem{idOf(e.t, m["token"].(string)), int(u["repliers"].(float64)), int(u["replies"].(float64))})
	}
	return out, r
}

func wantItems(t *testing.T, what string, got []dItem, want ...dItem) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func unlimited(c *Config) {
	c.KeyLimit = Limit{Burst: 1e9, PerSec: 1e9}
	c.IPLimit = Limit{Burst: 1e9, PerSec: 1e9}
}

func TestSubAcceptance(t *testing.T) {
	e := newEnv(t, unlimited)
	x := e.createChannel(alice, "sub-x", "public", "anyone", "open", nil)

	// Auth is required on both endpoints.
	wantErr(t, e.do("GET", "/v1/subs", nil, ""), 401, EAuth)
	wantErr(t, e.do("GET", "/v1/digest", nil, ""), 401, EAuth)
	stale := e.authFor(bob, -2*time.Minute, "GET", "/v1/digest", nil, nil)
	wantErr(t, e.do("GET", "/v1/digest", nil, stale), 401, EAuth)

	// Unknown channel: 404, as for every channel-scoped object.
	wantErr(t, e.submit(e.subTok(bob, "c_"+idOf(t, e.dm(alice, "not a channel", bob))[2:])), 404, ENotFound)

	sid := e.mustSubmit(e.subTok(bob, x))
	e.advance(time.Second)
	// One live sub per (key, channel); a fresh sub for the same channel is refused.
	wantErr(t, e.submit(e.subTok(bob, x)), 403, EForbidden)

	// A sub is private to its signer.
	wantErr(t, e.do("GET", "/v1/objects/"+sid, nil, ""), 404, ENotFound)
	wantErr(t, e.as(carol, "GET", "/v1/objects/"+sid, nil), 404, ENotFound)
	if r := e.as(bob, "GET", "/v1/objects/"+sid, nil); r.status != 200 || idOf(t, r.str("token")) != sid {
		t.Fatalf("signer fetch of own sub: %d %v", r.status, r.body)
	}

	subs := func(k ed25519.PrivateKey) []string {
		r := e.as(k, "GET", "/v1/subs", nil)
		wantOK(t, r)
		var ids []string
		for _, it := range r.body["items"].([]any) {
			m := it.(map[string]any)
			if m["channel"] != x {
				t.Fatalf("sub listed for channel %v", m["channel"])
			}
			ids = append(ids, idOf(t, m["token"].(string)))
		}
		return ids
	}
	if s := subs(bob); len(s) != 1 || s[0] != sid {
		t.Fatalf("bob's subs: %v", s)
	}
	if s := subs(carol); len(s) != 0 {
		t.Fatalf("carol's subs: %v", s)
	}

	// Only the signer may revoke it; after the revoke a new sub is accepted.
	wantErr(t, e.submit(e.tok(carol, "revoke", map[string]any{"target": sid})), 403, EForbidden)
	e.mustSubmit(e.tok(bob, "revoke", map[string]any{"target": sid}))
	if s := subs(bob); len(s) != 0 {
		t.Fatalf("revoked sub still listed: %v", s)
	}
	e.advance(time.Second) // re-sign: the refused bytes stay refused for the window (§5)
	e.mustSubmit(e.subTok(bob, x))

	// The live-subscription cap: bob holds 1, so 99 more are accepted and the next is E_RATE.
	for i := 0; i < maxLiveSubs; i++ {
		c := e.createChannel(key(fmt.Sprintf("owner-%d", i)), fmt.Sprintf("cap-%d", i), "public", "anyone", "open", nil)
		r := e.submit(e.subTok(bob, c))
		if i < maxLiveSubs-1 {
			if r.status != 200 {
				t.Fatalf("sub %d of %d refused: %d %v", i+2, maxLiveSubs, r.status, r.body)
			}
			continue
		}
		wantErr(t, r, 429, ERate)
	}

	// A key under the kill switch cannot read its digest (§6.3 rule 1).
	gid := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": gid}))
	e.mustSubmit(e.subTok(scout, x))
	wantOK(t, e.as(scout, "GET", "/v1/digest", nil))
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": gid}))
	wantErr(t, e.as(scout, "GET", "/v1/digest", nil), 403, ERevoked)
}

// Every §8.1 eligibility rule that depends on hub state, plus the counts and
// the ranking, in one channel the subscriber reads.
func TestDigestEligibilityAndRanking(t *testing.T) {
	e := newEnv(t, unlimited)
	x := e.createChannel(alice, "dig-x", "public", "anyone", "open", nil)
	y := e.createChannel(alice, "dig-y", "public", "anyone", "open", nil)

	e.post(carol, x, "before the sub", "")      // rule 2: predates the sub
	e.mustSubmit(e.subTok(bob, x))              //
	c1 := e.post(carol, x, "c1", "")            //
	d1 := e.post(dave, x, "d1", "")             //
	e.post(bob, x, "bob's own post", "")        // rule 4: own post
	e.post(eve, x, "eve's post", "")            // rule 5: eve is banned below
	e.post(eve, x, "eve replies to c1", c1)     // banned author: not a candidate, not counted
	hid := e.post(dave, x, "to be removed", "") // rule 1: hidden
	e.mustSubmit(e.tok(dave, "remove", map[string]any{"channel": x, "target": hid}))
	hr := e.post(scout, x, "removed reply to c1", c1) // hidden reply: not counted
	e.mustSubmit(e.tok(scout, "remove", map[string]any{"channel": x, "target": hr}))
	e.post(carol, y, "y is not subscribed", "") // rule 2: no sub
	r1 := e.post(alice, x, "alice on d1", d1)
	r2 := e.post(carol, x, "carol on d1", d1)
	e.post(bob, x, "bob on c1", c1) // bob's own reply is not a candidate but counts
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": x, "member": kid(eve)}))

	items, r := e.digest(bob, "")
	wantItems(t, "bob's digest", items, dItem{d1, 2, 2}, dItem{c1, 1, 1}, dItem{r2, 0, 0}, dItem{r1, 0, 0})
	if r.body["omitted"].(float64) != 0 || r.body["more"] != false {
		t.Fatalf("omitted/more: %v", r.body)
	}

	// Control: a key with no subscription sees nothing, and its cursor stays put.
	items, r = e.digest(scout, "")
	if len(items) != 0 || r.str("next") != "0" {
		t.Fatalf("non-subscriber digest: %v", r.body)
	}
}

func TestDigestMembersOnlyChannel(t *testing.T) {
	e := newEnv(t, unlimited)
	m := e.createChannel(alice, "dig-m", "members", "members", "approval", nil)

	wantErr(t, e.submit(e.subTok(bob, m)), 403, EForbidden) // not a member
	e.mustSubmit(e.tok(bob, "join", map[string]any{"channel": m}))
	wantErr(t, e.submit(e.subTok(bob, m)), 403, EForbidden) // pending
	e.mustSubmit(e.tok(alice, "admit", map[string]any{"channel": m, "member": kid(bob)}))
	e.advance(time.Second) // re-sign: the refused bytes stay refused for the window (§5)
	msid := e.mustSubmit(e.subTok(bob, m))

	p1 := e.post(alice, m, "members only", "")
	items, _ := e.digest(bob, "")
	wantItems(t, "member", items, dItem{p1, 0, 0})

	// Leaving keeps the sub but stops the channel contributing.
	e.mustSubmit(e.tok(bob, "leave", map[string]any{"channel": m}))
	items, r := e.digest(bob, "")
	wantItems(t, "after leave", items)
	if r.str("next") != "0" {
		t.Fatalf("an empty window must not move the cursor: %v", r.body)
	}
	e.mustSubmit(e.tok(bob, "join", map[string]any{"channel": m}))
	e.mustSubmit(e.tok(alice, "admit", map[string]any{"channel": m, "member": kid(bob)}))
	items, _ = e.digest(bob, "")
	wantItems(t, "after rejoin", items, dItem{p1, 0, 0})

	// A ban removes access: nothing from the channel, and no new sub.
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": m, "member": kid(bob)}))
	items, _ = e.digest(bob, "")
	wantItems(t, "banned subscriber", items)
	e.mustSubmit(e.tok(bob, "revoke", map[string]any{"target": msid}))
	e.advance(time.Second)
	wantErr(t, e.submit(e.subTok(bob, m)), 403, EForbidden)
}

func TestDigestCursor(t *testing.T) {
	e := newEnv(t, unlimited)
	x := e.createChannel(alice, "cur-x", "public", "anyone", "open", nil)
	y := e.createChannel(alice, "cur-y", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, x))
	e.mustSubmit(e.subTok(bob, y))

	y1 := e.post(dave, y, "y1", "")
	e.post(carol, x, "x1", "")
	e.post(carol, x, "x2", "") // the last window post, and capped out below
	e.post(bob, y, "bob on y1", y1)

	items, r := e.digest(bob, "limit=1")
	wantItems(t, "limit 1", items, dItem{y1, 1, 1})
	if r.body["omitted"].(float64) != 2 {
		t.Fatalf("omitted: %v", r.body)
	}
	next := r.str("next")

	// At-least-once: a retry without advancing reconsiders the same posts.
	items, r = e.digest(bob, "limit=1")
	wantItems(t, "retry", items, dItem{y1, 1, 1})
	if r.str("next") != next {
		t.Fatalf("retry next %s, want %s", r.str("next"), next)
	}

	// The cursor moved past the capped-out x1 and x2: they are not offered again.
	items, r = e.digest(bob, "after="+next)
	wantItems(t, "after next", items)
	if r.str("next") != next {
		t.Fatalf("empty window moved the cursor: %s -> %s", next, r.str("next"))
	}
	x3 := e.post(carol, x, "x3", "")
	items, r = e.digest(bob, "after="+next)
	wantItems(t, "new post", items, dItem{x3, 0, 0})
	if r.str("next") == next {
		t.Fatal("cursor did not advance")
	}

	for _, q := range []string{"limit=0", "limit=51", "limit=x", "per_channel=0", "per_channel=51", "after=-1", "after=abc"} {
		wantErr(t, e.as(bob, "GET", "/v1/digest?"+q, nil), 400, EQuery)
	}
}

func TestDigestDefaultsAndCaps(t *testing.T) {
	e := newEnv(t, unlimited)
	z := e.createChannel(alice, "caps-z", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, z))
	var ids []string
	for i := 0; i < 21; i++ {
		ids = append(ids, e.post(carol, z, fmt.Sprintf("z%d", i), ""))
	}
	// Equal counts: newest first.
	newest := func(n int) []dItem {
		var out []dItem
		for i := 0; i < n; i++ {
			out = append(out, dItem{ids[20-i], 0, 0})
		}
		return out
	}
	for _, c := range []struct {
		q       string
		n       int
		omitted float64
	}{
		{"", 5, 16},                        // per_channel defaults to 5
		{"per_channel=50", 20, 1},          // limit defaults to 20
		{"per_channel=50&limit=50", 21, 0}, // both explicit
		{"per_channel=3&limit=2", 2, 19},
	} {
		items, r := e.digest(bob, c.q)
		wantItems(t, "?"+c.q, items, newest(c.n)...)
		if r.body["omitted"].(float64) != c.omitted {
			t.Fatalf("?%s omitted %v, want %v", c.q, r.body["omitted"], c.omitted)
		}
	}
}

func TestDigestWindow(t *testing.T) {
	e := newEnv(t, unlimited)
	w := e.createChannel(alice, "win-w", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, w))
	// Literals, not digestWindow: an expectation derived from the constant
	// cannot see the constant change.
	const n = 1002
	for i := 0; i < n; i++ {
		e.mustSubmit(e.tok(carol, "msg", map[string]any{"to": []any{w}, "body": fmt.Sprintf("w%d", i)}))
	}
	items, r := e.digest(bob, "")
	if len(items) != 5 || r.body["omitted"].(float64) != 995 || r.body["more"] != true {
		t.Fatalf("first window: %d items, omitted %v, more %v", len(items), r.body["omitted"], r.body["more"])
	}
	items, r = e.digest(bob, "after="+r.str("next"))
	if len(items) != 2 || r.body["omitted"].(float64) != 0 || r.body["more"] != false {
		t.Fatalf("second window: %d items, omitted %v, more %v", len(items), r.body["omitted"], r.body["more"])
	}
	items, _ = e.digest(bob, "after="+r.str("next"))
	wantItems(t, "third window", items)
}

func TestRevokedSubStopsDelivery(t *testing.T) {
	e := newEnv(t, unlimited)
	x := e.createChannel(alice, "rev-x", "public", "anyone", "open", nil)
	sid := e.mustSubmit(e.subTok(bob, x))
	p1 := e.post(carol, x, "p1", "")
	items, _ := e.digest(bob, "")
	wantItems(t, "live sub", items, dItem{p1, 0, 0})

	e.mustSubmit(e.tok(bob, "revoke", map[string]any{"target": sid}))
	items, _ = e.digest(bob, "")
	wantItems(t, "after revoke", items)

	// A new sub covers posts from its own acceptance only.
	e.mustSubmit(e.subTok(bob, x))
	items, _ = e.digest(bob, "")
	wantItems(t, "resubscribed", items)
	p2 := e.post(carol, x, "p2", "")
	items, _ = e.digest(bob, "")
	wantItems(t, "post after resubscribe", items, dItem{p2, 0, 0})
}

// A database written before chan_log.re existed is migrated on open, and its
// stored replies count.
func TestLogReMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, unlimited, func(c *Config) { c.Store = s1 })
	x := e.createChannel(alice, "mig-x", "public", "anyone", "open", nil)
	e.mustSubmit(e.subTok(bob, x))
	p := e.post(carol, x, "parent", "")
	e.post(dave, x, "reply", p)
	if _, err := s1.db.Exec(`ALTER TABLE chan_log DROP COLUMN re`); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() })
	e2 := newEnv(t, unlimited, func(c *Config) { c.Store = s2 })
	e2.advance(time.Hour) // fresh auth ids: the old ones are in this database
	items, _ := e2.digest(bob, "")
	if len(items) != 2 || items[0] != (dItem{p, 1, 1}) {
		t.Fatalf("migrated digest: %v", items)
	}
}
