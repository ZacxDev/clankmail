package hub

// Regression tests for PR #2 audit rounds 1 and 2. Round-1 tests were
// measured red at 8dc466b, the byte-identical (hub code) rebase of 1658234
// that the audit read; round-2 tests were measured red at d077193. All pass
// after their fixes.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// 🔴1: a live ban overrides the mods list and membership (§7.3).
func TestBannedModLosesPowers(t *testing.T) {
	e := newEnv(t)
	cid := e.createChannel(alice, "mods-club", "members", "members", "approval",
		map[string]any{"mods": []any{kid(carol)}})
	logPath := "/v1/channels/" + cid + "/log"
	e.mustSubmit(e.tok(dave, "join", map[string]any{"channel": cid}))
	e.mustSubmit(e.tok(eve, "join", map[string]any{"channel": cid}))
	e.mustSubmit(e.tok(bob, "join", map[string]any{"channel": cid}))
	e.mustSubmit(e.tok(alice, "admit", map[string]any{"channel": cid, "member": kid(bob)}))
	removedID := e.mustSubmit(e.tok(bob, "msg", map[string]any{"to": []any{cid}, "body": "to be removed"}))
	e.mustSubmit(e.tok(alice, "remove", map[string]any{"channel": cid, "target": removedID}))
	visibleID := e.mustSubmit(e.tok(bob, "msg", map[string]any{"to": []any{cid}, "body": "visible"}))

	// Positive controls: before the ban carol has every power under test.
	e.mustSubmit(e.tok(carol, "admit", map[string]any{"channel": cid, "member": kid(eve)}))
	wantOK(t, e.as(carol, "GET", logPath, nil))
	wantOK(t, e.as(carol, "GET", "/v1/objects/"+removedID, nil))
	wantOK(t, e.as(carol, "GET", "/v1/objects/"+visibleID, nil))
	wantOK(t, e.as(bob, "GET", "/v1/objects/"+removedID, nil)) // the author sees its own removed post

	e.advance(time.Second)
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": cid, "member": kid(carol)}))

	for what, tok := range map[string]string{
		"admit":  e.tok(carol, "admit", map[string]any{"channel": cid, "member": kid(dave)}),
		"ban":    e.tok(carol, "ban", map[string]any{"channel": cid, "member": kid(bob)}),
		"remove": e.tok(carol, "remove", map[string]any{"channel": cid, "target": visibleID}),
	} {
		r := e.submit(tok)
		if r.status != 403 || r.str("error") != EForbidden {
			t.Errorf("banned mod %s: want 403 E_FORBIDDEN, got %d %v", what, r.status, r.body)
		}
	}
	if r := e.as(carol, "GET", logPath, nil); r.status != 403 || r.str("error") != EForbidden {
		t.Errorf("banned mod members-log read: want 403 E_FORBIDDEN, got %d %v", r.status, r.body)
	}
	for what, id := range map[string]string{"removed post": removedID, "members-only post": visibleID} {
		if r := e.as(carol, "GET", "/v1/objects/"+id, nil); r.status != 404 || r.str("error") != ENotFound {
			t.Errorf("banned mod fetch of %s: want 404 E_NOT_FOUND, got %d %v", what, r.status, r.body)
		}
	}
	// Control: the visible post is still there for an unbanned member.
	wantOK(t, e.as(eve, "GET", "/v1/objects/"+visibleID, nil))

	// A banned AUTHOR loses access to its removed post and cannot remove.
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": cid, "member": kid(bob)}))
	if r := e.as(bob, "GET", "/v1/objects/"+removedID, nil); r.status != 404 {
		t.Errorf("banned author fetch of its removed post: want 404, got %d %v", r.status, r.body)
	}
	if r := e.submit(e.tok(bob, "remove", map[string]any{"channel": cid, "target": visibleID})); r.status != 403 {
		t.Errorf("banned author remove: want 403, got %d %v", r.status, r.body)
	}
}

// 🟡2a (as corrected by round 2): forbidden FRESH submissions pay the
// signer's key; idempotent retries of a stored token do not.
func TestForbiddenSubmitsChargeKeyLimitRetriesDoNot(t *testing.T) {
	e := newEnv(t)
	cid := e.createChannel(alice, "owner-only", "public", "owner", "open", nil)
	n := int(DefaultKeyLimit.Burst)
	for i := 0; i < n; i++ {
		wantErr(t, e.submit(e.tok(bob, "msg", map[string]any{"to": []any{cid}, "body": "nope " + strings.Repeat("x", i+1)})), 403, EForbidden)
	}
	wantErr(t, e.submit(e.tok(bob, "msg", map[string]any{"to": []any{cid}, "body": "one more"})), 429, ERate)

	m := e.dm(scout, "retried", carol)
	e.mustSubmit(m)
	for i := 0; i < 2*n; i++ {
		wantOK(t, e.submit(m))
	}
	// The retries left scout's budget untouched.
	e.mustSubmit(e.dm(scout, "fresh after many retries", carol))
}

// Round 2 🔴: replaying a victim's stored or stale tokens, from another
// client address, must not drain the victim's per-key budget (it could
// otherwise block the victim's revoke).
func TestReplayCannotDrainVictimKeyLimit(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
	cid := e.createChannel(alice, "alice-says", "public", "owner", "open", nil)
	post := e.tok(alice, "msg", map[string]any{"to": []any{cid}, "body": "public post"})
	e.mustSubmit(post)
	handle := e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName})
	e.mustSubmit(handle)
	stale := e.tokAt(alice, -10*time.Minute, "msg", map[string]any{"to": []any{cid}, "body": "signed long ago"})

	replay := func(tok string) resp {
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/submit", strings.NewReader(tok))
		req.Header.Set("X-Forwarded-For", "203.0.113.66") // the attacker's address
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out := resp{status: res.StatusCode}
		json.NewDecoder(res.Body).Decode(&out.body)
		return out
	}
	for i := 0; i < 70; i++ { // 70 stale replays alone exceed the 60-token burst
		wantOK(t, replay(post))
		wantOK(t, replay(handle))
		wantErr(t, replay(stale), 400, EStale)
	}
	// 210 replays later, alice's next fresh post is accepted.
	r := e.submit(e.tok(alice, "msg", map[string]any{"to": []any{cid}, "body": "still mine"}))
	if r.status != 200 {
		t.Fatalf("victim's fresh post after 210 replays: want 200, got %d %v", r.status, r.body)
	}
}

// Round 2 🟡: the hub re-reads the EXACT keys "to" and "re", never a
// case-insensitive match. A payload with both "to" and "TO" verifies with
// to=[bob]; the hub must read [bob] too.
func TestStoredFieldsReadExactKeys(t *testing.T) {
	e := newEnv(t)
	// Literal bytes: "TO" comes after "to" so a case-insensitive decoder
	// would let it win.
	payload := fmt.Sprintf(`{"v":1,"t":"msg","from":"%s","ts":%d,"to":["%s"],"TO":["%s"],"body":"for bob only"}`,
		kid(scout), e.now.Load(), kid(bob), kid(eve))
	m := clankmail.Sign(scout, []byte(payload))
	id := e.mustSubmit(m)
	if r := e.as(bob, "GET", "/v1/objects/"+id, nil); r.status != 200 {
		t.Errorf("bob (in to) fetching his DM: want 200, got %d %v", r.status, r.body)
	}
	if r := e.as(eve, "GET", "/v1/objects/"+id, nil); r.status != 404 {
		t.Errorf("eve (only in TO) fetching bob's DM: want 404, got %d %v", r.status, r.body)
	}
	// The reply rule reads the same key: eve citing it is a stranger.
	reply := e.tok(eve, "msg", map[string]any{"to": []any{kid(scout)}, "body": "re", "re": id})
	e.mustSubmit(reply)
	if has(e.queue(scout, "inbox"), reply) {
		t.Errorf("eve, named only in TO, used the reply route into scout's inbox")
	}
}

// 🟡2b: the per-client-address limit is charged before signature
// verification, so malformed tokens cost budget too.
func TestMalformedSubmitsChargeAddressLimit(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.IPLimit = Limit{Burst: 3, PerSec: 0.001} })
	for i := 0; i < 3; i++ {
		r := e.submit("not-a-token")
		if r.status != 400 {
			t.Fatalf("garbage %d: %d %v", i, r.status, r.body)
		}
	}
	wantErr(t, e.submit(e.dm(scout, "valid, but the address is spent", bob)), 429, ERate)
}

// 🟡3: stored tokens were verified at acceptance and are re-read without a
// second Ed25519 verification. Observed by corrupting a stored signature in
// the database: a hub that re-verifies drops the token from the reply rule,
// the thread walk and the DM visibility check; one that re-reads keeps it.
func TestStoredTokensAreNotReverified(t *testing.T) {
	var store *SQLite
	e := newEnv(t, func(c *Config) { store = c.Store.(*SQLite) })
	m1 := e.dm(scout, "root", bob)
	m1ID := e.mustSubmit(m1)
	parts := strings.Split(m1, ".")
	tampered := strings.Join(append(parts[:3:3], flipB64(parts[3])), ".")
	if _, err := store.db.Exec(`UPDATE objects SET token=? WHERE id=?`, tampered, m1ID); err != nil {
		t.Fatal(err)
	}

	reply := e.tok(bob, "msg", map[string]any{"to": []any{kid(scout)}, "body": "reply", "re": m1ID})
	e.mustSubmit(reply)
	if !has(e.queue(scout, "inbox"), reply) {
		t.Errorf("reply rule re-verified the stored message: reply not in scout's inbox")
	}
	if got := e.threads(scout, "inbox")[reply]; got != m1ID {
		t.Errorf("thread walk re-verified the stored message: thread = %v, want %s", got, m1ID)
	}
	if r := e.as(bob, "GET", "/v1/objects/"+m1ID, nil); r.status != 200 {
		t.Errorf("DM visibility re-verified the stored message: recipient got %d %v", r.status, r.body)
	}
}

// gateStore blocks the next Tx after arm() until release, so a test can
// interleave two requests deterministically.
type gateStore struct {
	Store
	armed            atomic.Bool
	entered, release chan struct{}
}

func (g *gateStore) Tx(ctx context.Context, fn func(Ops) error) error {
	if g.armed.CompareAndSwap(true, false) {
		g.entered <- struct{}{}
		<-g.release
	}
	return g.Store.Tx(ctx, fn)
}

// 🟢4: freshness, pruning and the replay check share one `now` read inside
// the transaction. Interleaving: R (a replay of a used auth) passes the
// freshness check, then waits; P, a later request, prunes R's id; R then
// must not be accepted as new.
func TestAuthReplayCannotSlipPastPrune(t *testing.T) {
	g := &gateStore{entered: make(chan struct{}), release: make(chan struct{})}
	e := newEnv(t, func(c *Config) { g.Store = c.Store; c.Store = g })
	p := "/v1/inbox?queue=inbox"
	hdr := e.authFor(bob, 0, "GET", p, nil, nil)
	wantOK(t, e.do("GET", p, nil, hdr))

	e.advance(59 * time.Second) // the replay is still inside ±60 s
	g.armed.Store(true)
	done := make(chan resp, 1)
	go func() {
		req, _ := http.NewRequest("GET", e.srv.URL+p, nil)
		req.Header.Set("Authorization", hdr)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- resp{status: -1}
			return
		}
		defer res.Body.Close()
		out := resp{status: res.StatusCode}
		json.NewDecoder(res.Body).Decode(&out.body)
		done <- out
	}()
	<-g.entered
	e.advance(66 * time.Second) // P's prune now drops ids older than the window
	wantOK(t, e.as(alice, "GET", p, nil))
	close(g.release)
	r := <-done
	if r.status != 401 || r.str("error") != EAuth {
		t.Fatalf("replayed auth after a prune: want 401 E_AUTH, got %d %v", r.status, r.body)
	}
}

// 🟢5: a malformed path parameter is 400 E_QUERY (§8); a well-formed one
// that names nothing is still 404.
func TestMalformedPathParams(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{
		"/v1/objects/m_bad", "/v1/objects/zzz", "/v1/objects/" + "m_" + strings.Repeat("A", 52),
		"/v1/channels/c_bad", "/v1/channels/" + url.PathEscape("#Bad_Slug"), "/v1/channels/x",
		"/v1/channels/c_bad/log",
		"/v1/handles/A!", "/v1/handles/a",
	} {
		r := e.do("GET", p, nil, "")
		if r.status != 400 || r.str("error") != EQuery {
			t.Errorf("%s: want 400 E_QUERY, got %d %v", p, r.status, r.body)
		}
	}
	missing := strings.Repeat("a", 52)
	for _, p := range []string{
		"/v1/objects/m_" + missing, "/v1/channels/c_" + missing, "/v1/channels/c_" + missing + "/log",
		"/v1/channels/" + url.PathEscape("#nosuch"), "/v1/handles/nobody",
	} {
		if r := e.do("GET", p, nil, ""); r.status != 404 || r.str("error") != ENotFound {
			t.Errorf("%s: want 404 E_NOT_FOUND, got %d %v", p, r.status, r.body)
		}
	}
}
