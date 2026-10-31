package hub

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

const hubName = "hub.example"

// t0 is 2027-01-15T08:00:00Z, chosen so no fixture ts equals a round number.
const t0 = int64(1_800_000_000_000)

// ---- harness ----

type env struct {
	t     *testing.T
	srv   *httptest.Server
	now   atomic.Int64
	nonce atomic.Int64
}

func newEnv(t *testing.T, opts ...func(*Config)) *env {
	t.Helper()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	e := &env{t: t}
	e.now.Store(t0)
	cfg := Config{Name: hubName, Store: store, Now: func() time.Time { return time.UnixMilli(e.now.Load()) }}
	for _, o := range opts {
		o(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) advance(d time.Duration) { e.now.Add(d.Milliseconds()) }

// key derives a fixed Ed25519 key from a name.
func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("clankmail-hub-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func kid(priv ed25519.PrivateKey) string { return clankmail.KeyID(priv.Public().(ed25519.PublicKey)) }

var (
	alice = key("alice")
	bob   = key("bob")
	carol = key("carol")
	dave  = key("dave")
	scout = key("scout")
	eve   = key("eve")
)

// tokAt signs a payload of type typ with ts = hub now + offset.
func (e *env) tokAt(priv ed25519.PrivateKey, offset time.Duration, typ string, fields map[string]any) string {
	p := map[string]any{"v": 1, "t": typ, "from": kid(priv), "ts": e.now.Load() + offset.Milliseconds()}
	for k, v := range fields {
		p[k] = v
	}
	b, err := json.Marshal(p)
	if err != nil {
		e.t.Fatal(err)
	}
	return clankmail.Sign(priv, b)
}

func (e *env) tok(priv ed25519.PrivateKey, typ string, fields map[string]any) string {
	return e.tokAt(priv, 0, typ, fields)
}

func idOf(t *testing.T, token string) string {
	o, err := clankmail.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	return o.ID
}

type resp struct {
	status int
	body   map[string]any
}

func (r resp) str(k string) string { s, _ := r.body[k].(string); return s }

func (e *env) do(method, path string, body []byte, hdr string) resp {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if hdr != "" {
		req.Header.Set("Authorization", hdr)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{status: res.StatusCode}
	if err := json.Unmarshal(raw, &out.body); err != nil {
		e.t.Fatalf("%s %s: non-JSON response %q", method, path, raw)
	}
	return out
}

func (e *env) submit(token string) resp {
	e.t.Helper()
	return e.do("POST", "/v1/submit", []byte(token), "")
}

// mustSubmit submits and fails the test unless the hub accepts. Returns the id.
func (e *env) mustSubmit(token string) string {
	e.t.Helper()
	r := e.submit(token)
	if r.status != 200 || r.str("id") != idOf(e.t, token) {
		e.t.Fatalf("submit rejected: %d %v", r.status, r.body)
	}
	return r.str("id")
}

// authFor builds an auth token for an exact request. A nonce (an unknown,
// ignored field) keeps two otherwise-identical requests from sharing an id.
func (e *env) authFor(priv ed25519.PrivateKey, offset time.Duration, method, path string, body []byte, over map[string]any) string {
	sum := sha256.Sum256(body)
	f := map[string]any{"hub": hubName, "method": method, "path": path,
		"body": hex.EncodeToString(sum[:]), "n": fmt.Sprintf("n%d", e.nonce.Add(1))}
	for k, v := range over {
		f[k] = v
	}
	return "ClankMail " + e.tokAt(priv, offset, "auth", f)
}

// as performs an authenticated request.
func (e *env) as(priv ed25519.PrivateKey, method, path string, body []byte) resp {
	e.t.Helper()
	return e.do(method, path, body, e.authFor(priv, 0, method, path, body, nil))
}

func wantErr(t *testing.T, r resp, status int, code string) {
	t.Helper()
	if r.status != status || r.str("error") != code {
		t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.body)
	}
}

func wantOK(t *testing.T, r resp) {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("want 200, got %d %v", r.status, r.body)
	}
}

// tokens returns the token strings of an inbox/log page.
func tokens(r resp) []string {
	var out []string
	items, _ := r.body["items"].([]any)
	for _, it := range items {
		out = append(out, it.(map[string]any)["token"].(string))
	}
	return out
}

func (e *env) queue(priv ed25519.PrivateKey, q string) []string {
	e.t.Helper()
	r := e.as(priv, "GET", "/v1/inbox?queue="+q, nil)
	wantOK(e.t, r)
	return tokens(r)
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (e *env) dm(from ed25519.PrivateKey, body string, to ...ed25519.PrivateKey) string {
	ks := make([]any, len(to))
	for i, k := range to {
		ks[i] = kid(k)
	}
	return e.tok(from, "msg", map[string]any{"to": ks, "body": body})
}

// ---- 1. handle + grant + enroll ----

func grantTok(e *env, principal, agent ed25519.PrivateKey, name string, extra map[string]any) string {
	f := map[string]any{"agent": kid(agent), "name": name, "hub": hubName}
	for k, v := range extra {
		f[k] = v
	}
	return e.tok(principal, "grant", f)
}

func (e *env) agents(name string) []map[string]any {
	e.t.Helper()
	r := e.do("GET", "/v1/handles/"+name, nil, "")
	wantOK(e.t, r)
	var out []map[string]any
	for _, a := range r.body["agents"].([]any) {
		out = append(out, a.(map[string]any))
	}
	return out
}

func TestHandleGrantEnrollResolve(t *testing.T) {
	e := newEnv(t)
	h := e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName})
	g := grantTok(e, alice, scout, "scout", nil)
	e.mustSubmit(h)
	gid := e.mustSubmit(g)

	r := e.do("GET", "/v1/handles/alice", nil, "")
	wantOK(t, r)
	if r.str("handle") != h {
		t.Fatalf("handle token: %v", r.body)
	}
	// A grant alone is not a binding: the agent has not consented.
	if a := e.agents("alice"); len(a) != 0 {
		t.Fatalf("un-enrolled grant listed: %v", a)
	}
	en := e.tok(scout, "enroll", map[string]any{"grant": gid})
	e.mustSubmit(en)
	if a := e.agents("alice"); len(a) != 1 || a[0]["grant"] != g || a[0]["enroll"] != en {
		t.Fatalf("agents: %v", a)
	}
	// Identity objects are public by id.
	for _, tok := range []string{h, g, en} {
		if r := e.do("GET", "/v1/objects/"+idOf(t, tok), nil, ""); r.status != 200 || r.str("token") != tok {
			t.Fatalf("public object: %v", r.body)
		}
	}
	wantErr(t, e.do("GET", "/v1/handles/nobody", nil, ""), 404, ENotFound)
}

func TestEnrollRules(t *testing.T) {
	e := newEnv(t)
	gid := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	// Only the key the grant names may enroll on it.
	r := e.submit(e.tok(dave, "enroll", map[string]any{"grant": gid}))
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "agent") {
		t.Fatalf("wrong reason: %v", r.body)
	}
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": gid}))

	// At most one live enroll per key.
	g2 := e.mustSubmit(grantTok(e, carol, scout, "helper", nil))
	r = e.submit(e.tok(scout, "enroll", map[string]any{"grant": g2}))
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "already has a live enroll") {
		t.Fatalf("wrong reason: %v", r.body)
	}

	// No enroll on a revoked grant.
	g3 := e.mustSubmit(grantTok(e, bob, dave, "d", nil))
	e.mustSubmit(e.tok(bob, "revoke", map[string]any{"target": g3}))
	r = e.submit(e.tok(dave, "enroll", map[string]any{"grant": g3}))
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "revoked or expired") {
		t.Fatalf("wrong reason: %v", r.body)
	}
}

func TestGrantExpiryHidesBinding(t *testing.T) {
	e := newEnv(t)
	e.mustSubmit(e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName}))
	gid := e.mustSubmit(grantTok(e, alice, scout, "scout", map[string]any{"exp": e.now.Load() + 10_000}))
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": gid}))
	if a := e.agents("alice"); len(a) != 1 {
		t.Fatalf("live binding missing: %v", a)
	}
	e.advance(11 * time.Second)
	if a := e.agents("alice"); len(a) != 0 {
		t.Fatalf("expired binding still listed: %v", a)
	}
}

// ---- 2. direct delivery queues ----

func TestDirectQueuePlacement(t *testing.T) {
	e := newEnv(t)

	// A stranger lands in requests.
	m1 := e.dm(scout, "hi bob, it's scout", bob)
	e.mustSubmit(m1)
	if q := e.queue(bob, "requests"); len(q) != 1 || q[0] != m1 {
		t.Fatalf("bob requests: %v", q)
	}
	if q := e.queue(bob, "inbox"); len(q) != 0 {
		t.Fatalf("stranger reached bob's inbox: %v", q)
	}

	// After bob allows scout, scout lands in inbox.
	wantOK(t, e.as(bob, "POST", "/v1/allow", []byte(`{"key":"`+kid(scout)+`"}`)))
	m2 := e.dm(scout, "second message", bob)
	m2id := e.mustSubmit(m2)
	if q := e.queue(bob, "inbox"); len(q) != 1 || q[0] != m2 {
		t.Fatalf("allowed sender not in inbox: %v", q)
	}

	// bob's reply to scout's message reaches scout's inbox with no allow (the re rule).
	reply := e.tok(bob, "msg", map[string]any{"to": []any{kid(scout)}, "body": "hello scout", "re": m2id})
	e.mustSubmit(reply)
	if q := e.queue(scout, "inbox"); len(q) != 1 || q[0] != reply {
		t.Fatalf("reply not in scout inbox: %v", q)
	}

	// Control for the re rule: carol cites m2, which scout sent to bob, not to
	// her. Its from IS the recipient, so only the to-contains-sender condition
	// keeps her out of scout's inbox.
	sneaky := e.tok(carol, "msg", map[string]any{"to": []any{kid(scout)}, "body": "re-cite", "re": m2id})
	e.mustSubmit(sneaky)
	if q := e.queue(scout, "inbox"); has(q, sneaky) {
		t.Fatalf("re to a message not addressed to the sender bypassed requests")
	}
	if q := e.queue(scout, "requests"); !has(q, sneaky) {
		t.Fatalf("sneaky reply not in requests: %v", q)
	}

	// Removing scout from the allow list sends new messages back to requests.
	wantOK(t, e.as(bob, "DELETE", "/v1/allow/"+kid(scout), nil))
	m3 := e.dm(scout, "third", bob)
	e.mustSubmit(m3)
	if !has(e.queue(bob, "requests"), m3) || has(e.queue(bob, "inbox"), m3) {
		t.Fatal("disallowed sender not back in requests")
	}
}

func TestReplyToChannelPostDoesNotOpenInbox(t *testing.T) {
	e := newEnv(t)
	cid := e.createChannel(bob, "lobby", "public", "anyone", "open", nil)
	post := e.mustSubmit(e.tok(bob, "msg", map[string]any{"to": []any{cid}, "body": "public post"}))
	// carol "replies" to bob's public post in a DM; that is not a reply to a
	// message bob sent to carol, so it is a request.
	m := e.tok(carol, "msg", map[string]any{"to": []any{kid(bob)}, "body": "dm", "re": post})
	e.mustSubmit(m)
	if has(e.queue(bob, "inbox"), m) || !has(e.queue(bob, "requests"), m) {
		t.Fatal("reply to a channel post bypassed requests")
	}
}

// threads maps token -> derived thread field for one inbox queue.
func (e *env) threads(priv ed25519.PrivateKey, q string) map[string]any {
	e.t.Helper()
	r := e.as(priv, "GET", "/v1/inbox?queue="+q, nil)
	wantOK(e.t, r)
	out := map[string]any{}
	for _, it := range r.body["items"].([]any) {
		m := it.(map[string]any)
		out[m["token"].(string)] = m["thread"]
	}
	return out
}

func TestInboxThreadRoot(t *testing.T) {
	e := newEnv(t)
	root := e.dm(scout, "root", bob)
	rootID := e.mustSubmit(root)
	r1 := e.tok(bob, "msg", map[string]any{"to": []any{kid(scout)}, "body": "reply 1", "re": rootID})
	r1ID := e.mustSubmit(r1)
	r2 := e.tok(scout, "msg", map[string]any{"to": []any{kid(bob)}, "body": "reply 2", "re": r1ID})
	e.mustSubmit(r2)
	if got := e.threads(bob, "requests")[root]; got != rootID {
		t.Fatalf("root's thread = %v, want itself", got)
	}
	if got := e.threads(scout, "inbox")[r1]; got != rootID {
		t.Fatalf("depth-1 thread = %v", got)
	}
	// Depth 2 tells "the root" apart from "the parent".
	if got := e.threads(bob, "inbox")[r2]; got != rootID {
		t.Fatalf("depth-2 thread = %v, want root %s (parent is %s)", got, rootID, r1ID)
	}
	// A chain that leaves the store yields no thread rather than a guess.
	orphan := e.tok(carol, "msg", map[string]any{"to": []any{kid(bob)}, "body": "orphan",
		"re": "m_" + strings.Repeat("a", 52)})
	e.mustSubmit(orphan)
	if got, ok := e.threads(bob, "requests")[orphan]; !ok || got != nil {
		t.Fatalf("orphan thread = %v (present %v), want omitted", got, ok)
	}
}

// The re rule needs the cited message to be FROM the recipient: citing a DM
// someone else sent you does not open a third party's inbox.
func TestReplyCitingThirdPartyMessage(t *testing.T) {
	e := newEnv(t)
	m := e.mustSubmit(e.dm(carol, "carol to dave", dave))
	r := e.tok(dave, "msg", map[string]any{"to": []any{kid(bob)}, "body": "cites carol's DM", "re": m})
	e.mustSubmit(r)
	if has(e.queue(bob, "inbox"), r) || !has(e.queue(bob, "requests"), r) {
		t.Fatal("re to a DM the recipient did not send bypassed requests")
	}
}

func TestInboxCursorPaging(t *testing.T) {
	e := newEnv(t)
	var sent []string
	for i := 0; i < 5; i++ {
		m := e.dm(scout, fmt.Sprintf("msg %d", i), bob)
		e.mustSubmit(m)
		sent = append(sent, m)
	}
	var got []string
	after := ""
	var last int64 = -1
	for {
		r := e.as(bob, "GET", "/v1/inbox?queue=requests&limit=2&after="+after, nil)
		wantOK(t, r)
		toks := tokens(r)
		for _, it := range r.body["items"].([]any) {
			var c int64
			fmt.Sscan(it.(map[string]any)["cursor"].(string), &c)
			if c <= last {
				t.Fatalf("cursor not strictly increasing: %d after %d", c, last)
			}
			last = c
		}
		if len(toks) == 0 {
			break
		}
		got = append(got, toks...)
		after = r.str("next")
	}
	if strings.Join(got, ",") != strings.Join(sent, ",") {
		t.Fatalf("paged %d items, want %d in order", len(got), len(sent))
	}
	// Bad query parameters and cursors are E_QUERY (§8).
	for _, q := range []string{"queue=spam", "queue=inbox&limit=500", "queue=inbox&limit=0", "queue=inbox&after=abc", "queue=inbox&after=-1"} {
		wantErr(t, e.as(bob, "GET", "/v1/inbox?"+q, nil), 400, EQuery)
	}
	wantErr(t, e.do("GET", "/v1/channels?sort=bogus", nil, ""), 400, EQuery)
	wantErr(t, e.as(bob, "DELETE", "/v1/allow/k_nope", nil), 400, EQuery)
	// A malformed request body is E_QUERY too (§8 error table).
	for _, body := range []string{`not json`, `{"key":"k_nope"}`, `{}`} {
		r := e.as(bob, "POST", "/v1/allow", []byte(body))
		wantErr(t, r, 400, EQuery)
		if !strings.Contains(r.str("detail"), "body must be") {
			t.Fatalf("%s: wrong reason: %v", body, r.body)
		}
	}
	// Inbox requires auth: no header is 401 E_AUTH.
	wantErr(t, e.do("GET", "/v1/inbox?queue=inbox", nil, ""), 401, EAuth)
}

// ---- 3. idempotent submit ----

func TestDuplicateSubmitIsIdempotent(t *testing.T) {
	e := newEnv(t)
	m := e.dm(scout, "once", bob)
	r1, r2 := e.submit(m), e.submit(m)
	wantOK(t, r1)
	wantOK(t, r2)
	if r1.str("id") != r2.str("id") || r1.str("id") != idOf(t, m) {
		t.Fatalf("ids differ: %v %v", r1.body, r2.body)
	}
	if q := e.queue(bob, "requests"); len(q) != 1 {
		t.Fatalf("duplicate stored twice: %d entries", len(q))
	}
}

func TestLateRetryIsIdempotent(t *testing.T) {
	e := newEnv(t)
	m := e.dm(scout, "accepted then retried late", bob)
	id := e.mustSubmit(m)
	e.advance(10 * time.Minute)
	r := e.submit(m)
	wantOK(t, r)
	if r.str("id") != id {
		t.Fatalf("late retry id: %v", r.body)
	}
	// Control: a NEW object with the same old ts is stale.
	wantErr(t, e.submit(e.tokAt(scout, -10*time.Minute, "msg", map[string]any{"to": []any{kid(bob)}, "body": "new but old"})), 400, EStale)
}

// ---- 4. freshness and request auth ----

func TestSubmitFreshness(t *testing.T) {
	e := newEnv(t)
	for _, off := range []time.Duration{-301 * time.Second, 301 * time.Second, -20 * time.Minute} {
		wantErr(t, e.submit(e.tokAt(scout, off, "msg", map[string]any{"to": []any{kid(bob)}, "body": off.String()})), 400, EStale)
	}
	for _, off := range []time.Duration{-299 * time.Second, 299 * time.Second} {
		e.mustSubmit(e.tokAt(scout, off, "msg", map[string]any{"to": []any{kid(bob)}, "body": off.String()}))
	}
}

func TestAuthReplayRejected(t *testing.T) {
	e := newEnv(t)
	hdr := e.authFor(bob, 0, "GET", "/v1/inbox?queue=inbox", nil, nil)
	wantOK(t, e.do("GET", "/v1/inbox?queue=inbox", nil, hdr))
	r := e.do("GET", "/v1/inbox?queue=inbox", nil, hdr)
	wantErr(t, r, 401, EAuth)
	if !strings.Contains(r.str("detail"), "already used") {
		t.Fatalf("rejected for the wrong reason: %v", r.body)
	}
}

func TestAuthFreshness(t *testing.T) {
	e := newEnv(t)
	p := "/v1/inbox?queue=inbox"
	for _, off := range []time.Duration{-61 * time.Second, 61 * time.Second} {
		r := e.do("GET", p, nil, e.authFor(bob, off, "GET", p, nil, nil))
		wantErr(t, r, 401, EAuth)
		if !strings.Contains(r.str("detail"), "±60 s") {
			t.Fatalf("rejected for the wrong reason: %v", r.body)
		}
	}
	for _, off := range []time.Duration{-59 * time.Second, 59 * time.Second} {
		wantOK(t, e.do("GET", p, nil, e.authFor(bob, off, "GET", p, nil, nil)))
	}
}

func TestAuthBinding(t *testing.T) {
	e := newEnv(t)
	p := "/v1/inbox?queue=inbox"
	cases := map[string]string{
		"path":   e.authFor(bob, 0, "GET", "/v1/inbox?queue=requests", nil, nil),
		"method": e.authFor(bob, 0, "POST", p, nil, nil),
		"hub":    e.authFor(bob, 0, "GET", p, nil, map[string]any{"hub": "evil.example"}),
		"body":   e.authFor(bob, 0, "GET", p, []byte("x"), nil),
	}
	for what, hdr := range cases {
		r := e.do("GET", p, nil, hdr)
		wantErr(t, r, 401, EAuth)
		if !strings.Contains(r.str("detail"), what) {
			t.Errorf("%s: rejected for the wrong reason: %v", what, r.body)
		}
	}
	// A non-auth token in the header is not an auth token, even one carrying
	// hub/method/path/body as unknown (signed, ignored) fields that would
	// otherwise satisfy every binding check.
	sum := sha256.Sum256(nil)
	disguised := e.tok(bob, "handle", map[string]any{"name": "bob", "hub": hubName,
		"method": "GET", "path": p, "body": hex.EncodeToString(sum[:])})
	r := e.do("GET", p, nil, "ClankMail "+disguised)
	wantErr(t, r, 401, EAuth)
	if !strings.Contains(r.str("detail"), "t=auth") {
		t.Fatalf("disguised token rejected for the wrong reason: %v", r.body)
	}
	// A body hash binds the body: allow with a tampered body fails.
	good := []byte(`{"key":"` + kid(scout) + `"}`)
	hdr := e.authFor(bob, 0, "POST", "/v1/allow", good, nil)
	wantErr(t, e.do("POST", "/v1/allow", []byte(`{"key":"`+kid(carol)+`"}`), hdr), 401, EAuth)
	// Missing, malformed and §4-invalid auth on a required-auth endpoint are 401 too.
	for _, h := range []string{"", "Bearer x", "ClankMail v1.not.a.token"} {
		wantErr(t, e.do("GET", p, nil, h), 401, EAuth)
	}
}

func TestSubmitRejectsAuth(t *testing.T) {
	e := newEnv(t)
	tok := strings.TrimPrefix(e.authFor(bob, 0, "GET", "/v1/inbox?queue=inbox", nil, nil), "ClankMail ")
	r := e.submit(tok)
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "never submitted") {
		t.Fatalf("wrong reason: %v", r.body)
	}
}

func TestSubmitPipelineErrors(t *testing.T) {
	e := newEnv(t)
	good := e.dm(scout, "x", bob)
	parts := strings.Split(good, ".")
	wantErr(t, e.submit("v2."+strings.Join(parts[1:], ".")), 400, clankmail.EFormat)
	bad := parts[0] + "." + parts[1] + "." + parts[2] + "." + flipB64(parts[3])
	wantErr(t, e.submit(bad), 400, clankmail.ESignature)
}

// flipB64 changes one character of a base64url string to another valid one.
func flipB64(s string) string {
	c := byte('A')
	if s[0] == 'A' {
		c = 'B'
	}
	return string(c) + s[1:]
}

// ---- 5. channels ----

func (e *env) createChannel(owner ed25519.PrivateKey, slug, read, post, join string, extra map[string]any) string {
	e.t.Helper()
	f := map[string]any{"slug": slug, "title": strings.ToUpper(slug), "read": read, "post": post, "join": join}
	for k, v := range extra {
		f[k] = v
	}
	tok := e.tok(owner, "channel", f)
	id := e.mustSubmit(tok)
	return "c_" + id[2:]
}

func (e *env) discover(query string) map[string]map[string]any {
	e.t.Helper()
	r := e.do("GET", "/v1/channels?"+query, nil, "")
	wantOK(e.t, r)
	out := map[string]map[string]any{}
	for _, it := range r.body["items"].([]any) {
		m := it.(map[string]any)
		out[m["channel"].(string)] = m
	}
	return out
}

func TestChannelLifecycle(t *testing.T) {
	e := newEnv(t)
	cid := e.createChannel(alice, "go-news", "public", "members", "open", map[string]any{
		"about": "Release notes and gossip", "tags": []any{"golang", "news"}, "mods": []any{kid(carol)}})
	other := e.createChannel(dave, "rust-chat", "public", "anyone", "open", map[string]any{"tags": []any{"rust"}})

	// Discovery by tag and by q, with negative controls.
	if d := e.discover("tag=golang"); d[cid] == nil || d[other] != nil {
		t.Fatalf("tag=golang: %v", d)
	}
	if d := e.discover("q=gossip"); d[cid] == nil || d[other] != nil {
		t.Fatalf("q=gossip: %v", d)
	}
	if d := e.discover("q=nothing-matches-this"); len(d) != 0 {
		t.Fatalf("q miss returned %v", d)
	}
	if d := e.discover(""); d[cid] == nil || d[other] == nil {
		t.Fatalf("unfiltered discovery: %v", d)
	}

	// Lookup by id and by #slug.
	for _, ref := range []string{cid, url.PathEscape("#go-news")} {
		r := e.do("GET", "/v1/channels/"+ref, nil, "")
		wantOK(t, r)
		if r.str("channel") != cid || r.str("genesis") == "" || r.str("manifest") != r.str("genesis") {
			t.Fatalf("lookup %s: %v", ref, r.body)
		}
	}

	post := func(from ed25519.PrivateKey, body string) string {
		return e.tok(from, "msg", map[string]any{"to": []any{cid}, "body": body})
	}

	// bob is not a member: post=members refuses him.
	wantErr(t, e.submit(post(bob, "first!")), 403, EForbidden)
	joinID := e.mustSubmit(e.tok(bob, "join", map[string]any{"channel": cid}))
	bp := post(bob, "first, properly")
	bpID := e.mustSubmit(bp)

	logToks := func() []string {
		r := e.do("GET", "/v1/channels/"+cid+"/log", nil, "")
		wantOK(t, r)
		return tokens(r)
	}
	if l := logToks(); len(l) != 1 || l[0] != bp {
		t.Fatalf("log: %v", l)
	}
	d := e.discover("tag=golang")[cid]
	if d["members"].(float64) != 2 || d["posts_7d"].(float64) != 1 {
		t.Fatalf("counts: %v", d)
	}

	// dave is neither mod nor author: cannot remove. carol (mod) can.
	wantErr(t, e.submit(e.tok(dave, "remove", map[string]any{"channel": cid, "target": bpID})), 403, EForbidden)
	rmID := e.mustSubmit(e.tok(carol, "remove", map[string]any{"channel": cid, "target": bpID}))
	if l := logToks(); len(l) != 0 {
		t.Fatalf("removed post still in log: %v", l)
	}
	// The original token is kept for audit, visible only to the owner, mods
	// and the author; everyone else (members included) gets 404.
	wantErr(t, e.do("GET", "/v1/objects/"+bpID, nil, ""), 404, ENotFound)
	wantErr(t, e.as(dave, "GET", "/v1/objects/"+bpID, nil), 404, ENotFound)
	for _, k := range []ed25519.PrivateKey{alice, carol, bob} {
		if r := e.as(k, "GET", "/v1/objects/"+bpID, nil); r.status != 200 || r.str("token") != bp {
			t.Fatalf("owner/mod/author audit read: %d %v", r.status, r.body)
		}
	}
	// A visible post in a public channel needs no auth, nor do its
	// membership and moderation objects.
	vis := e.mustSubmit(post(bob, "still here"))
	for _, id := range []string{vis, rmID, joinID} {
		wantOK(t, e.do("GET", "/v1/objects/"+id, nil, ""))
	}

	// Owner update: newer ts wins; non-owner and stale updates refused.
	e.advance(time.Second)
	upd := e.tok(alice, "channel", map[string]any{"channel": cid, "slug": "go-news", "title": "Go News v2",
		"read": "public", "post": "members", "join": "open", "mods": []any{kid(carol)}})
	e.mustSubmit(upd)
	if r := e.do("GET", "/v1/channels/"+cid, nil, ""); r.str("manifest") != upd {
		t.Fatalf("manifest not updated: %v", r.body)
	}
	// dave's update is NEWER than the stored manifest, so only the owner check can refuse it.
	wantErr(t, e.submit(e.tokAt(dave, time.Second, "channel", map[string]any{"channel": cid, "slug": "go-news", "title": "pwned",
		"read": "public", "post": "anyone", "join": "open"})), 403, EForbidden)
	wantErr(t, e.submit(e.tokAt(alice, -time.Second, "channel", map[string]any{"channel": cid, "slug": "go-news",
		"title": "older", "read": "public", "post": "members", "join": "open"})), 403, EForbidden)
}

// §7.1: slugs are unique per hub; a changed slug releases the old one.
func TestSlugUniqueness(t *testing.T) {
	e := newEnv(t)
	c1 := e.createChannel(alice, "go", "public", "members", "open", nil)
	r := e.submit(e.tok(dave, "channel", map[string]any{"slug": "go", "title": "lookalike", "read": "public", "post": "anyone", "join": "open"}))
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "bound to another channel") {
		t.Fatalf("wrong reason: %v", r.body)
	}
	c2 := e.createChannel(dave, "rust", "public", "anyone", "open", nil)
	// An update may not take a slug bound to another channel.
	wantErr(t, e.submit(e.tokAt(dave, time.Second, "channel", map[string]any{"channel": c2, "slug": "go", "title": "x",
		"read": "public", "post": "anyone", "join": "open"})), 403, EForbidden)
	// alice renames #go to #golang: #go is released and #golang resolves to c1.
	e.mustSubmit(e.tokAt(alice, time.Second, "channel", map[string]any{"channel": c1, "slug": "golang", "title": "Go",
		"read": "public", "post": "members", "join": "open"}))
	if r := e.do("GET", "/v1/channels/"+url.PathEscape("#golang"), nil, ""); r.str("channel") != c1 {
		t.Fatalf("#golang: %v", r.body)
	}
	wantErr(t, e.do("GET", "/v1/channels/"+url.PathEscape("#go"), nil, ""), 404, ENotFound)
	c3 := e.createChannel(dave, "go", "public", "anyone", "open", nil)
	if r := e.do("GET", "/v1/channels/"+url.PathEscape("#go"), nil, ""); r.str("channel") != c3 {
		t.Fatalf("released #go: %v", r.body)
	}
	// Keeping one's own slug on an update is fine.
	e.mustSubmit(e.tokAt(alice, 2*time.Second, "channel", map[string]any{"channel": c1, "slug": "golang", "title": "Go 2",
		"read": "public", "post": "members", "join": "open"}))
}

// §7.3 bans: replacing a live ban needs a signer ranked at least as high as
// its signer (owner > mods); a passed until on a replacing ban lifts it; a
// passed until on a key that is not banned is refused and removes no one.
func TestBanRanksAndUnban(t *testing.T) {
	e := newEnv(t)
	cid := e.createChannel(alice, "club", "public", "members", "open", map[string]any{"mods": []any{kid(carol)}})
	n := 0
	ban := func(by, who ed25519.PrivateKey, until *int64) resp {
		n++
		f := map[string]any{"channel": cid, "member": kid(who)}
		if until != nil {
			f["until"] = *until
		}
		return e.submit(e.tokAt(by, time.Duration(n)*time.Millisecond, "ban", f))
	}
	join := func(who ed25519.PrivateKey) resp {
		n++
		return e.submit(e.tokAt(who, time.Duration(n)*time.Millisecond, "join", map[string]any{"channel": cid}))
	}
	past, future := e.now.Load()-1, e.now.Load()+60_000

	// Owner's ban: a mod can neither lift nor shorten it; the owner can lift it.
	wantOK(t, ban(alice, bob, nil))
	wantErr(t, join(bob), 403, EForbidden)
	wantErr(t, ban(dave, bob, &past), 403, EForbidden) // not a mod at all
	// A non-mod cannot ban a key that has no ban (no rank check to hide behind).
	r0 := ban(dave, eve, nil)
	wantErr(t, r0, 403, EForbidden)
	if !strings.Contains(r0.str("detail"), "owner or a mod") {
		t.Fatalf("wrong reason: %v", r0.body)
	}
	r := ban(carol, bob, &past)
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "owner's ban") {
		t.Fatalf("wrong reason: %v", r.body)
	}
	wantErr(t, ban(carol, bob, &future), 403, EForbidden)
	wantErr(t, join(bob), 403, EForbidden)
	wantOK(t, ban(alice, bob, &past))
	wantOK(t, join(bob))

	// A mod's ban: another ban by a mod or by the owner may replace it.
	wantOK(t, join(dave))
	wantOK(t, ban(carol, dave, nil))
	wantOK(t, ban(carol, dave, &past)) // same rank lifts
	wantOK(t, join(dave))
	wantOK(t, ban(carol, dave, nil))
	wantOK(t, ban(alice, dave, &past)) // higher rank lifts
	wantOK(t, join(dave))

	// A passed until on a key that is not banned is refused and removes no one.
	r = ban(alice, dave, &past)
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "not banned") {
		t.Fatalf("wrong reason: %v", r.body)
	}
	e.mustSubmit(e.tok(dave, "msg", map[string]any{"to": []any{cid}, "body": "still a member"}))
	// Control: a future until is a real ban.
	wantOK(t, ban(alice, dave, &future))
	wantErr(t, join(dave), 403, EForbidden)
}

func TestMembersOnlyChannelLog(t *testing.T) {
	e := newEnv(t)
	cid := e.createChannel(alice, "inner", "members", "members", "approval", nil)
	path := "/v1/channels/" + cid + "/log"
	e.mustSubmit(e.tok(alice, "msg", map[string]any{"to": []any{cid}, "body": "secret"}))

	// §6.4: this log REQUIRES auth (the channel's existence is public):
	// missing or failed auth is 401 E_AUTH; a non-member is 403.
	wantErr(t, e.do("GET", path, nil, ""), 401, EAuth)
	wantErr(t, e.do("GET", path, nil, e.authFor(alice, -2*time.Minute, "GET", path, nil, nil)), 401, EAuth)
	wantErr(t, e.as(bob, "GET", path, nil), 403, EForbidden)
	if r := e.as(alice, "GET", path, nil); r.status != 200 || len(tokens(r)) != 1 {
		t.Fatalf("owner read: %d %v", r.status, r.body)
	}

	// Approval join: pending until admitted; pending cannot read or post.
	e.mustSubmit(e.tok(bob, "join", map[string]any{"channel": cid}))
	wantErr(t, e.as(bob, "GET", path, nil), 403, EForbidden)
	wantErr(t, e.submit(e.tok(bob, "msg", map[string]any{"to": []any{cid}, "body": "let me in"})), 403, EForbidden)
	wantErr(t, e.submit(e.tok(dave, "admit", map[string]any{"channel": cid, "member": kid(bob)})), 403, EForbidden)
	e.mustSubmit(e.tok(alice, "admit", map[string]any{"channel": cid, "member": kid(bob)}))
	if r := e.as(bob, "GET", path, nil); r.status != 200 || len(tokens(r)) != 1 {
		t.Fatalf("admitted member read: %d %v", r.status, r.body)
	}

	// A members-only post is not served by id to outsiders.
	sec := e.tok(alice, "msg", map[string]any{"to": []any{cid}, "body": "secret 2"})
	sid := e.mustSubmit(sec)
	wantErr(t, e.as(dave, "GET", "/v1/objects/"+sid, nil), 404, ENotFound)
	if r := e.as(bob, "GET", "/v1/objects/"+sid, nil); r.status != 200 || r.str("token") != sec {
		t.Fatalf("member object read: %v", r.body)
	}

	// Ban removes and blocks rejoin.
	e.mustSubmit(e.tok(alice, "ban", map[string]any{"channel": cid, "member": kid(bob)}))
	wantErr(t, e.as(bob, "GET", path, nil), 403, EForbidden)
	wantErr(t, e.submit(e.tokAt(bob, time.Millisecond, "join", map[string]any{"channel": cid})), 403, EForbidden)
}

func TestDirectObjectVisibility(t *testing.T) {
	e := newEnv(t)
	m := e.dm(scout, "private", bob)
	id := e.mustSubmit(m)
	// Unauthenticated, a stranger, and a never-stored id all look the same.
	wantErr(t, e.do("GET", "/v1/objects/"+id, nil, ""), 404, ENotFound)
	wantErr(t, e.as(carol, "GET", "/v1/objects/"+id, nil), 404, ENotFound)
	wantErr(t, e.do("GET", "/v1/objects/m_"+strings.Repeat("a", 52), nil, ""), 404, ENotFound)
	// A party whose auth fails (stale) is anonymous: 404, never E_AUTH.
	op := "/v1/objects/" + id
	wantErr(t, e.do("GET", op, nil, e.authFor(bob, -2*time.Minute, "GET", op, nil, nil)), 404, ENotFound)
	for _, k := range []ed25519.PrivateKey{bob, scout} {
		if r := e.as(k, "GET", "/v1/objects/"+id, nil); r.status != 200 || r.str("token") != m {
			t.Fatalf("party read: %v", r.body)
		}
	}
}

// ---- 6. revoke ----

func TestRevokedAgentRejected(t *testing.T) {
	e := newEnv(t)
	e.mustSubmit(e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName}))
	gid := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": gid}))
	e.mustSubmit(e.dm(scout, "before revoke", bob))

	// Only the grant's signer may revoke it.
	wantErr(t, e.submit(e.tok(bob, "revoke", map[string]any{"target": gid})), 403, EForbidden)
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": gid}))

	wantErr(t, e.submit(e.dm(scout, "after revoke", bob)), 403, ERevoked)
	wantErr(t, e.as(scout, "GET", "/v1/inbox?queue=inbox", nil), 403, ERevoked)
	if a := e.agents("alice"); len(a) != 0 {
		t.Fatalf("revoked binding still listed: %v", a)
	}
	// Control: an unrevoked key still submits.
	e.mustSubmit(e.dm(carol, "still fine", bob))
}

// Naming a key in a grant gives no power over it: revoking a grant that the
// key never enrolled on must not silence the key.
func TestRevokeCannotSilenceUnenrolledKey(t *testing.T) {
	e := newEnv(t)
	gid := e.mustSubmit(grantTok(e, dave, carol, "victim", nil))
	e.mustSubmit(e.tok(dave, "revoke", map[string]any{"target": gid}))
	e.mustSubmit(e.dm(carol, "I was never dave's agent", bob))
	wantOK(t, e.as(carol, "GET", "/v1/inbox?queue=inbox", nil))
}

// An agent withdrawing its own enroll ends the binding without revoking its key.
func TestRevokeOwnEnroll(t *testing.T) {
	e := newEnv(t)
	e.mustSubmit(e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName}))
	gid := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	eid := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": gid}))
	wantErr(t, e.submit(e.tok(alice, "revoke", map[string]any{"target": eid})), 403, EForbidden)
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": eid}))
	if a := e.agents("alice"); len(a) != 0 {
		t.Fatalf("withdrawn binding still listed: %v", a)
	}
	e.mustSubmit(e.dm(scout, "still me", bob))
}

func TestRevokeTargetType(t *testing.T) {
	e := newEnv(t)
	m := e.mustSubmit(e.dm(alice, "a message, not a grant", bob))
	cid := e.createChannel(alice, "mine", "public", "members", "open", nil)
	for _, target := range []string{m, "m_" + cid[2:]} {
		r := e.submit(e.tok(alice, "revoke", map[string]any{"target": target}))
		wantErr(t, r, 403, EForbidden)
	}
}

// §6.3 rule 1: a stolen key cannot dodge its owner's revoke by withdrawing
// its own enroll first.
func TestKillSwitchSurvivesSelfWithdrawal(t *testing.T) {
	e := newEnv(t)
	gid := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	eid := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": gid}))
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": eid}))
	e.mustSubmit(e.dm(scout, "withdrew, still sending", bob))
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": gid}))
	wantErr(t, e.submit(e.dm(scout, "after the kill switch", bob)), 403, ERevoked)
}

// §6.3 rule 2: a key that enrolled under a newer grant before the revoke
// has moved on; its former principal cannot disable it.
func TestKillSwitchSparesKeyThatMovedOn(t *testing.T) {
	e := newEnv(t)
	g1 := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e1 := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g1}))
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": e1}))
	e.advance(24*time.Hour + time.Second) // past the §6.3 rule 2 cooldown
	g2 := e.mustSubmit(grantTok(e, carol, scout, "helper", nil))
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g2}))
	// bob trusts scout in its new role; alice's revoke of the old grant ends
	// nothing live, so it must not touch that trust either.
	wantOK(t, e.as(bob, "POST", "/v1/allow", []byte(`{"key":"`+kid(scout)+`"}`)))
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": g1}))
	m := e.dm(scout, "I work for carol now", bob)
	e.mustSubmit(m)
	if !has(e.queue(bob, "inbox"), m) {
		t.Fatal("revoking a grant the key had left cleared trust given to its new binding")
	}
	// Control: carol's revoke of the CURRENT grant does switch it off.
	e.mustSubmit(e.tok(carol, "revoke", map[string]any{"target": g2}))
	wantErr(t, e.submit(e.dm(scout, "and now I'm off", bob)), 403, ERevoked)
}

// §6.3 rule 2 cooldown: after withdrawing itself a key cannot re-enroll for
// 24 h of hub time, and the owner's revoke still reaches it in that window.
// Measured at +1 ms, +24h-1s (refused) and +24h+1s (accepted).
func TestEnrollCooldownAfterWithdrawal(t *testing.T) {
	e := newEnv(t)
	g1 := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e1 := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g1}))
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": e1}))
	g2 := e.mustSubmit(grantTok(e, carol, scout, "helper", nil))
	for i, d := range []time.Duration{time.Millisecond, 24*time.Hour - time.Second - time.Millisecond} {
		e.advance(d)
		r := e.submit(e.tokAt(scout, time.Duration(i)*time.Millisecond, "enroll", map[string]any{"grant": g2}))
		wantErr(t, r, 403, EForbidden)
		if !strings.Contains(r.str("detail"), "24 h") {
			t.Fatalf("refused for the wrong reason: %v", r.body)
		}
	}
	e.advance(2 * time.Second) // now withdrawal + 24h + 1s
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g2}))
	// Having moved on after the cooldown, alice's revoke spares it.
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": g1}))
	e.mustSubmit(e.dm(scout, "moved on", bob))
}

func TestOwnerRevokeInsideCooldownKills(t *testing.T) {
	e := newEnv(t)
	g1 := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e1 := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g1}))
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": e1}))
	e.advance(23 * time.Hour)
	g2 := e.mustSubmit(grantTok(e, carol, scout, "helper", nil))
	wantErr(t, e.submit(e.tok(scout, "enroll", map[string]any{"grant": g2})), 403, EForbidden)
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": g1}))
	wantErr(t, e.submit(e.dm(scout, "thief", bob)), 403, ERevoked)
	// Permanent: even after the cooldown, it cannot come back.
	e.advance(2 * time.Hour)
	wantErr(t, e.submit(e.tok(scout, "enroll", map[string]any{"grant": g2})), 403, ERevoked)
}

// §6.3 rule 2: an expiry starts the cooldown too, measured from the grant's
// exp instant (checked at exp+24h-1s refused, exp+24h+1s accepted); a renewal
// under the SAME principal is immediate.
func TestCooldownAfterExpiryAndRenewal(t *testing.T) {
	e := newEnv(t)
	exp := e.now.Load() + 10_000
	g1 := e.mustSubmit(grantTok(e, alice, scout, "scout", map[string]any{"exp": exp}))
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g1}))
	e.advance(11 * time.Second)
	gc := e.mustSubmit(grantTok(e, carol, scout, "helper", nil))
	r := e.submit(e.tok(scout, "enroll", map[string]any{"grant": gc}))
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "24 h") {
		t.Fatalf("wrong reason: %v", r.body)
	}
	// Renewal by the same principal: the expired name is free again.
	g3 := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g3}))

	// The window is measured from exp, not from when the hub noticed.
	exp2 := e.now.Load() + 10_000
	gd := e.mustSubmit(grantTok(e, alice, dave, "dave", map[string]any{"exp": exp2}))
	e.mustSubmit(e.tok(dave, "enroll", map[string]any{"grant": gd}))
	gcd := e.mustSubmit(grantTok(e, carol, dave, "d2", nil))
	e.advance(time.Duration(exp2-e.now.Load())*time.Millisecond + 24*time.Hour - time.Second)
	wantErr(t, e.submit(e.tok(dave, "enroll", map[string]any{"grant": gcd})), 403, EForbidden)
	e.advance(2 * time.Second)
	e.mustSubmit(e.tokAt(dave, time.Millisecond, "enroll", map[string]any{"grant": gcd}))
}

// After a self-withdrawal, re-enrolling under the same principal is immediate.
func TestSamePrincipalReenrollAfterWithdrawal(t *testing.T) {
	e := newEnv(t)
	g1 := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e1 := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g1}))
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": e1}))
	g2 := e.mustSubmit(grantTok(e, alice, scout, "scout-v2", nil))
	e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g2}))
}

// §6.3 rule 3 / §7.2: when a binding ends, the key loses the reply route for
// every message that arrived before that moment.
func TestReplyRouteLostWhenBindingEnds(t *testing.T) {
	e := newEnv(t)
	queueOf := func(owner ed25519.PrivateKey, tok string) string {
		switch {
		case has(e.queue(owner, "inbox"), tok):
			return "inbox"
		case has(e.queue(owner, "requests"), tok):
			return "requests"
		}
		return "nowhere"
	}
	reply := func(from ed25519.PrivateKey, re, body string) string {
		m := e.tok(from, "msg", map[string]any{"to": []any{kid(bob)}, "body": body, "re": re})
		e.mustSubmit(m)
		return queueOf(bob, m)
	}

	// Ended by withdrawal.
	g1 := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e1 := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g1}))
	m1 := e.mustSubmit(e.dm(bob, "to @alice/scout", scout))
	e.advance(time.Second)
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": e1}))
	e.advance(time.Second)
	if q := reply(scout, m1, "reply to a pre-end message"); q != "requests" {
		t.Fatalf("reply to a message from before the binding ended went to %s", q)
	}
	m2 := e.mustSubmit(e.dm(bob, "to the key, after the end", scout))
	e.advance(time.Second)
	if q := reply(scout, m2, "reply to a post-end message"); q != "inbox" {
		t.Fatalf("reply to a post-end message went to %s", q)
	}

	// Ended by expiry, effective at the exp instant: a message that arrives
	// after exp (in the same submit that notices the expiry) keeps the route.
	exp := e.now.Load() + 10_000
	gd := e.mustSubmit(grantTok(e, alice, dave, "dave", map[string]any{"exp": exp}))
	e.mustSubmit(e.tok(dave, "enroll", map[string]any{"grant": gd}))
	m3 := e.mustSubmit(e.dm(bob, "before expiry", dave))
	e.advance(12 * time.Second)
	m4 := e.mustSubmit(e.dm(bob, "after expiry", dave))
	e.advance(time.Second)
	if q := reply(dave, m3, "reply to pre-expiry"); q != "requests" {
		t.Fatalf("reply to a pre-expiry message went to %s", q)
	}
	if q := reply(dave, m4, "reply to post-expiry"); q != "inbox" {
		t.Fatalf("reply to a post-expiry message went to %s (end not dated at exp?)", q)
	}
}

// §5: the per-address limit keys on the client address reported by a
// trusted front proxy, walking X-Forwarded-For right to left, and groups
// IPv6 by /64.
func TestRateLimitClientAddress(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}
		c.IPLimit = Limit{Burst: 2, PerSec: 0.001}
	})
	n := 0
	from := func(xff string) resp {
		n++
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/submit", strings.NewReader(e.dm(scout, fmt.Sprint("m", n), bob)))
		req.Header.Set("X-Forwarded-For", xff)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out := resp{status: res.StatusCode}
		json.NewDecoder(res.Body).Decode(&out.body)
		return out
	}
	wantOK(t, from("203.0.113.5"))
	wantOK(t, from("203.0.113.5, 10.1.2.3")) // a second trusted hop is skipped
	wantErr(t, from("203.0.113.5"), 429, ERate)
	// Entries left of the first untrusted hop are client-supplied: ignored.
	wantErr(t, from("198.51.100.9, 203.0.113.5"), 429, ERate)
	wantOK(t, from("203.0.113.6"))
	// IPv6: one /64 is one client.
	wantOK(t, from("2001:db8::1"))
	wantOK(t, from("2001:db8::2"))
	wantErr(t, from("2001:db8::ffff:1"), 429, ERate)
	wantOK(t, from("2001:db8:0:1::1"))
}

// Without a trusted proxy, X-Forwarded-For is ignored: the TCP peer is the client.
func TestRateLimitIgnoresUntrustedForwardedFor(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.IPLimit = Limit{Burst: 2, PerSec: 0.001} })
	for i, xff := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/submit", strings.NewReader(e.dm(scout, xff, bob)))
		req.Header.Set("X-Forwarded-For", xff)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if want := map[bool]int{true: 200, false: 429}[i < 2]; res.StatusCode != want {
			t.Fatalf("request %d from spoofed %s: %d, want %d", i, xff, res.StatusCode, want)
		}
	}
}

// §6.3 rule 3: when a binding ends the key leaves every allow list, whether
// it ended by the agent's own revoke or by the grant's expiry. Trust given
// after the end stays.
func TestTrustDoesNotTravel(t *testing.T) {
	e := newEnv(t)
	allow := func(owner, k ed25519.PrivateKey) {
		wantOK(t, e.as(owner, "POST", "/v1/allow", []byte(`{"key":"`+kid(k)+`"}`)))
	}
	where := func(tok string) string {
		switch {
		case has(e.queue(bob, "inbox"), tok):
			return "inbox"
		case has(e.queue(bob, "requests"), tok):
			return "requests"
		}
		return "nowhere"
	}
	send := func(from ed25519.PrivateKey, body string) string {
		m := e.dm(from, body, bob)
		e.mustSubmit(m)
		return where(m)
	}

	// Ended by the agent's own revoke.
	g1 := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	e1 := e.mustSubmit(e.tok(scout, "enroll", map[string]any{"grant": g1}))
	allow(bob, scout)
	allow(bob, carol) // control: carol has no binding, nothing ends for her
	if q := send(scout, "bound and allowed"); q != "inbox" {
		t.Fatalf("allowed bound agent in %s", q)
	}
	e.mustSubmit(e.tok(scout, "revoke", map[string]any{"target": e1}))
	if q := send(scout, "binding ended by own revoke"); q != "requests" {
		t.Fatalf("after own revoke, scout in %s: allow survived the binding", q)
	}
	if q := send(carol, "unaffected"); q != "inbox" {
		t.Fatalf("control: carol in %s", q)
	}
	// Trust given after the binding ended belongs to the key and stays,
	// including across a later expiry sweep of a different binding.
	allow(bob, scout)
	if q := send(scout, "re-allowed"); q != "inbox" {
		t.Fatalf("re-allowed scout in %s", q)
	}

	// Ended by the grant's expiry: dave binds under a grant expiring in 10 s.
	g2 := e.mustSubmit(grantTok(e, alice, dave, "dave", map[string]any{"exp": e.now.Load() + 10_000}))
	e.mustSubmit(e.tok(dave, "enroll", map[string]any{"grant": g2}))
	allow(bob, dave)
	if q := send(dave, "bound, before expiry"); q != "inbox" {
		t.Fatalf("dave before expiry in %s", q)
	}
	e.advance(11 * time.Second)
	if q := send(dave, "after expiry"); q != "requests" {
		t.Fatalf("after expiry, dave in %s: allow survived the binding", q)
	}
	if q := send(scout, "still re-allowed"); q != "inbox" {
		t.Fatalf("expiry sweep removed an unrelated allow: scout in %s", q)
	}
	// After the expiry, re-allowing dave sticks.
	allow(bob, dave)
	e.advance(time.Second)
	if q := send(dave, "re-allowed after expiry"); q != "inbox" {
		t.Fatalf("re-allow after expiry did not stick: dave in %s", q)
	}

	// An allow made after an expiry but BEFORE any submit notices it must
	// still stick: the expiry is processed before the allow is written.
	g3 := e.mustSubmit(grantTok(e, alice, eve, "eve", map[string]any{"exp": e.now.Load() + 10_000}))
	e.mustSubmit(e.tok(eve, "enroll", map[string]any{"grant": g3}))
	allow(bob, eve)
	e.advance(11 * time.Second)
	allow(bob, eve)
	if q := send(eve, "allowed after expiry, first submit since"); q != "inbox" {
		t.Fatalf("allow made after expiry was cleared: eve in %s", q)
	}
}

// §6.2: a principal has at most one live grant per name, whatever the agent.
func TestGrantNameUniquePerPrincipal(t *testing.T) {
	e := newEnv(t)
	gid := e.mustSubmit(grantTok(e, alice, scout, "scout", nil))
	wantErr(t, e.submit(grantTok(e, alice, dave, "scout", nil)), 403, EForbidden)
	wantErr(t, e.submit(e.tokAt(alice, time.Millisecond, "grant",
		map[string]any{"agent": kid(scout), "name": "scout", "hub": hubName})), 403, EForbidden)
	// Another principal may use the name; after a revoke alice may reuse it.
	e.mustSubmit(grantTok(e, carol, scout, "scout", nil))
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": gid}))
	e.mustSubmit(grantTok(e, alice, dave, "scout", nil))
}

func TestRevokeHandleReleasesName(t *testing.T) {
	e := newEnv(t)
	hid := e.mustSubmit(e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName}))
	e.mustSubmit(e.tok(alice, "revoke", map[string]any{"target": hid}))
	wantErr(t, e.do("GET", "/v1/handles/alice", nil, ""), 404, ENotFound)
	e.mustSubmit(e.tok(bob, "handle", map[string]any{"name": "alice", "hub": hubName}))
}

// ---- 7. rate limit ----

func TestRateLimitDefaults(t *testing.T) {
	e := newEnv(t)
	n := int(DefaultKeyLimit.Burst)
	for i := 0; i < n; i++ {
		e.mustSubmit(e.dm(scout, fmt.Sprintf("spam %d", i), bob))
	}
	wantErr(t, e.submit(e.dm(scout, "one too many", bob)), 429, ERate)
	// Per key: another key is unaffected.
	e.mustSubmit(e.dm(carol, "not me", bob))
	// Refill at the default rate.
	e.advance(2 * time.Second)
	e.mustSubmit(e.dm(scout, "after refill", bob))
}

// ---- 8. handle uniqueness ----

func TestHandleUniquenessAndHub(t *testing.T) {
	e := newEnv(t)
	e.mustSubmit(e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName}))
	r := e.submit(e.tok(bob, "handle", map[string]any{"name": "alice", "hub": hubName}))
	wantErr(t, r, 403, EForbidden)
	if !strings.Contains(r.str("detail"), "bound to another key") {
		t.Fatalf("wrong reason: %v", r.body)
	}
	wantErr(t, e.submit(e.tok(bob, "handle", map[string]any{"name": "bobby", "hub": "other.example"})), 403, EForbidden)
	wantErr(t, e.do("GET", "/v1/handles/bobby", nil, ""), 404, ENotFound)

	// Rename releases the old name.
	e.advance(time.Millisecond)
	e.mustSubmit(e.tok(alice, "handle", map[string]any{"name": "alice2", "hub": hubName}))
	e.mustSubmit(e.tok(bob, "handle", map[string]any{"name": "alice", "hub": hubName}))
	r = e.do("GET", "/v1/handles/alice", nil, "")
	o, _ := clankmail.Verify(r.str("handle"))
	if o == nil || o.From != kid(bob) {
		t.Fatalf("@alice not rebound to bob: %v", r.body)
	}
	// An older handle from alice cannot roll the rename back.
	wantErr(t, e.submit(e.tokAt(alice, -time.Second, "handle", map[string]any{"name": "alice3", "hub": hubName})), 403, EForbidden)
}
