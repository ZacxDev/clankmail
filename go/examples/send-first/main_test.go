package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// testKey derives a fixed key from a name.
func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("clankmail-send-first-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func kid(priv ed25519.PrivateKey) string { return clankmail.KeyID(priv.Public().(ed25519.PublicKey)) }

// cid builds a well-formed c_ id from a name (format only, §7.2).
func cid(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "c_" + clankmail.B32(sum[:])
}

var (
	sender = testKey("sender")
	peer   = testKey("peer")
	other  = testKey("other")
)

// ts is 2027-01-15T08:00:00.123Z: not a round number, so a mutant that
// hardcodes or truncates the clock is visible.
const ts = int64(1_800_000_000_123)

func writeKey(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "chief.key")
	line := base64.RawURLEncoding.EncodeToString(priv.Seed()) + "\n"
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildMsgFieldsAndSignature(t *testing.T) {
	to := []string{kid(peer), kid(other)}
	payload, err := BuildMsg(sender, to, "hello <&>", "First message.\nline two é", ts, MaxBody)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"v":       float64(1),
		"t":       "msg",
		"from":    kid(sender),
		"ts":      float64(ts),
		"to":      []any{kid(peer), kid(other)},
		"subject": "hello <&>",
		"body":    "First message.\nline two é",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("payload fields\n got %v\nwant %v", got, want)
	}
	tok := clankmail.Sign(sender, payload)
	obj, err := clankmail.Verify(tok)
	if err != nil {
		t.Fatalf("signed msg does not verify: %v", err)
	}
	if obj.Type != "msg" || obj.From != kid(sender) || obj.ID != clankmail.ObjectID(payload) {
		t.Fatalf("verified object: %+v", obj)
	}
	if _, ok := obj.Fields["re"]; ok {
		t.Fatal("a first message carries no re")
	}
}

func TestBuildMsgOmitsEmptySubject(t *testing.T) {
	payload, err := BuildMsg(sender, []string{kid(peer)}, "", "hi", ts, MaxBody)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(`"subject"`)) {
		t.Fatalf("empty subject must be omitted (§7.2 subject is 1-200 bytes): %s", payload)
	}
	if _, err := clankmail.Verify(clankmail.Sign(sender, payload)); err != nil {
		t.Fatal(err)
	}
}

func TestBuildMsgLimits(t *testing.T) {
	keys := func(n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, kid(testKey(strings.Repeat("r", i+1))))
		}
		return out
	}
	one := []string{kid(peer)}
	ok := []struct {
		name          string
		to            []string
		subject, body string
		max           int
	}{
		{"body at 32768", one, "", strings.Repeat("a", 32768), MaxBody},
		{"subject at 200", one, strings.Repeat("s", 200), "b", MaxBody},
		{"32 key recipients", keys(32), "", "b", MaxBody},
		{"one channel", []string{cid("chan")}, "", "b", MaxBody},
		{"body at a 16384 limit, in bytes", one, "", strings.Repeat("é", 8192), 16384},
	}
	for _, c := range ok {
		p, err := BuildMsg(sender, c.to, c.subject, c.body, ts, c.max)
		if err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
			continue
		}
		if _, err := clankmail.Verify(clankmail.Sign(sender, p)); err != nil {
			t.Errorf("%s: built but does not verify: %v", c.name, err)
		}
	}
	bad := []struct {
		name          string
		to            []string
		subject, body string
		max           int
		want          string
	}{
		{"empty body", one, "", "", MaxBody, "body is 0 bytes"},
		{"body at 32769", one, "", strings.Repeat("a", 32769), MaxBody, "body is 32769 bytes"},
		{"body over a 16384 limit, in bytes", one, "", strings.Repeat("é", 8193), 16384, "body is 16386 bytes; it must be 1-16384"},
		{"subject at 201", one, strings.Repeat("s", 201), "b", MaxBody, "subject is 201 bytes"},
		{"33 key recipients", keys(33), "", "b", MaxBody, "33 key recipients"},
		{"no recipients", nil, "", "b", MaxBody, "at least one recipient"},
		{"duplicate key", []string{kid(peer), kid(peer)}, "", "b", MaxBody, "listed twice"},
		{"channel plus key", []string{cid("chan"), kid(peer)}, "", "b", MaxBody, "only recipient"},
		{"key then channel", []string{kid(peer), cid("chan")}, "", "b", MaxBody, "is not a k_ key id"},
		{"uppercase key", []string{"k_" + strings.ToUpper(kid(peer)[2:])}, "", "b", MaxBody, "is not a k_ key id"},
		{"short key", []string{kid(peer)[:50]}, "", "b", MaxBody, "is not a k_ key id"},
		{"handle, not key", []string{"@owner/chief"}, "", "b", MaxBody, "is not a k_ key id"},
		{"bad channel", []string{"c_abc"}, "", "b", MaxBody, "is not a c_ channel id"},
		{"invalid UTF-8", one, "", "a\xffb", MaxBody, "valid UTF-8"},
	}
	for _, c := range bad {
		_, err := BuildMsg(sender, c.to, c.subject, c.body, ts, c.max)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
}

func TestReadKeyFile(t *testing.T) {
	priv, err := ReadKeyFile(writeKey(t, sender))
	if err != nil || !priv.Equal(sender) {
		t.Fatalf("round trip: %v", err)
	}
	seed := base64.RawURLEncoding.EncodeToString(sender.Seed())
	for name, text := range map[string]string{
		"padded":      base64.URLEncoding.EncodeToString(sender.Seed()) + "\n",
		"two lines":   seed + "\n" + seed + "\n",
		"leading sp":  " " + seed,
		"std base64":  strings.NewReplacer("-", "+", "_", "/").Replace(seed) + "x",
		"short":       seed[:40],
		"empty":       "",
		"crlf ending": seed + "\r\n",
	} {
		p := filepath.Join(t.TempDir(), "k")
		os.WriteFile(p, []byte(text), 0o600)
		if _, err := ReadKeyFile(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeHub answers /v1/submit like a conforming hub that accepts everything
// that passes §4, and records what it received.
type fakeHub struct {
	srv    *httptest.Server
	tokens []string
	status int    // when non-zero, answer this status instead
	answer string // and this body
	// when non-zero, verify and answer this status with the message's real
	// id, so a refusal is told apart only by its status
	statusWithID int
}

func newFakeHub(t *testing.T) *fakeHub {
	f := &fakeHub{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/submit" || r.Header.Get("Content-Type") != "text/plain" {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"E_NOT_FOUND","detail":"wrong route"}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.tokens = append(f.tokens, string(b))
		if f.status != 0 {
			w.WriteHeader(f.status)
			io.WriteString(w, f.answer)
			return
		}
		obj, err := clankmail.Verify(string(b))
		if err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": err.(*clankmail.Error).Code, "detail": err.Error()})
			return
		}
		if f.statusWithID != 0 {
			w.WriteHeader(f.statusWithID)
		}
		json.NewEncoder(w).Encode(map[string]string{"id": obj.ID})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func runCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, &o, &e, func() time.Time { return time.UnixMilli(ts) }, defaultClient())
	return code, o.String(), e.String()
}

func TestRunSubmitsAndPrintsID(t *testing.T) {
	hub := newFakeHub(t)
	code, out, errOut := runCmd(t, "--key", writeKey(t, sender), "--hub", hub.srv.URL+"/",
		"--to", kid(peer), "--subject", "hello", "--body", "First message.")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if len(hub.tokens) != 1 {
		t.Fatalf("hub received %d submissions", len(hub.tokens))
	}
	obj, err := clankmail.Verify(hub.tokens[0])
	if err != nil {
		t.Fatalf("submitted token does not verify: %v", err)
	}
	if obj.From != kid(sender) || obj.Fields["ts"] != ts || obj.Fields["body"] != "First message." ||
		obj.Fields["subject"] != "hello" || !reflect.DeepEqual(obj.Fields["to"], []any{kid(peer)}) {
		t.Fatalf("submitted fields: %v", obj.Fields)
	}
	if out != obj.ID+"\n" {
		t.Fatalf("stdout %q, want the id %s", out, obj.ID)
	}
}

func TestRunBodyFile(t *testing.T) {
	hub := newFakeHub(t)
	bf := filepath.Join(t.TempDir(), "body.txt")
	os.WriteFile(bf, []byte("from a file\n"), 0o600)
	code, _, errOut := runCmd(t, "--key", writeKey(t, sender), "--hub", hub.srv.URL,
		"--to", kid(peer)+","+kid(other), "--body-file", bf)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	obj, _ := clankmail.Verify(hub.tokens[0])
	if obj.Fields["body"] != "from a file\n" || len(obj.Fields["to"].([]any)) != 2 {
		t.Fatalf("fields: %v", obj.Fields)
	}
}

// Every non-2xx answer, a redirect, a 2xx without the message's id and an
// unreachable hub exit 1 with nothing on stdout.
func TestRunHubRefusalExitsNonZero(t *testing.T) {
	cases := []struct {
		name   string
		status int
		answer string
		want   string
	}{
		{"E_STALE", 400, `{"error":"E_STALE","detail":"ts outside ±300 s of hub time"}`, `"E_STALE"`},
		{"E_FORBIDDEN", 403, `{"error":"E_FORBIDDEN","detail":"no"}`, `403 Forbidden "E_FORBIDDEN"`},
		{"E_RATE", 429, `{"error":"E_RATE","detail":"slow down"}`, "429"},
		{"500 not JSON", 500, `oops`, "500 Internal Server Error"},
		{"redirect", 302, ``, "302 Found"},
		{"200 wrong id", 200, `{"id":"m_` + strings.Repeat("a", 52) + `"}`, "the message's id is"},
		{"200 no id", 200, `{}`, "without an m_ id"},
		{"201 not JSON", 201, `ok`, "without an m_ id"},
	}
	for _, c := range cases {
		hub := newFakeHub(t)
		hub.status, hub.answer = c.status, c.answer
		code, out, errOut := runCmd(t, "--key", writeKey(t, sender), "--hub", hub.srv.URL,
			"--to", kid(peer), "--body", "x")
		if code != 1 || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: exit %d stdout %q stderr %q; want exit 1, empty stdout, stderr containing %q",
				c.name, code, out, errOut, c.want)
		}
		if len(hub.tokens) != 1 {
			t.Errorf("%s: hub received %d submissions, want 1", c.name, len(hub.tokens))
		}
	}
	for _, st := range []int{400, 404, 500} {
		hub := newFakeHub(t)
		hub.statusWithID = st
		code, out, _ := runCmd(t, "--key", writeKey(t, sender), "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x")
		if code != 1 || out != "" {
			t.Errorf("status %d carrying the message's id: exit %d stdout %q, want 1 and empty", st, code, out)
		}
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	code, out, _ := runCmd(t, "--key", writeKey(t, sender), "--hub", url, "--to", kid(peer), "--body", "x")
	if code != 1 || out != "" {
		t.Errorf("unreachable hub: exit %d stdout %q", code, out)
	}
}

// Input errors exit 2 and send nothing.
func TestRunUsageErrorsSendNothing(t *testing.T) {
	hub := newFakeHub(t)
	key := writeKey(t, sender)
	cases := map[string][]string{
		"key as argv":         {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x", "SECRETSEED"},
		"no key":              {"--hub", hub.srv.URL, "--to", kid(peer), "--body", "x"},
		"no to":               {"--key", key, "--hub", hub.srv.URL, "--body", "x"},
		"no body":             {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer)},
		"both bodies":         {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x", "--body-file", key},
		"bad hub":             {"--key", key, "--hub", "ftp://h.example", "--to", kid(peer), "--body", "x"},
		"over max-body":       {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--max-body", "16384", "--body", strings.Repeat("a", 16385)},
		"max-body above spec": {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--max-body", "32769", "--body", "x"},
		"bad key file":        {"--key", hub.srv.URL, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x"},
		// 20000 NULs escape to 120000 JSON bytes: under the body limit, over
		// the §4 98304-byte token limit, caught by the Verify gate.
		"token too large": {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", strings.Repeat("\x00", 20000)},
	}
	for name, args := range cases {
		code, out, _ := runCmd(t, args...)
		if code != 2 || out != "" {
			t.Errorf("%s: exit %d stdout %q, want 2 and empty", name, code, out)
		}
	}
	if len(hub.tokens) != 0 {
		t.Fatalf("usage errors sent %d submissions", len(hub.tokens))
	}
}
