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
	payload, err := BuildMsg(sender, to, "hello <&>", "First message.\nline two é", ts)
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
	payload, err := BuildMsg(sender, []string{kid(peer)}, "", "hi", ts)
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

// keys returns n distinct k_ ids.
func keys(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, kid(testKey(strings.Repeat("r", i+1))))
	}
	return out
}

// Inputs at the §7.2 limits build into a message that verifies: the builder's
// encoding does not push a legal message over a limit.
func TestBuildMsgAtSpecLimitsVerifies(t *testing.T) {
	one := []string{kid(peer)}
	for _, c := range []struct {
		name          string
		to            []string
		subject, body string
	}{
		{"body at 32768", one, "", strings.Repeat("a", 32768)},
		{"body at 32768, in bytes", one, "", strings.Repeat("é", 16384)},
		{"subject at 200", one, strings.Repeat("s", 200), "b"},
		{"32 key recipients", keys(32), "", "b"},
		{"one channel", []string{cid("chan")}, "", "b"},
	} {
		p, err := BuildMsg(sender, c.to, c.subject, c.body, ts)
		if err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
			continue
		}
		if _, err := clankmail.Verify(clankmail.Sign(sender, p)); err != nil {
			t.Errorf("%s: built but does not verify: %v", c.name, err)
		}
	}
}

// Go's json encoder would replace invalid UTF-8 with U+FFFD and sign text the
// caller never wrote, so BuildMsg refuses it before encoding.
func TestBuildMsgRefusesInvalidUTF8(t *testing.T) {
	for name, c := range map[string][2]string{
		"body":    {"", "a\xffb"},
		"subject": {"s\xc3", "b"},
	} {
		_, err := BuildMsg(sender, []string{kid(peer)}, c[0], c[1], ts)
		if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
			t.Errorf("invalid UTF-8 %s: want error containing %q, got %v", name, "valid UTF-8", err)
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
	srv      *httptest.Server
	tokens   []string
	status   int    // when non-zero, answer this status instead
	answer   string // and this body
	location string // and, when set, this Location header
	// when non-zero, verify and answer this status with the message's real
	// id, so a refusal is told apart only by its status
	statusWithID int
	// when non-zero, verify and answer 200 with this many bytes of padding
	// before the message's real id
	pad int
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
			if f.location != "" {
				w.Header().Set("Location", f.location)
			}
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
		if f.pad != 0 {
			json.NewEncoder(w).Encode(map[string]string{"a_pad": strings.Repeat("x", f.pad), "id": obj.ID})
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

// Every non-2xx answer, a 2xx without the message's id and an unreachable hub
// exit 1 with nothing on stdout. Redirects: TestRunRedirectNotFollowed.
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

// A redirect is not an answer from the hub. The origin redirects to a second
// hub that would accept the message; the program must not follow it. 307 and
// 308 keep the POST and its body, so a followed redirect would deliver the
// message to the target and exit 0; 302 turns it into a GET.
func TestRunRedirectNotFollowed(t *testing.T) {
	for _, c := range []struct {
		status int
		want   string
	}{
		{307, "307 Temporary Redirect"},
		{308, "308 Permanent Redirect"},
		{302, "302 Found"},
	} {
		target := newFakeHub(t)
		origin := newFakeHub(t)
		origin.status, origin.location = c.status, target.srv.URL+"/v1/submit"
		code, out, errOut := runCmd(t, "--key", writeKey(t, sender), "--hub", origin.srv.URL,
			"--to", kid(peer), "--body", "x")
		if code != 1 || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("%d to an accepting hub: exit %d stdout %q stderr %q; want exit 1, empty stdout, stderr containing %q",
				c.status, code, out, errOut, c.want)
		}
		if len(origin.tokens) != 1 || len(target.tokens) != 0 {
			t.Errorf("%d to an accepting hub: origin received %d submissions, target %d; want 1 and 0",
				c.status, len(origin.tokens), len(target.tokens))
		}
	}
}

// Only the first 64 KiB of a hub answer is read: a 2xx whose id comes after
// the cap is an answer without an id.
func TestRunResponseCap(t *testing.T) {
	for _, c := range []struct {
		pad  int
		code int
	}{
		{1000, 0},        // well under the cap: accepted
		{maxResponse, 1}, // the id starts past the cap
	} {
		hub := newFakeHub(t)
		hub.pad = c.pad
		code, out, errOut := runCmd(t, "--key", writeKey(t, sender), "--hub", hub.srv.URL,
			"--to", kid(peer), "--body", "x")
		if code != c.code {
			t.Errorf("200 with %d bytes of padding before the id: exit %d stdout %q stderr %q, want %d",
				c.pad, code, out, errOut, c.code)
		}
		if c.code == 1 && (out != "" || !strings.Contains(errOut, "200 OK without an m_ id")) {
			t.Errorf("past the cap: stdout %q stderr %q, want empty stdout and %q", out, errOut, "200 OK without an m_ id")
		}
	}
}

// A key file longer than the cap is refused before it is parsed, without
// repeating its contents, and nothing is sent.
func TestRunOversizedKeyFile(t *testing.T) {
	hub := newFakeHub(t)
	seed := base64.RawURLEncoding.EncodeToString(sender.Seed())
	for _, n := range []int{maxKeyFile + 1, 1 << 20} {
		p := filepath.Join(t.TempDir(), "big.key")
		text := seed + "\n" + "KEYMARKER" + strings.Repeat("A", n-len(seed)-1-len("KEYMARKER"))
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := runCmd(t, "--key", p, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x")
		want := "the key file is longer than 128 bytes"
		if code != 2 || out != "" || !strings.Contains(errOut, want) {
			t.Errorf("%d-byte key file: exit %d stdout %q stderr %q; want exit 2, empty stdout, stderr containing %q",
				n, code, out, errOut, want)
		}
		if strings.Contains(errOut, "KEYMARKER") || strings.Contains(errOut, seed) {
			t.Errorf("%d-byte key file: stderr repeats the file: %q", n, errOut)
		}
	}
	if len(hub.tokens) != 0 {
		t.Fatalf("an oversized key file sent %d submissions", len(hub.tokens))
	}
}

// Input errors exit 2 and send nothing.
func TestRunUsageErrorsSendNothing(t *testing.T) {
	hub := newFakeHub(t)
	key := writeKey(t, sender)
	cases := map[string][]string{
		"key as argv":        {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x", "SECRETSEED"},
		"key as a flag":      {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x", "-SECRETSEED"},
		"key as a value":     {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x", "--max-body", "SECRETSEED"},
		"no key":             {"--hub", hub.srv.URL, "--to", kid(peer), "--body", "x"},
		"no to":              {"--key", key, "--hub", hub.srv.URL, "--body", "x"},
		"no body":            {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer)},
		"both bodies":        {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x", "--body-file", key},
		"bad hub":            {"--key", key, "--hub", "ftp://h.example", "--to", kid(peer), "--body", "x"},
		"negative max-body":  {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--max-body", "-1", "--body", "x"},
		"invalid UTF-8 body": {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "a\xffb"},
		"bad key file":       {"--key", hub.srv.URL, "--hub", hub.srv.URL, "--to", kid(peer), "--body", "x"},
		// 20000 NULs escape to 120000 JSON bytes: under the body limit, over
		// the §4 98304-byte token limit, caught by the Verify gate.
		"token too large": {"--key", key, "--hub", hub.srv.URL, "--to", kid(peer), "--body", strings.Repeat("\x00", 20000)},
	}
	for name, args := range cases {
		code, out, errOut := runCmd(t, args...)
		if code != 2 || out != "" {
			t.Errorf("%s: exit %d stdout %q, want 2 and empty", name, code, out)
		}
		if name == "key as a flag" || name == "key as a value" {
			want := map[string]string{"key as a flag": "send-first: unknown flag (the argument is not echoed)", "key as a value": "send-first: invalid flag value (the argument is not echoed)"}[name]
			if strings.Contains(errOut, "SECRETSEED") || !strings.Contains(errOut, want) {
				t.Errorf("%s: stderr %q; want %q and no trace of the argument", name, errOut, want)
			}
		}
		if name == "key as argv" {
			const want = "unexpected positional argument (10 bytes); the key is read from --key FILE, never from argv"
			if strings.Contains(errOut, "SECRETSEED") || !strings.Contains(errOut, want) {
				t.Errorf("key as argv: stderr %q; want %q and no trace of the argument", errOut, want)
			}
		}
	}
	if len(hub.tokens) != 0 {
		t.Fatalf("usage errors sent %d submissions", len(hub.tokens))
	}
}

// --max-body is a stricter limit the caller chooses, counted in bytes.
func TestRunMaxBody(t *testing.T) {
	hub := newFakeHub(t)
	key := writeKey(t, sender)
	code, _, errOut := runCmd(t, "--key", key, "--hub", hub.srv.URL, "--to", kid(peer),
		"--max-body", "16384", "--body", strings.Repeat("é", 8192))
	if code != 0 || len(hub.tokens) != 1 {
		t.Fatalf("body at a 16384 limit: exit %d, %d submissions, stderr %q", code, len(hub.tokens), errOut)
	}
	code, _, errOut = runCmd(t, "--key", key, "--hub", hub.srv.URL, "--to", kid(peer),
		"--max-body", "16384", "--body", strings.Repeat("é", 8193))
	if want := "body is 16386 bytes; --max-body is 16384"; code != 2 || !strings.Contains(errOut, want) {
		t.Fatalf("body over a 16384 limit: exit %d stderr %q, want 2 and %q", code, errOut, want)
	}
	if len(hub.tokens) != 1 {
		t.Fatalf("the refused body was sent: %d submissions", len(hub.tokens))
	}
}

// A message that breaks a §7.2 field rule is refused by the post-sign Verify
// gate: exit 2, the reason from Verify on stderr, and no request to the hub.
func TestRunSchemaInvalidRefusedBeforeSend(t *testing.T) {
	key := writeKey(t, sender)
	empty := filepath.Join(t.TempDir(), "empty.txt")
	os.WriteFile(empty, nil, 0o600)
	const gate = "the signed message does not verify: E_SCHEMA: "
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"33 key recipients", []string{"--to", strings.Join(keys(33), ","), "--body", "b"}, "to: want array of 1–32 items"},
		{"duplicate key", []string{"--to", kid(peer), "--to", kid(peer), "--body", "b"}, "to: duplicate array item"},
		{"channel plus key", []string{"--to", cid("chan") + "," + kid(peer), "--body", "b"}, "to: want k_ id"},
		{"handle, not key", []string{"--to", "@owner/chief", "--body", "b"}, "to: want k_ id"},
		{"empty body", []string{"--to", kid(peer), "--body-file", empty}, "body: want string of 1–32768 bytes"},
		{"body at 32769", []string{"--to", kid(peer), "--body", strings.Repeat("a", 32769)}, "body: want string of 1–32768 bytes"},
		{"body at 32770, in bytes", []string{"--to", kid(peer), "--body", strings.Repeat("é", 16385)}, "body: want string of 1–32768 bytes"},
		{"subject at 201", []string{"--to", kid(peer), "--subject", strings.Repeat("s", 201), "--body", "b"}, "subject: want string of 1–200 bytes"},
	}
	for _, c := range cases {
		hub := newFakeHub(t)
		code, out, errOut := runCmd(t, append([]string{"--key", key, "--hub", hub.srv.URL}, c.args...)...)
		if code != 2 || out != "" || !strings.Contains(errOut, gate+c.want) {
			t.Errorf("%s: exit %d stdout %q stderr %q; want exit 2, empty stdout, stderr containing %q",
				c.name, code, out, errOut, gate+c.want)
		}
		if len(hub.tokens) != 0 {
			t.Errorf("%s: hub received %d requests, want 0", c.name, len(hub.tokens))
		}
	}
}
