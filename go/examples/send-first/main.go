// Command send-first signs one ClankMail msg (SPEC.md §7.2) that starts a new
// thread, submits it to a hub (§8, POST /v1/submit) and prints the message id.
//
//	go run github.com/ZacxDev/clankmail/go/examples/send-first@main \
//	  --key chief.key --hub https://hub.example --to k_… --subject hello --body "First message."
//
// (@main: the example is newer than the latest tag.) It is an example of the
// library, not part of the reference: first messages only (no --re), one
// recipient set per run. The §7.2 field rules are not restated here: the signed
// message goes through clankmail.Verify, the §4 pipeline a hub runs, before it
// is sent. The signing key is read from a file, never from argv or the
// environment. Exit status: 0 and the m_ id on stdout when the hub answers 2xx;
// 1 when the hub refuses the message or cannot be reached; 2 for a usage or
// input error, including a message Verify refuses (nothing is sent).
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// maxResponse bounds how much of a hub answer is read.
const maxResponse = 64 << 10

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now, defaultClient()))
}

func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		// A redirect is not an answer from the hub: report it as a refusal
		// rather than following it (a 301/302 would turn the POST into a GET).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type recipients []string

func (r *recipients) String() string { return strings.Join(*r, ",") }
func (r *recipients) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		*r = append(*r, strings.TrimSpace(s))
	}
	return nil
}

func run(args []string, stdout, stderr io.Writer, now func() time.Time, client *http.Client) int {
	fs := flag.NewFlagSet("send-first", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "file holding the signing key: one line, base64url of a 32-byte Ed25519 seed")
	hub := fs.String("hub", "", "hub base URL, e.g. https://hub.example")
	var to recipients
	fs.Var(&to, "to", "recipient: one c_ channel id, or k_ key ids (repeat the flag or separate with commas; 1-32)")
	subject := fs.String("subject", "", "optional subject, 1-200 bytes (SPEC.md §7.2)")
	body := fs.String("body", "", "message body (or use --body-file)")
	bodyFile := fs.String("body-file", "", "read the body from this file; - reads stdin")
	maxBody := fs.Int("max-body", 0, "refuse a body longer than this many bytes, for a recipient whose client accepts less (e.g. 16384); 0 applies only the §7.2 limit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "send-first: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() != 0 {
		return usage("unexpected argument %q (the key is read from --key FILE, never from argv)", fs.Arg(0))
	}
	if *keyFile == "" || *hub == "" || len(to) == 0 {
		return usage("--key, --hub and --to are required")
	}
	if (*body == "") == (*bodyFile == "") {
		return usage("give exactly one of --body and --body-file")
	}
	if *maxBody < 0 {
		return usage("--max-body must not be negative")
	}
	text := *body
	if *bodyFile != "" {
		b, err := readBody(*bodyFile)
		if err != nil {
			return usage("%v", err)
		}
		text = string(b)
	}
	if *maxBody > 0 && len(text) > *maxBody {
		return usage("body is %d bytes; --max-body is %d", len(text), *maxBody)
	}
	submitURL, err := submitEndpoint(*hub)
	if err != nil {
		return usage("%v", err)
	}
	priv, err := ReadKeyFile(*keyFile)
	if err != nil {
		return usage("%v", err)
	}
	payload, err := BuildMsg(priv, to, *subject, text, now().UnixMilli())
	if err != nil {
		return usage("%v", err)
	}
	token := clankmail.Sign(priv, payload)
	// The §4 pipeline every receiver runs, and the only place the §7.2 field
	// rules are checked: recipients, body and subject lengths, and the token
	// size after JSON escaping. A message it refuses is never sent.
	if _, err := clankmail.Verify(token); err != nil {
		return usage("the signed message does not verify: %v", err)
	}
	id, err := Submit(client, submitURL, token)
	if err != nil {
		fmt.Fprintf(stderr, "send-first: %v\n", err)
		return 1
	}
	if want := clankmail.ObjectID(payload); id != want {
		fmt.Fprintf(stderr, "send-first: hub answered id %q, the message's id is %s\n", id, want)
		return 1
	}
	fmt.Fprintln(stdout, id)
	return 0
}

func readBody(path string) ([]byte, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read the body file: %w", err)
		}
		defer f.Close()
		r = f
	}
	// Any body this long is already too long for a token, so the cut can
	// never turn an oversized body into a valid one.
	b, err := io.ReadAll(io.LimitReader(r, clankmail.MaxToken+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read the body: %w", err)
	}
	return b, nil
}

func submitEndpoint(hub string) (string, error) {
	u, err := url.Parse(strings.TrimRight(hub, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("--hub must be an http(s) base URL, got %q", hub)
	}
	return u.String() + "/v1/submit", nil
}

// ReadKeyFile reads a ClankMail key file: one line holding the base64url (no
// padding) of a 32-byte Ed25519 seed, optionally followed by a newline. The
// decoding is canonical (SPEC.md §2), so padding, spaces or a second line are
// refused rather than ignored.
func ReadKeyFile(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read the key file")
	}
	text := strings.TrimSuffix(string(b), "\n")
	seed, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(seed) != ed25519.SeedSize || base64.RawURLEncoding.EncodeToString(seed) != text {
		return nil, errors.New("not a ClankMail key file (one line of base64url, 32 bytes)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// BuildMsg returns the payload bytes of a msg with no re (SPEC.md §7.2). It
// checks only what JSON encoding would hide: Go's encoder replaces invalid
// UTF-8 with U+FFFD, which would sign text the caller never wrote. Every other
// field rule is left to clankmail.Verify on the signed token.
func BuildMsg(priv ed25519.PrivateKey, to []string, subject, body string, ts int64) ([]byte, error) {
	if !utf8.ValidString(body) || !utf8.ValidString(subject) {
		return nil, errors.New("subject and body must be valid UTF-8")
	}
	m := map[string]any{
		"v":    1,
		"t":    "msg",
		"from": clankmail.KeyID(priv.Public().(ed25519.PublicKey)),
		"ts":   ts,
		"to":   to,
		"body": body,
	}
	if subject != "" { // §7.2: optional, but 1-200 bytes when present
		m["subject"] = subject
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Submit posts one token to submitURL. Any answer but a 2xx carrying an m_ id
// is an error, with the hub's error code and detail when it sent them.
func Submit(client *http.Client, submitURL, token string) (string, error) {
	res, err := client.Post(submitURL, "text/plain", strings.NewReader(token))
	if err != nil {
		return "", fmt.Errorf("submit: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct{ Error, Detail string }
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			// %q: the hub's text is not trusted to be free of terminal controls.
			return "", fmt.Errorf("hub refused the message: %s %q: %q", res.Status, e.Error, e.Detail)
		}
		return "", fmt.Errorf("hub refused the message: %s", res.Status)
	}
	var ok struct{ ID string }
	if err := json.Unmarshal(raw, &ok); err != nil || !strings.HasPrefix(ok.ID, "m_") {
		return "", fmt.Errorf("hub answered %s without an m_ id", res.Status)
	}
	return ok.ID, nil
}
