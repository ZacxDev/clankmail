package hub

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// raw performs a request the way a browser on another origin would (with an
// Origin header) and returns the status and response headers.
func (e *env) raw(method, path string, body []byte, auth string) (int, http.Header) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Origin", "https://page.example")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode, res.Header
}

// corsHeaders lists every CORS response header present.
func corsHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Access-Control-") {
			out[k] = h.Get(k)
		}
	}
	return out
}

// TestDiscoveryCORS: GET /v1/channels, and only it, is readable from any
// origin (SPEC §8), on success and on its own errors, never with credentials.
func TestDiscoveryCORS(t *testing.T) {
	e := newEnv(t)
	alice := key("alice")
	e.createChannel(alice, "cors", "public", "anyone", "open", nil)

	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/v1/channels?sort=active", 200},
		{"/v1/channels", 200},
		{"/v1/channels?sort=bogus", 400},
		{"/v1/channels?limit=-1", 400},
	} {
		status, h := e.raw("GET", tc.path, nil, "")
		if status != tc.status {
			t.Fatalf("GET %s: status %d, want %d", tc.path, status, tc.status)
		}
		got := corsHeaders(h)
		want := map[string]string{"Access-Control-Allow-Origin": "*"}
		if len(got) != len(want) || got["Access-Control-Allow-Origin"] != "*" {
			t.Fatalf("GET %s (%d): CORS headers %v, want exactly %v", tc.path, status, got, want)
		}
	}
}

// TestNoCORSOutsideDiscovery: every other endpoint, including every one that
// takes auth (§6.4), sends no CORS header at all, on success. A preflight to
// discovery is not opened up either: OPTIONS falls to the hub's catch-all
// 404 E_NOT_FOUND, like any unrouted method, with no CORS header.
func TestNoCORSOutsideDiscovery(t *testing.T) {
	e := newEnv(t)
	alice, bob := key("alice"), key("bob")
	chID := e.createChannel(alice, "nocors", "public", "anyone", "open", nil)
	postTok := e.tok(alice, "msg", map[string]any{"to": []any{chID}, "body": "hi"})
	postID := e.mustSubmit(postTok)
	e.mustSubmit(e.tok(alice, "handle", map[string]any{"name": "alice", "hub": hubName}))
	e.mustSubmit(e.tok(bob, "sub", map[string]any{"channel": chID}))

	cases := []struct {
		method, path string
		body         []byte
		auth         bool
		status       int
	}{
		{"POST", "/v1/submit", []byte(e.tok(bob, "msg", map[string]any{"to": []any{chID}, "body": "x"})), false, 200},
		{"POST", "/v1/submit", []byte("not a token"), false, 400},
		{"GET", "/v1/objects/" + postID, nil, false, 200},
		{"GET", "/v1/inbox?queue=inbox", nil, true, 200},
		{"GET", "/v1/digest", nil, true, 200},
		{"GET", "/v1/subs", nil, true, 200},
		{"GET", "/v1/handles/alice", nil, false, 200},
		{"GET", "/v1/channels/" + chID, nil, false, 200},
		{"GET", "/v1/channels/%23nocors", nil, false, 200},
		{"GET", "/v1/channels/" + chID + "/log", nil, false, 200},
		{"GET", "/v1/nope", nil, false, 404},
		{"OPTIONS", "/v1/channels", nil, false, 404},
		{"POST", "/v1/channels", nil, false, 404},
	}
	for _, c := range cases {
		auth := ""
		if c.auth {
			auth = e.authFor(bob, 0, c.method, c.path, c.body, nil)
		}
		status, h := e.raw(c.method, c.path, c.body, auth)
		if status != c.status {
			t.Fatalf("%s %s: status %d, want %d", c.method, c.path, status, c.status)
		}
		if got := corsHeaders(h); len(got) != 0 {
			t.Fatalf("%s %s (%d): CORS headers %v, want none", c.method, c.path, status, got)
		}
	}
}
