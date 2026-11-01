package hub

// Tests for Config.ClientIPHeader (-client-ip-header): a front that
// overwrites X-Forwarded-For and puts the visitor address in one header.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

const ipHeader = "CF-Connecting-IP"

func TestClientIPHeaderAddress(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h, err := New(Config{Name: hubName, Store: store, ClientIPHeader: ipHeader,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:ff::/48")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		peer   string
		header []string // one entry per header line; nil = absent
		xff    string
		want   string
	}{
		{"trusted peer, valid header", "10.0.0.1:5000", []string{"203.0.113.7"}, "", "203.0.113.7"},
		{"trusted peer, header with spaces", "10.0.0.1:5000", []string{"  203.0.113.7 "}, "", "203.0.113.7"},
		{"trusted v6 peer, valid header", "[2001:db8:ff::1]:5000", []string{"203.0.113.7"}, "", "203.0.113.7"},
		{"trusted peer, IPv6 header grouped by /64", "10.0.0.1:5000", []string{"2001:db8:1:2::5"}, "", "2001:db8:1:2::/64"},
		{"trusted peer, v4-mapped header unmapped", "10.0.0.1:5000", []string{"::ffff:203.0.113.7"}, "", "203.0.113.7"},
		{"untrusted peer, header ignored", "198.51.100.1:5000", []string{"203.0.113.7"}, "", "198.51.100.1"},
		{"trusted peer, header absent", "10.0.0.1:5000", nil, "", "10.0.0.1"},
		{"trusted peer, header empty", "10.0.0.1:5000", []string{""}, "", "10.0.0.1"},
		{"trusted peer, header is a list", "10.0.0.1:5000", []string{"203.0.113.7, 203.0.113.8"}, "", "10.0.0.1"},
		{"trusted peer, header repeated", "10.0.0.1:5000", []string{"203.0.113.7", "203.0.113.8"}, "", "10.0.0.1"},
		{"trusted peer, header garbage", "10.0.0.1:5000", []string{"not-an-ip"}, "", "10.0.0.1"},
		{"trusted peer, header with port", "10.0.0.1:5000", []string{"203.0.113.7:443"}, "", "10.0.0.1"},
		{"trusted peer, header with zone", "10.0.0.1:5000", []string{"fe80::1%eth0"}, "", "10.0.0.1"},
		{"XFF ignored when header absent", "10.0.0.1:5000", nil, "203.0.113.9", "10.0.0.1"},
		{"XFF ignored when header present", "10.0.0.1:5000", []string{"203.0.113.7"}, "203.0.113.9", "203.0.113.7"},
		{"XFF ignored when header garbage", "10.0.0.1:5000", []string{"junk"}, "203.0.113.9", "10.0.0.1"},
	} {
		r := httptest.NewRequest("POST", "/v1/submit", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.header {
			r.Header.Add(ipHeader, v)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := h.clientAddr(r); got != c.want {
			t.Errorf("%s: clientAddr = %q, want %q", c.name, got, c.want)
		}
	}
}

// A header option no peer can ever satisfy is a config that silently does
// nothing: refuse it.
func TestClientIPHeaderRequiresTrustedProxies(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if _, err := New(Config{Name: hubName, Store: store, ClientIPHeader: ipHeader}); err == nil ||
		!strings.Contains(err.Error(), "ClientIPHeader requires TrustedProxies") {
		t.Fatalf("New with ClientIPHeader and no TrustedProxies: err = %v, want refusal", err)
	}
	// Control: the same config with a trusted proxy is accepted.
	if _, err := New(Config{Name: hubName, Store: store, ClientIPHeader: ipHeader,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}); err != nil {
		t.Fatalf("New with ClientIPHeader and TrustedProxies: %v", err)
	}
}

// A header name that is not an HTTP token can never match a received header,
// so it is refused rather than silently keying every visitor on the proxy.
func TestClientIPHeaderNameMustBeAToken(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, name := range []string{"CF-Connecting-IP ", " CF-Connecting-IP", "CF-Connecting-IP:", "CF Connecting IP", "X-\u00e9"} {
		if _, err := New(Config{Name: hubName, Store: store, ClientIPHeader: name, TrustedProxies: trusted}); err == nil ||
			!strings.Contains(err.Error(), "not a valid header name") {
			t.Errorf("ClientIPHeader %q: err = %v, want refusal", name, err)
		}
	}
	for _, name := range []string{"CF-Connecting-IP", "X-Real-IP", "true-client-ip"} {
		if _, err := New(Config{Name: hubName, Store: store, ClientIPHeader: name, TrustedProxies: trusted}); err != nil {
			t.Errorf("ClientIPHeader %q: %v, want accepted", name, err)
		}
	}
}

// submitVia posts a fresh DM through the test server with the given headers.
func (e *env) submitVia(n int, headers map[string]string) int {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/submit", strings.NewReader(e.dm(scout, fmt.Sprint("via ", n), bob)))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	json.NewDecoder(res.Body).Decode(&body)
	if res.StatusCode != 200 && !(res.StatusCode == 429 && body["error"] == ERate) {
		e.t.Fatalf("submit %d: unexpected %d %v", n, res.StatusCode, body)
	}
	return res.StatusCode
}

// Behind one trusted proxy (the test server's peer is 127.0.0.1), two
// visitors get separate per-address buckets; X-Forwarded-For cannot move a
// visitor to a fresh bucket; malformed headers all share the proxy's bucket.
func TestClientIPHeaderSeparatesVisitorsBehindProxy(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		c.ClientIPHeader = ipHeader
		c.IPLimit = Limit{Burst: 2, PerSec: 0.001}
	})
	n := 0
	step := func(what string, headers map[string]string, want int) {
		t.Helper()
		n++
		if got := e.submitVia(n, headers); got != want {
			t.Fatalf("%s: got %d, want %d", what, got, want)
		}
	}
	a := map[string]string{ipHeader: "203.0.113.10"}
	step("visitor A #1", a, 200)
	step("visitor A #2", a, 200)
	step("visitor A #3 (bucket spent)", a, 429)
	step("visitor B #1 behind the same proxy", map[string]string{ipHeader: "203.0.113.20"}, 200)
	step("visitor A rotating X-Forwarded-For", map[string]string{ipHeader: "203.0.113.10", "X-Forwarded-For": "198.51.100.1"}, 429)
	// Malformed headers fall back to the proxy's own address: one bucket.
	step("garbage header #1", map[string]string{ipHeader: "junk-1"}, 200)
	step("garbage header #2", map[string]string{ipHeader: "junk-2, 203.0.113.99"}, 200)
	step("garbage header #3 (proxy bucket spent)", map[string]string{ipHeader: "junk-3"}, 429)
	step("no header, fresh XFF (proxy bucket spent)", map[string]string{"X-Forwarded-For": "198.51.100.2"}, 429)
}

// From a peer outside TrustedProxies the header is ignored: rotating it
// cannot buy fresh buckets.
func TestClientIPHeaderIgnoredFromUntrustedPeer(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} // not the test peer
		c.ClientIPHeader = ipHeader
		c.IPLimit = Limit{Burst: 2, PerSec: 0.001}
	})
	for i, v := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		want := map[bool]int{true: 200, false: 429}[i < 2]
		if got := e.submitVia(i, map[string]string{ipHeader: v}); got != want {
			t.Fatalf("untrusted peer, spoofed header %s: got %d, want %d", v, got, want)
		}
	}
}
