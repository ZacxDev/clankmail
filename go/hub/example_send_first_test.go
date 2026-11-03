package hub

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// buildSendFirst builds the go/examples/send-first program from this checkout.
func buildSendFirst(t *testing.T) string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("this test builds go/examples/send-first and needs the go tool on PATH")
	}
	bin := filepath.Join(t.TempDir(), "send-first")
	cmd := exec.Command(gobin, "build", "-o", bin, "./go/examples/send-first")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build send-first: %v\n%s", err, out)
	}
	return bin
}

// The example program against this hub: the seam between the two. A first
// message from alice is accepted (exit 0) and the id it prints names the
// signed message the hub stored. Queue placement and hub refusals are covered
// by this package's own tests and by the program's fake-hub tests.
func TestExampleSendFirstAgainstHub(t *testing.T) {
	bin := buildSendFirst(t)
	// The program signs with the wall clock, so the hub's clock (frozen, and
	// shared with the auth tokens e.as signs) is set to it.
	e := newEnv(t)
	e.now.Store(time.Now().UnixMilli())
	keyFile := filepath.Join(t.TempDir(), "alice.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(alice.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var o, er bytes.Buffer
	cmd := exec.Command(bin, "--key", keyFile, "--hub", e.srv.URL, "--to", kid(bob),
		"--subject", "hello", "--body", "First message.")
	cmd.Stdout, cmd.Stderr = &o, &er
	if err := cmd.Run(); err != nil {
		t.Fatalf("send-first: %v: %s", err, er.String())
	}
	id := strings.TrimSpace(o.String())
	r := e.as(bob, "GET", "/v1/objects/"+id, nil)
	if r.status != 200 {
		t.Fatalf("GET the printed id %q: status %d %v", id, r.status, r.body)
	}
	obj, err := clankmail.Verify(r.str("token"))
	if err != nil {
		t.Fatalf("stored token: %v", err)
	}
	if obj.ID != id || obj.From != kid(alice) || obj.Fields["body"] != "First message." || obj.Fields["subject"] != "hello" {
		t.Fatalf("printed id %s; stored object %s from %s, fields %v", id, obj.ID, obj.From, obj.Fields)
	}
}
