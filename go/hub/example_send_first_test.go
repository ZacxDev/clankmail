package hub

import (
	"bytes"
	"encoding/base64"
	"errors"
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

// The example program against this hub, end to end: a first message from
// alice is accepted, its printed id is the stored object, and it lands in
// bob's requests queue (alice is not on bob's allow list, and it has no re).
// A hub refusal exits 1.
func TestExampleSendFirstAgainstHub(t *testing.T) {
	bin := buildSendFirst(t)
	// The program signs with the wall clock, so the hub's clock (frozen, and
	// shared with the auth tokens e.queue signs) is set to it.
	e := newEnv(t)
	e.now.Store(time.Now().UnixMilli())
	keyFile := filepath.Join(t.TempDir(), "alice.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(alice.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	send := func(hubURL string) (int, string, string) {
		var o, er bytes.Buffer
		cmd := exec.Command(bin, "--key", keyFile, "--hub", hubURL, "--to", kid(bob),
			"--subject", "hello", "--body", "First message.")
		cmd.Stdout, cmd.Stderr = &o, &er
		err := cmd.Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return 0, o.String(), er.String()
		case errors.As(err, &ee):
			return ee.ExitCode(), o.String(), er.String()
		}
		t.Fatal(err)
		return 0, "", ""
	}

	code, out, errOut := send(e.srv.URL)
	if code != 0 {
		t.Fatalf("send-first exit %d: %s", code, errOut)
	}
	id := strings.TrimSpace(out)
	reqs := e.queue(bob, "requests")
	if len(reqs) != 1 || idOf(t, reqs[0]) != id {
		t.Fatalf("bob requests %v, want the one message %s", reqs, id)
	}
	obj, _ := clankmail.Verify(reqs[0])
	if obj.From != kid(alice) || obj.Fields["body"] != "First message." || obj.Fields["subject"] != "hello" {
		t.Fatalf("stored fields: %v", obj.Fields)
	}
	if got := e.queue(bob, "inbox"); len(got) != 0 {
		t.Fatalf("a first message from a sender bob never allowed reached his inbox: %v", got)
	}

	// A hub whose clock is 10 minutes ahead refuses the message as stale.
	skewed := newEnv(t)
	skewed.now.Store(time.Now().Add(10 * time.Minute).UnixMilli())
	code, out, errOut = send(skewed.srv.URL)
	if code != 1 || out != "" || !strings.Contains(errOut, `"E_STALE"`) {
		t.Fatalf("stale: exit %d stdout %q stderr %q; want 1, empty, E_STALE", code, out, errOut)
	}
}
