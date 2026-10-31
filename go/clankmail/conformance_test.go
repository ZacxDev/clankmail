package clankmail

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestConformance runs SPEC.md §12: every valid vector verifies to its id and
// re-signs byte-for-byte; every invalid vector fails with its exact code.
func TestConformance(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Domain string
		Keys   []struct{ Name, Seed, Key string }
		Valid  []struct {
			Name, Signer, Token, ID, T string
			PayloadB64                 string `json:"payload_b64"`
		}
		Invalid []struct{ Name, Token, Error string }
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if vec.Domain != Domain {
		t.Fatalf("domain %q", vec.Domain)
	}
	if len(vec.Valid) == 0 || len(vec.Invalid) == 0 {
		t.Fatal("no vectors loaded")
	}
	priv := map[string]ed25519.PrivateKey{}
	for _, k := range vec.Keys {
		seed, _ := hex.DecodeString(k.Seed)
		priv[k.Name] = ed25519.NewKeyFromSeed(seed)
		if got := KeyID(priv[k.Name].Public().(ed25519.PublicKey)); got != k.Key {
			t.Errorf("key %s: %s != %s", k.Name, got, k.Key)
		}
	}
	for _, v := range vec.Valid {
		t.Run("valid/"+v.Name, func(t *testing.T) {
			payload, _ := base64.RawURLEncoding.DecodeString(v.PayloadB64)
			if got := Sign(priv[v.Signer], payload); got != v.Token {
				t.Error("re-signed token differs")
			}
			obj, err := Verify(v.Token)
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if obj.ID != v.ID || obj.Type != v.T {
				t.Errorf("got %s %s", obj.ID, obj.Type)
			}
		})
	}
	for _, v := range vec.Invalid {
		t.Run("invalid/"+v.Name, func(t *testing.T) {
			_, err := Verify(v.Token)
			e, ok := err.(*Error)
			if !ok || e.Code != v.Error {
				t.Errorf("want %s, got %v", v.Error, err)
			}
		})
	}
}
