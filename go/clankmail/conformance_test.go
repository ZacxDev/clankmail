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
		Domain  string
		Keys    []struct{ Name, Seed, Key string }
		Derived map[string]string
		Valid   []struct {
			Name, Signer, Token, ID, T, From string
			PayloadB64                       string `json:"payload_b64"`
		}
		Invalid []struct{ Name, Token, Error string }
		Digest  []struct {
			Name       string
			Limit      int
			PerChannel int `json:"per_channel"`
			Posts      []DigestPost
			Items      []DigestItem
			Omitted    int
		}
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if vec.Domain != Domain {
		t.Fatalf("domain %q", vec.Domain)
	}
	if len(vec.Valid) == 0 || len(vec.Invalid) == 0 || len(vec.Derived) == 0 || len(vec.Digest) == 0 {
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
			if obj.ID != v.ID || obj.Type != v.T || obj.From != v.From {
				t.Errorf("got %s %s %s", obj.ID, obj.Type, obj.From)
			}
			if want, ok := vec.Derived[v.Name+".channel_id"]; ok {
				if got := ChannelID(payload); got != want {
					t.Errorf("channel id %s != %s", got, want)
				}
			}
		})
	}
	for _, c := range vec.Digest {
		t.Run("digest/"+c.Name, func(t *testing.T) {
			items, omitted := RankDigest(c.Posts, c.Limit, c.PerChannel)
			if len(items) != len(c.Items) || omitted != c.Omitted {
				t.Fatalf("got %v omitted %d, want %v omitted %d", items, omitted, c.Items, c.Omitted)
			}
			for i := range items {
				if items[i] != c.Items[i] {
					t.Errorf("item %d: got %+v, want %+v", i, items[i], c.Items[i])
				}
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
