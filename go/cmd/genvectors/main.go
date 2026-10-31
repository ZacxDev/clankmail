// Command genvectors writes vectors/vectors.json, the SPEC.md §12 conformance
// vectors, from fixed seeds. Payloads are written as literal bytes so that the
// vectors pin exact bytes, never a Go serialisation. It refuses to write a file
// in which any vector disagrees with the reference Verify.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	am "github.com/ZacxDev/clankmail/go/clankmail"
)

const ts = "1767225600000" // 2026-01-01T00:00:00Z

type key struct {
	Name string `json:"name"`
	Seed string `json:"seed"`
	ID   string `json:"key"`
	priv ed25519.PrivateKey
}

type valid struct {
	Name       string `json:"name"`
	Signer     string `json:"signer"`
	Payload    string `json:"payload"`
	PayloadB64 string `json:"payload_b64"`
	Token      string `json:"token"`
	ID         string `json:"id"`
	T          string `json:"t"`
}

type invalid struct {
	Name  string `json:"name"`
	Why   string `json:"why"`
	Token string `json:"token"`
	Error string `json:"error"`
}

type file struct {
	Spec    string            `json:"spec"`
	Domain  string            `json:"domain"`
	Keys    []*key            `json:"keys"`
	Derived map[string]string `json:"derived"`
	Valid   []valid           `json:"valid"`
	Invalid []invalid         `json:"invalid"`
}

var keys = map[string]*key{}

func mkKey(name string) *key {
	seed := sha256.Sum256([]byte("clankmail-vectors/" + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	k := &key{Name: name, Seed: hex.EncodeToString(seed[:]),
		ID: am.KeyID(priv.Public().(ed25519.PublicKey)), priv: priv}
	keys[name] = k
	return k
}

func sign(k *key, payload string) string { return am.Sign(k.priv, []byte(payload)) }

func parts(tok string) []string { return strings.Split(tok, ".") }

func join(p []string) string { return strings.Join(p, ".") }

func main() {
	out := file{Spec: "clankmail/v1", Domain: am.Domain, Derived: map[string]string{}}
	alice, scout, bob, carol := mkKey("alice"), mkKey("scout"), mkKey("bob"), mkKey("carol")
	out.Keys = []*key{alice, scout, bob, carol}

	addValid := func(name string, k *key, payload string) string {
		tok := sign(k, payload)
		id := am.ObjectID([]byte(payload))
		var head struct{ T string }
		_ = json.Unmarshal([]byte(payload), &head)
		out.Valid = append(out.Valid, valid{name, k.Name, payload, am.B64([]byte(payload)), tok, id, head.T})
		return id
	}
	addInvalid := func(name, why, tok, code string) {
		out.Invalid = append(out.Invalid, invalid{name, why, tok, code})
	}
	hdr := func(t string, k *key) string {
		return fmt.Sprintf(`{"v":1,"t":%q,"from":%q,"ts":%s`, t, k.ID, ts)
	}

	// ---- valid: identity
	addValid("handle", alice, hdr("handle", alice)+`,"name":"alice","hub":"hub.example"}`)
	grant := addValid("grant", alice, hdr("grant", alice)+fmt.Sprintf(`,"agent":%q,"name":"scout","hub":"hub.example"}`, scout.ID))
	addValid("grant-with-exp", alice, hdr("grant", alice)+fmt.Sprintf(`,"agent":%q,"name":"scout-2","hub":"hub.example","exp":1798761600000}`, carol.ID))
	addValid("revoke", alice, hdr("revoke", alice)+fmt.Sprintf(`,"target":%q}`, grant))
	emptySHA := hex.EncodeToString(func() []byte { s := sha256.Sum256(nil); return s[:] }())
	addValid("auth", scout, hdr("auth", scout)+fmt.Sprintf(`,"hub":"hub.example","method":"GET","path":"/v1/inbox?queue=inbox","body":%q}`, emptySHA))

	// ---- valid: channels
	genesis := hdr("channel", alice) + fmt.Sprintf(`,"slug":"llm-evals","title":"LLM evals","about":"Benchmarks and eval harnesses.","tags":["llm","evals"],"read":"public","post":"members","join":"open","mods":[%q]}`, carol.ID)
	addValid("channel-genesis", alice, genesis)
	ch := am.ChannelID([]byte(genesis))
	out.Derived["channel-genesis.channel_id"] = ch
	addValid("channel-minimal", bob, hdr("channel", bob)+`,"slug":"bob-notes","title":"B","read":"members","post":"owner","join":"approval"}`)
	addValid("channel-update", alice, fmt.Sprintf(`{"v":1,"t":"channel","from":%q,"ts":1767225660000,"channel":%q,"slug":"llm-evals","title":"LLM evals (weekly)","read":"public","post":"members","join":"open"}`, alice.ID, ch))
	addValid("join", bob, hdr("join", bob)+fmt.Sprintf(`,"channel":%q}`, ch))
	addValid("leave", bob, hdr("leave", bob)+fmt.Sprintf(`,"channel":%q}`, ch))
	addValid("admit", carol, hdr("admit", carol)+fmt.Sprintf(`,"channel":%q,"member":%q}`, ch, bob.ID))
	addValid("ban", alice, hdr("ban", alice)+fmt.Sprintf(`,"channel":%q,"member":%q,"until":1767312000000}`, ch, bob.ID))

	// ---- valid: messages
	dm := addValid("msg-direct", scout, hdr("msg", scout)+fmt.Sprintf(`,"to":[%q],"subject":"hello","body":"Hi Bob, scout here."}`, bob.ID))
	addValid("msg-reply", bob, hdr("msg", bob)+fmt.Sprintf(`,"to":[%q],"body":"Hi scout.","re":%q,"thread":%q}`, scout.ID, dm, dm))
	post := addValid("msg-channel", bob, hdr("msg", bob)+fmt.Sprintf(`,"to":[%q],"body":"First post."}`, ch))
	addValid("remove", carol, hdr("remove", carol)+fmt.Sprintf(`,"channel":%q,"target":%q}`, ch, post))
	addValid("msg-multi-recipient", scout, hdr("msg", scout)+fmt.Sprintf(`,"to":[%q,%q],"body":"to both"}`, bob.ID, carol.ID))
	// No canonicalisation: reordered keys + whitespace + an unknown field are valid as sent.
	addValid("msg-no-canonical-form", bob, fmt.Sprintf("{\n  \"body\": \"order and spacing are the sender's\",\n  \"x-client\": {\"name\": \"demo\"},\n  \"to\": [%q], \"ts\": %s, \"from\": %q, \"t\": \"msg\", \"v\": 1\n}\n", alice.ID, ts, bob.ID))
	addValid("msg-unicode-escapes", bob, hdr("msg", bob)+fmt.Sprintf(`,"to":[%q],"body":"café 😀 — ✓"}`, alice.ID))
	addValid("msg-body-max", bob, hdr("msg", bob)+fmt.Sprintf(`,"to":[%q],"body":"%s"}`, alice.ID, strings.Repeat("a", 32768)))
	addValid("msg-ts-max", bob, fmt.Sprintf(`{"v":1,"t":"msg","from":%q,"ts":9007199254740991,"to":[%q],"body":"x"}`, bob.ID, alice.ID))

	base := sign(bob, hdr("msg", bob)+fmt.Sprintf(`,"to":[%q],"body":"base"}`, alice.ID))

	// ---- E_SIZE / E_FORMAT
	addInvalid("size-over", "98305 bytes: rejected before anything else", "v1."+strings.Repeat("a", am.MaxToken-2), am.ESize)
	addInvalid("size-at-limit-is-not-size", "exactly 98304 bytes passes step 1 and fails step 2", "v1."+strings.Repeat("a", am.MaxToken-3), am.EFormat)
	addInvalid("format-empty", "empty string", "", am.EFormat)
	addInvalid("format-three-fields", "missing signature field", join(parts(base)[:3]), am.EFormat)
	addInvalid("format-five-fields", "extra field", base+".x", am.EFormat)
	addInvalid("format-version", "v2 prefix", "v2"+base[2:], am.EFormat)

	// ---- E_ENCODING
	p := parts(base)
	addInvalid("enc-signer-uppercase", "base32 must be lowercase", join([]string{p[0], strings.ToUpper(p[1]), p[2], p[3]}), am.EEncoding)
	addInvalid("enc-signer-short", "51 base32 chars", join([]string{p[0], p[1][:51], p[2], p[3]}), am.EEncoding)
	addInvalid("enc-signer-trailing-bits", "non-zero unused bits in the last base32 char", join([]string{p[0], bumpLast(p[1], "abcdefghijklmnopqrstuvwxyz234567"), p[2], p[3]}), am.EEncoding)
	addInvalid("enc-payload-padded", "base64url padding is not allowed", join([]string{p[0], p[1], p[2] + "=", p[3]}), am.EEncoding)
	addInvalid("enc-payload-newline", "a newline inside base64url (some decoders skip it)", join([]string{p[0], p[1], p[2][:10] + "\n" + p[2][10:], p[3]}), am.EEncoding)
	addInvalid("enc-payload-std-alphabet", "'+' from the standard alphabet", join([]string{p[0], p[1], "+" + p[2][1:], p[3]}), am.EEncoding)
	// A payload whose length is not a multiple of 3 has unused bits in its last char.
	odd := hdr("msg", bob) + fmt.Sprintf(`,"to":[%q],"body":"odd"}`, alice.ID)
	for len(odd)%3 == 0 {
		odd += " "
	}
	po := parts(sign(bob, odd))
	b64a := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	addInvalid("enc-payload-trailing-bits", "non-zero unused bits in the last base64url char", join([]string{po[0], po[1], bumpLast(po[2], b64a), po[3]}), am.EEncoding)
	addInvalid("enc-signature-short", "63-byte signature", join([]string{p[0], p[1], p[2], am.B64(mustB64(p[3])[:63])}), am.EEncoding)

	// ---- E_SIGNATURE
	sig := mustB64(p[3])
	flip := append([]byte{}, sig...)
	flip[0] ^= 1
	addInvalid("sig-bit-flip", "one bit of R flipped", join([]string{p[0], p[1], p[2], am.B64(flip)}), am.ESignature)
	other := parts(sign(alice, string(mustB64(p[2]))))
	addInvalid("sig-wrong-key", "signed by alice, signer field says bob", join([]string{p[0], p[1], p[2], other[3]}), am.ESignature)
	addInvalid("sig-no-domain-prefix", "signature over the bare payload, without \"clankmail/v1\\n\"", join([]string{p[0], p[1], p[2], am.B64(ed25519.Sign(bob.priv, mustB64(p[2])))}), am.ESignature)
	addInvalid("sig-s-not-reduced", "S replaced by S+L: same point equation, non-canonical scalar", join([]string{p[0], p[1], p[2], am.B64(malleate(sig))}), am.ESignature)
	badJSON := am.B64([]byte(`{"v":1,`))
	addInvalid("sig-before-json", "bad signature AND bad JSON: the signature is checked first", join([]string{p[0], p[1], badJSON, p[3]}), am.ESignature)

	// ---- E_JSON (all correctly signed by bob)
	j := func(name, why, payload string) { addInvalid(name, why, sign(bob, payload), am.EJSON) }
	to := fmt.Sprintf(`"to":[%q]`, alice.ID)
	h := hdr("msg", bob)
	j("json-invalid-utf8", "byte 0xff in a string", h+","+to+`,"body":"`+"\xff"+`"}`)
	j("json-bom", "UTF-8 byte-order mark before the object", "\xef\xbb\xbf"+h+","+to+`,"body":"x"}`)
	j("json-trailing-data", "a second value after the object", h+","+to+`,"body":"x"}{}`)
	j("json-top-level-array", "payload is an array", `[1]`)
	j("json-duplicate-key", "\"body\" twice: parsers disagree on which wins", h+","+to+`,"body":"shown to hub","body":"shown to client"}`)
	j("json-duplicate-key-nested", "duplicate inside an ignored unknown field", h+","+to+`,"body":"x","x":{"a":1,"a":2}}`)
	j("json-float", "ts written with a fraction", fmt.Sprintf(`{"v":1,"t":"msg","from":%q,"ts":1767225600000.0,%s,"body":"x"}`, bob.ID, to))
	j("json-exponent", "ts written with an exponent", fmt.Sprintf(`{"v":1,"t":"msg","from":%q,"ts":1e12,%s,"body":"x"}`, bob.ID, to))
	j("json-negative", "negative integer", h+","+to+`,"body":"x","x":-1}`)
	j("json-leading-zero", "leading zero", h+","+to+`,"body":"x","x":01}`)
	j("json-int-too-big", "2^53 is out of range", fmt.Sprintf(`{"v":1,"t":"msg","from":%q,"ts":9007199254740992,%s,"body":"x"}`, bob.ID, to))
	j("json-lone-high-surrogate", "\\ud800 not followed by a low surrogate", h+","+to+`,"body":"\ud800x"}`)
	j("json-lone-low-surrogate", "\\udc00 on its own", h+","+to+`,"body":"\udc00"}`)
	j("json-nan", "NaN is not JSON", h+","+to+`,"body":"x","x":NaN}`)
	j("json-depth-17", "17 levels of nesting", h+","+to+`,"body":"x","x":`+strings.Repeat("[", 16)+strings.Repeat("]", 16)+`}`)
	addValid("json-depth-16", bob, h+","+to+`,"body":"x","x":`+strings.Repeat("[", 15)+strings.Repeat("]", 15)+`}`)

	// ---- E_SCHEMA (all correctly signed by bob)
	s := func(name, why, payload string) { addInvalid(name, why, sign(bob, payload), am.ESchema) }
	s("schema-v2", "v must be 1", fmt.Sprintf(`{"v":2,"t":"msg","from":%q,"ts":%s,%s,"body":"x"}`, bob.ID, ts, to))
	s("schema-unknown-type", "t is not a v1 type", hdr("poke", bob)+","+to+`}`)
	s("schema-missing-ts", "ts absent", fmt.Sprintf(`{"v":1,"t":"msg","from":%q,%s,"body":"x"}`, bob.ID, to))
	s("schema-ts-string", "ts as a string", fmt.Sprintf(`{"v":1,"t":"msg","from":%q,"ts":"1767225600000",%s,"body":"x"}`, bob.ID, to))
	s("schema-from-malformed", "from is not a key id", fmt.Sprintf(`{"v":1,"t":"msg","from":"k_bob","ts":%s,%s,"body":"x"}`, ts, to))
	s("schema-to-empty", "no recipients", h+`,"to":[],"body":"x"}`)
	s("schema-to-mixed", "a channel and a key together", h+fmt.Sprintf(`,"to":[%q,%q],"body":"x"}`, ch, alice.ID))
	s("schema-to-two-channels", "two channels", h+fmt.Sprintf(`,"to":[%q,%q],"body":"x"}`, ch, am.ChannelID([]byte("other"))))
	s("schema-to-duplicate", "same key twice", h+fmt.Sprintf(`,"to":[%q,%q],"body":"x"}`, alice.ID, alice.ID))
	s("schema-to-handle", "handles are not addresses in signed bytes", h+`,"to":["@alice"],"body":"x"}`)
	s("schema-body-empty", "body of 0 bytes", h+","+to+`,"body":""}`)
	s("schema-body-over", "body of 32769 bytes", h+","+to+`,"body":"`+strings.Repeat("a", 32769)+`"}`)
	s("schema-subject-over", "subject of 201 bytes", h+","+to+`,"body":"x","subject":"`+strings.Repeat("é", 100)+`a"}`)
	s("schema-re-without-thread", "re requires thread", h+","+to+fmt.Sprintf(`,"body":"x","re":%q}`, dm))
	s("schema-thread-without-re", "thread requires re", h+","+to+fmt.Sprintf(`,"body":"x","thread":%q}`, dm))
	s("schema-channel-bad-slug", "uppercase slug", hdr("channel", bob)+`,"slug":"Bob","title":"B","read":"public","post":"owner","join":"open"}`)
	s("schema-channel-bad-read", "unknown read policy", hdr("channel", bob)+`,"slug":"bob","title":"B","read":"secret","post":"owner","join":"open"}`)
	s("schema-channel-nine-tags", "more than 8 tags", hdr("channel", bob)+`,"slug":"bob","title":"B","tags":["a","b","c","d","e","f","g","h","i"],"read":"public","post":"owner","join":"open"}`)
	s("schema-hub-with-port", "hub names carry no port", hdr("handle", bob)+`,"name":"bob","hub":"hub.example:443"}`)
	s("schema-auth-bad-body", "body hash not lowercase hex", hdr("auth", bob)+`,"hub":"hub.example","method":"GET","path":"/v1/inbox","body":"`+strings.ToUpper(emptySHA)+`"}`)

	// ---- E_SIGNER
	addInvalid("signer-mismatch", "valid object claiming from=bob, signed by alice", sign(alice, h+","+to+`,"body":"x"}`), am.ESigner)

	// Self-check: every vector must agree with the reference pipeline.
	for _, v := range out.Valid {
		obj, err := am.Verify(v.Token)
		if err != nil || obj.ID != v.ID {
			die("valid vector %s: %v", v.Name, err)
		}
	}
	for _, v := range out.Invalid {
		_, err := am.Verify(v.Token)
		e, ok := err.(*am.Error)
		if !ok || e.Code != v.Error {
			die("invalid vector %s: want %s, got %v", v.Name, v.Error, err)
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(os.Args[1], append(b, '\n'), 0o644); err != nil {
		die("%v", err)
	}
	fmt.Printf("wrote %d valid + %d invalid vectors\n", len(out.Valid), len(out.Invalid))
}

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func mustB64(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		die("%v", err)
	}
	return b
}

// bumpLast moves the final character one step along the alphabet, which flips the
// lowest bit of its value — always an unused padding bit for these lengths.
func bumpLast(s, alphabet string) string {
	i := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[i^1])
}

// malleate returns R || (S + L), little-endian, the classic non-canonical scalar.
func malleate(sig []byte) []byte {
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	le := func(b []byte) *big.Int {
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return new(big.Int).SetBytes(r)
	}
	S := new(big.Int).Add(le(sig[32:]), L)
	be := S.FillBytes(make([]byte, 32))
	out := append([]byte{}, sig[:32]...)
	for i := 31; i >= 0; i-- {
		out = append(out, be[i])
	}
	return out
}
