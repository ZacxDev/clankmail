// Command genvectors writes vectors/vectors.json, the SPEC.md §12 conformance
// vectors, from fixed seeds. Payloads are written as literal bytes so that the
// vectors pin exact bytes, never a Go serialisation. It refuses to write a file
// in which any vector disagrees with the reference Verify.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
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
	From       string `json:"from"`
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
		var head struct{ T, From string }
		_ = json.Unmarshal([]byte(payload), &head)
		out.Valid = append(out.Valid, valid{name, k.Name, payload, am.B64([]byte(payload)), tok, id, head.T, head.From})
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
	addValid("enroll", scout, hdr("enroll", scout)+fmt.Sprintf(`,"grant":%q}`, grant))
	addValid("grant-with-exp", alice, hdr("grant", alice)+fmt.Sprintf(`,"agent":%q,"name":"scout-2","hub":"hub.example","exp":1798761600000}`, carol.ID))
	addValid("revoke", alice, hdr("revoke", alice)+fmt.Sprintf(`,"target":%q}`, grant))
	emptySHA := hex.EncodeToString(func() []byte { s := sha256.Sum256(nil); return s[:] }())
	addValid("auth", scout, hdr("auth", scout)+fmt.Sprintf(`,"hub":"hub.example","method":"GET","path":"/v1/inbox?queue=inbox","body":%q}`, emptySHA))
	addValid("auth-with-nonce", scout, hdr("auth", scout)+fmt.Sprintf(`,"hub":"hub.example","method":"POST","path":"/%s","body":%q,"n":"r4nd0m"}`, strings.Repeat("p", 2047), emptySHA))

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
	addValid("msg-reply", bob, hdr("msg", bob)+fmt.Sprintf(`,"to":[%q],"body":"Hi scout.","re":%q}`, scout.ID, dm))
	addValid("msg-thread-field-is-unknown", bob, hdr("msg", bob)+fmt.Sprintf(`,"to":[%q],"body":"x","thread":"not an id, and ignored"}`, scout.ID))
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
	s("schema-re-not-id", "re is not an m_ id", h+","+to+`,"body":"x","re":"m_x"}`)
	s("schema-channel-bad-slug", "uppercase slug", hdr("channel", bob)+`,"slug":"Bob","title":"B","read":"public","post":"owner","join":"open"}`)
	s("schema-channel-bad-read", "unknown read policy", hdr("channel", bob)+`,"slug":"bob","title":"B","read":"secret","post":"owner","join":"open"}`)
	s("schema-channel-nine-tags", "more than 8 tags", hdr("channel", bob)+`,"slug":"bob","title":"B","tags":["a","b","c","d","e","f","g","h","i"],"read":"public","post":"owner","join":"open"}`)
	s("schema-hub-with-port", "hub names carry no port", hdr("handle", bob)+`,"name":"bob","hub":"hub.example:443"}`)
	s("schema-auth-bad-body", "body hash not lowercase hex", hdr("auth", bob)+`,"hub":"hub.example","method":"GET","path":"/v1/inbox","body":"`+strings.ToUpper(emptySHA)+`"}`)

	// Field rules, pinned from both sides: one byte/item over each limit is rejected
	// here, and the valid vectors carry the limit itself.
	s("schema-grant-agent-not-key", "grant.agent is not a key id", hdr("grant", bob)+`,"agent":"bob","name":"x","hub":"hub.example"}`)
	s("schema-enroll-grant-not-id", "enroll.grant is not an m_ id", hdr("enroll", bob)+`,"grant":"g"}`)
	s("schema-revoke-target-not-id", "revoke.target is not an m_ id", hdr("revoke", bob)+`,"target":"x"}`)
	s("schema-title-over", "title of 81 bytes", hdr("channel", bob)+`,"slug":"bob","title":"`+strings.Repeat("t", 81)+`","read":"public","post":"owner","join":"open"}`)
	s("schema-mods-over", "17 mods", hdr("channel", bob)+`,"slug":"bob","title":"B","read":"public","post":"owner","join":"open","mods":[`+modList(17)+`]}`)
	s("schema-hub-over", "hub name of 254 bytes", hdr("handle", bob)+`,"name":"bob","hub":"`+hubName(62)+`"}`)
	s("schema-auth-path-over", "path of 2049 bytes", hdr("auth", bob)+fmt.Sprintf(`,"hub":"hub.example","method":"GET","path":"/%s","body":%q}`, strings.Repeat("p", 2048), emptySHA))
	s("schema-auth-method-lowercase", "method must be uppercase", hdr("auth", bob)+fmt.Sprintf(`,"hub":"hub.example","method":"get","path":"/v1/inbox","body":%q}`, emptySHA))
	s("schema-auth-nonce-empty", "nonce of 0 bytes", hdr("auth", bob)+fmt.Sprintf(`,"hub":"hub.example","method":"GET","path":"/","body":%q,"n":""}`, emptySHA))
	addValid("auth-nonce-at-limit", bob, hdr("auth", bob)+fmt.Sprintf(`,"hub":"hub.example","method":"GET","path":"/","body":%q,"n":"%s"}`, emptySHA, strings.Repeat("n", 64)))
	s("schema-auth-nonce-over", "nonce of 65 bytes", hdr("auth", bob)+fmt.Sprintf(`,"hub":"hub.example","method":"GET","path":"/","body":%q,"n":"%s"}`, emptySHA, strings.Repeat("n", 65)))
	addValid("channel-at-limits", bob, hdr("channel", bob)+`,"slug":"bob-limits","title":"`+strings.Repeat("t", 80)+`","read":"public","post":"owner","join":"open","mods":[`+modList(16)+`]}`)
	addValid("handle-hub-at-limit", bob, hdr("handle", bob)+`,"name":"bob","hub":"`+hubName(61)+`"}`)

	// ---- weak signer keys (§2 key validity rule). Each token carries R = identity,
	// S = 0, which plain Ed25519 verification ACCEPTS whenever [k]A is the identity,
	// so without the rule every one of these would verify.
	identity := make([]byte, 32)
	identity[0] = 1
	pPlus1 := leInt(new(big.Int).Add(fieldP(), big.NewInt(1)))
	order2 := leInt(new(big.Int).Sub(fieldP(), big.NewInt(1)))
	order4 := make([]byte, 32)
	order8, _ := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	order8b, _ := hex.DecodeString("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	order8Neg := append([]byte{}, order8...)
	order8Neg[31] |= 0x80
	for _, w := range []struct {
		name, why string
		pub       []byte
		order     int64
	}{
		{"key-identity", "signer is the identity point: anyone can sign as it", identity, 1},
		{"key-non-canonical", "signer encodes y = p+1, a second encoding of the identity", pPlus1, 1},
		{"key-order-2", "signer has order 2 (y = p-1)", order2, 2},
		{"key-order-4", "signer has order 4 (y = 0)", order4, 4},
		{"key-order-8", "signer has order 8", order8, 8},
		{"key-order-8b", "signer has order 8 (the other y value)", order8b, 8},
		{"key-order-8-negated", "signer has order 8, x sign bit set", order8Neg, 8},
	} {
		addInvalid(w.name, w.why, forgeSmallOrder(w.pub, w.order), am.EEncoding)
	}

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

func fieldP() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
}

func leInt(n *big.Int) []byte {
	be := n.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[31-i] = be[i]
	}
	return out
}

// forgeSmallOrder builds a token for a small-order key A with R = identity, S = 0.
// Plain verification computes [S]B − [k]A = −[k]A and compares it to R, so it
// passes exactly when k ≡ 0 (mod order(A)); the payload is varied until it does.
func forgeSmallOrder(pub []byte, order int64) string {
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	R := make([]byte, 32)
	R[0] = 1
	sig := append(append([]byte{}, R...), make([]byte, 32)...)
	from := am.KeyID(pub)
	for i := 0; ; i++ {
		payload := fmt.Sprintf(`{"v":1,"t":"handle","from":%q,"ts":%s,"name":"weak%d","hub":"hub.example"}`, from, ts, i)
		h := sha512.Sum512(append(append(append([]byte{}, R...), pub...), append([]byte(am.Domain), payload...)...))
		rev := make([]byte, 64)
		for j := range h {
			rev[63-j] = h[j]
		}
		k := new(big.Int).Mod(new(big.Int).SetBytes(rev), L)
		if new(big.Int).Mod(k, big.NewInt(order)).Sign() == 0 {
			return "v1." + am.B32(pub) + "." + am.B64([]byte(payload)) + "." + am.B64(sig)
		}
	}
}

func modList(n int) string {
	ids := make([]string, n)
	for i := range ids {
		seed := sha256.Sum256([]byte(fmt.Sprintf("clankmail-vectors/mod-%d", i)))
		ids[i] = fmt.Sprintf("%q", am.KeyID(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)))
	}
	return strings.Join(ids, ",")
}

// hubName returns a valid DNS name of 3×63-byte labels plus one of lastLen bytes.
func hubName(lastLen int) string {
	l := strings.Repeat("a", 63)
	return l + "." + l + "." + l + "." + strings.Repeat("b", lastLen)
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
