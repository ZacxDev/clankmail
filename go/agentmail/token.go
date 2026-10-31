// Package agentmail is the Go reference implementation of the Agent Mail token
// format and verification pipeline (SPEC.md §2–§4, §6–§7).
package agentmail

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"strings"
)

const (
	// MaxToken is the §4 step-1 size limit, in bytes.
	MaxToken = 98304
	// Domain is prepended to the payload bytes before signing (§3.1).
	Domain = "agentmail/v1\n"
)

// Error codes from SPEC.md §4.
const (
	ESize      = "E_SIZE"
	EFormat    = "E_FORMAT"
	EEncoding  = "E_ENCODING"
	ESignature = "E_SIGNATURE"
	EJSON      = "E_JSON"
	ESchema    = "E_SCHEMA"
	ESigner    = "E_SIGNER"
)

// Error is a pipeline failure carrying its §4 code.
type Error struct{ Code, Detail string }

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func fail(code, detail string) *Error { return &Error{code, detail} }

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// B32 encodes bytes as lowercase unpadded base32 (§2).
func B32(b []byte) string { return strings.ToLower(b32.EncodeToString(b)) }

// B64 encodes bytes as unpadded base64url (§2).
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeB32 applies the §2 canonical decoding rule: decode, re-encode, compare.
func decodeB32(s string, n int) ([]byte, bool) {
	b, err := b32.DecodeString(strings.ToUpper(s))
	if err != nil || len(b) != n || B32(b) != s {
		return nil, false
	}
	return b, true
}

// decodeB64 applies the §2 canonical decoding rule. The re-encode comparison is
// what rejects the CR/LF characters Go's decoder would otherwise skip.
func decodeB64(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || B64(b) != s {
		return nil, false
	}
	return b, true
}

// KeyID returns the k_ id of an Ed25519 public key.
func KeyID(pub ed25519.PublicKey) string { return "k_" + B32(pub) }

// ObjectID returns the m_ id of a payload (§3.3).
func ObjectID(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "m_" + B32(sum[:])
}

// ChannelID returns the c_ id of a channel whose genesis payload is given (§7.1).
func ChannelID(genesisPayload []byte) string { return "c_" + ObjectID(genesisPayload)[2:] }

// Sign produces a token over the exact payload bytes given; nothing is re-serialised.
func Sign(priv ed25519.PrivateKey, payload []byte) string {
	msg := append([]byte(Domain), payload...)
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	return "v1." + B32(pub) + "." + B64(payload) + "." + B64(sig)
}

// Object is an authentic, schema-valid token.
type Object struct {
	ID      string
	Type    string
	From    string
	Payload []byte
	Fields  map[string]any
}

// Verify runs the SPEC.md §4 pipeline in order and stops at the first failure.
func Verify(token string) (*Object, error) {
	if len(token) > MaxToken {
		return nil, fail(ESize, "token exceeds 98304 bytes")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return nil, fail(EFormat, "want v1.<signer>.<payload>.<signature>")
	}
	pub, ok := decodeB32(parts[1], ed25519.PublicKeySize)
	if !ok {
		return nil, fail(EEncoding, "signer")
	}
	payload, ok := decodeB64(parts[2])
	if !ok {
		return nil, fail(EEncoding, "payload")
	}
	sig, ok := decodeB64(parts[3])
	if !ok || len(sig) != ed25519.SignatureSize {
		return nil, fail(EEncoding, "signature")
	}
	// Step 4 before step 5: untrusted bytes reach the parser only once signed.
	if !ed25519.Verify(pub, append([]byte(Domain), payload...), sig) {
		return nil, fail(ESignature, "signature does not verify")
	}
	fields, err := parseStrict(payload)
	if err != nil {
		return nil, fail(EJSON, err.Error())
	}
	if err := validateSchema(fields); err != nil {
		return nil, fail(ESchema, err.Error())
	}
	from := fields["from"].(string)
	if from != "k_"+parts[1] {
		return nil, fail(ESigner, "from does not match signer")
	}
	return &Object{
		ID:      ObjectID(payload),
		Type:    fields["t"].(string),
		From:    from,
		Payload: payload,
		Fields:  fields,
	}, nil
}
