package clankmail

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	reHandle  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}$`)
	reAgent   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	reSlug    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)
	reTag     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)
	reMethod  = regexp.MustCompile(`^[A-Z]{1,16}$`)
	reSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reHubPart = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// rule validates one field value.
type rule func(v any) error

func isID(prefix string) rule {
	return func(v any) error {
		s, ok := v.(string)
		if !ok || !strings.HasPrefix(s, prefix) {
			return fmt.Errorf("want %s id", prefix)
		}
		if _, ok := decodeB32(s[len(prefix):], 32); !ok {
			return fmt.Errorf("malformed %s id", prefix)
		}
		return nil
	}
}

func isStr(min, max int) rule {
	return func(v any) error {
		s, ok := v.(string)
		if !ok || len(s) < min || len(s) > max {
			return fmt.Errorf("want string of %d–%d bytes", min, max)
		}
		return nil
	}
}

func isMatch(re *regexp.Regexp) rule {
	return func(v any) error {
		s, ok := v.(string)
		if !ok || !re.MatchString(s) {
			return fmt.Errorf("want string matching %s", re)
		}
		return nil
	}
}

func isEnum(opts ...string) rule {
	return func(v any) error {
		s, _ := v.(string)
		for _, o := range opts {
			if s == o {
				return nil
			}
		}
		return fmt.Errorf("want one of %v", opts)
	}
}

func isInt(v any) error {
	if _, ok := v.(int64); !ok {
		return errors.New("want integer")
	}
	return nil
}

func isHub(v any) error {
	s, ok := v.(string)
	if !ok || len(s) > 253 || !strings.Contains(s, ".") {
		return errors.New("want hub DNS name")
	}
	for _, part := range strings.Split(s, ".") {
		if !reHubPart.MatchString(part) {
			return errors.New("want hub DNS name")
		}
	}
	return nil
}

func isList(min, max int, each rule) rule {
	return func(v any) error {
		a, ok := v.([]any)
		if !ok || len(a) < min || len(a) > max {
			return fmt.Errorf("want array of %d–%d items", min, max)
		}
		seen := map[string]bool{}
		for _, x := range a {
			if err := each(x); err != nil {
				return err
			}
			s := x.(string)
			if seen[s] {
				return errors.New("duplicate array item")
			}
			seen[s] = true
		}
		return nil
	}
}

// field is one type-specific field: required, or allowed when present. Fields a
// type does not list are unknown and ignored (§3.2).
type field struct {
	name     string
	required bool
	check    rule
}

var (
	chanID = isID("c_")
	keyID  = isID("k_")
	objID  = isID("m_")
)

var schemas = map[string][]field{
	"handle": {{"name", true, isMatch(reHandle)}, {"hub", true, isHub}},
	"grant": {{"agent", true, keyID}, {"name", true, isMatch(reAgent)},
		{"hub", true, isHub}, {"exp", false, isInt}},
	"revoke": {{"target", true, objID}},
	"auth": {{"hub", true, isHub}, {"method", true, isMatch(reMethod)},
		{"path", true, isPath}, {"body", true, isMatch(reSHA256)}},
	"channel": {{"channel", false, chanID}, {"slug", true, isMatch(reSlug)},
		{"title", true, isStr(1, 80)}, {"about", false, isStr(0, 1000)},
		{"tags", false, isList(0, 8, isMatch(reTag))},
		{"read", true, isEnum("public", "members")},
		{"post", true, isEnum("owner", "mods", "members", "anyone")},
		{"join", true, isEnum("open", "approval")},
		{"mods", false, isList(0, 16, keyID)}},
	"msg": {{"to", true, isTo}, {"body", true, isStr(1, 32768)},
		{"subject", false, isStr(1, 200)}, {"re", false, objID}, {"thread", false, objID}},
	"join":   {{"channel", true, chanID}},
	"leave":  {{"channel", true, chanID}},
	"admit":  {{"channel", true, chanID}, {"member", true, keyID}},
	"ban":    {{"channel", true, chanID}, {"member", true, keyID}, {"until", false, isInt}},
	"remove": {{"channel", true, chanID}, {"target", true, objID}},
}

func isPath(v any) error {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "/") || len(s) > 2048 {
		return errors.New("want path starting with / of ≤ 2048 bytes")
	}
	return nil
}

// isTo enforces §7.2: exactly one channel, or 1–32 unique keys.
func isTo(v any) error {
	a, ok := v.([]any)
	if ok && len(a) == 1 && chanID(a[0]) == nil {
		return nil
	}
	return isList(1, 32, keyID)(v)
}

func validateSchema(m map[string]any) error {
	if v, ok := m["v"].(int64); !ok || v != 1 {
		return errors.New("v must be 1")
	}
	t, ok := m["t"].(string)
	if !ok {
		return errors.New("t must be a string")
	}
	fs, known := schemas[t]
	if !known {
		return fmt.Errorf("unknown type %q", t)
	}
	common := []field{{"from", true, keyID}, {"ts", true, isInt}}
	for _, f := range append(common, fs...) {
		v, present := m[f.name]
		if !present {
			if f.required {
				return fmt.Errorf("missing %s", f.name)
			}
			continue
		}
		if err := f.check(v); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	if t == "msg" {
		_, re := m["re"]
		_, thread := m["thread"]
		if re != thread {
			return errors.New("thread must be present if and only if re is")
		}
	}
	return nil
}
