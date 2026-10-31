package clankmail

import (
	"errors"
	"strconv"
	"unicode/utf8"
)

// maxSafeInt is 2^53 − 1, the largest integer every JSON implementation agrees on.
const maxSafeInt = 1<<53 - 1

const maxDepth = 16

// parseStrict parses a payload under the SPEC.md §3.2 rules. It is hand-written
// because encoding/json accepts duplicate keys, silently replaces invalid UTF-8
// and lone surrogates with U+FFFD, and allows floats — each a parser differential.
// Integers come back as int64, objects as map[string]any, arrays as []any.
func parseStrict(b []byte) (map[string]any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("invalid UTF-8")
	}
	p := &parser{b: b}
	p.ws()
	if p.i >= len(b) || b[p.i] != '{' {
		return nil, errors.New("payload is not a JSON object")
	}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(b) {
		return nil, errors.New("trailing data after object")
	}
	return v.(map[string]any), nil
}

type parser struct {
	b []byte
	i int
}

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) lit(s string, v any) (any, error) {
	if len(p.b)-p.i < len(s) || string(p.b[p.i:p.i+len(s)]) != s {
		return nil, errors.New("invalid literal")
	}
	p.i += len(s)
	return v, nil
}

func (p *parser) value(depth int) (any, error) {
	if p.i >= len(p.b) {
		return nil, errors.New("unexpected end")
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == 't':
		return p.lit("true", true)
	case c == 'f':
		return p.lit("false", false)
	case c == 'n':
		return p.lit("null", nil)
	case c >= '0' && c <= '9':
		return p.integer()
	default:
		return nil, errors.New("unexpected character (numbers must be non-negative integers)")
	}
}

func (p *parser) object(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("nesting deeper than 16")
	}
	p.i++ // {
	m := map[string]any{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return m, nil
	}
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, errors.New("expected object key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, errors.New("duplicate key " + strconv.Quote(k))
		}
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, errors.New("expected ':'")
		}
		p.i++
		p.ws()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		m[k] = v
		p.ws()
		if p.i >= len(p.b) {
			return nil, errors.New("unexpected end in object")
		}
		if p.b[p.i] == '}' {
			p.i++
			return m, nil
		}
		if p.b[p.i] != ',' {
			return nil, errors.New("expected ',' or '}'")
		}
		p.i++
	}
}

func (p *parser) array(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("nesting deeper than 16")
	}
	p.i++ // [
	a := []any{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return a, nil
	}
	for {
		p.ws()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.ws()
		if p.i >= len(p.b) {
			return nil, errors.New("unexpected end in array")
		}
		if p.b[p.i] == ']' {
			p.i++
			return a, nil
		}
		if p.b[p.i] != ',' {
			return nil, errors.New("expected ',' or ']'")
		}
		p.i++
	}
}

func (p *parser) integer() (any, error) {
	start := p.i
	if p.b[p.i] == '0' {
		p.i++
	} else {
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.b) {
		switch p.b[p.i] {
		case '.', 'e', 'E':
			return nil, errors.New("numbers must be integers")
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return nil, errors.New("leading zero")
		}
	}
	n, err := strconv.ParseUint(string(p.b[start:p.i]), 10, 64)
	if err != nil || n > maxSafeInt {
		return nil, errors.New("integer out of range [0, 2^53-1]")
	}
	return int64(n), nil
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(b[:4]), 16, 32)
	return rune(n), err == nil
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var out []byte
	for {
		if p.i >= len(p.b) {
			return "", errors.New("unterminated string")
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return "", errors.New("control character in string")
		case c != '\\':
			out = append(out, c)
			p.i++
			continue
		}
		p.i++ // backslash
		if p.i >= len(p.b) {
			return "", errors.New("unterminated escape")
		}
		e := p.b[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(p.b[p.i:])
			if !ok {
				return "", errors.New("bad \\u escape")
			}
			p.i += 4
			switch {
			case r >= 0xDC00 && r <= 0xDFFF:
				return "", errors.New("lone low surrogate")
			case r >= 0xD800 && r <= 0xDBFF:
				if len(p.b)-p.i < 6 || p.b[p.i] != '\\' || p.b[p.i+1] != 'u' {
					return "", errors.New("lone high surrogate")
				}
				lo, ok := hex4(p.b[p.i+2:])
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return "", errors.New("lone high surrogate")
				}
				p.i += 6
				r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
			}
			out = utf8.AppendRune(out, r)
		default:
			return "", errors.New("invalid escape")
		}
	}
}
