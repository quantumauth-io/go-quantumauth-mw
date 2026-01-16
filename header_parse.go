package qaauthmw

import (
	"fmt"
	"strings"
)

type QAHeaderFields struct {
	SigTPM string
	SigPQ  string
	// Future: challenge, kid, etc.
	Extra map[string]string
}

// ParseAuthorizationQuantumAuth parses:
//
//	Authorization: QuantumAuth sig_tpm="...", sig_pq="..."
func ParseAuthorizationQuantumAuth(auth string) (*QAHeaderFields, error) {
	const prefix = "QuantumAuth "
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("%w: invalid scheme", ErrBadRequest)
	}

	rest := strings.TrimSpace(auth[len(prefix):])
	if rest == "" {
		return nil, fmt.Errorf("%w: empty auth params", ErrBadRequest)
	}

	parts := strings.Split(rest, ",")
	seen := map[string]struct{}{}
	extra := make(map[string]string, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("%w: invalid param %q", ErrBadRequest, p)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if key == "" {
			return nil, fmt.Errorf("%w: empty key", ErrBadRequest)
		}
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrBadRequest, key)
		}
		seen[key] = struct{}{}

		// accept quoted or unquoted; strip one layer of quotes if present
		val = strings.Trim(val, `"`)
		if val == "" {
			return nil, fmt.Errorf("%w: empty value for %q", ErrBadRequest, key)
		}
		extra[key] = val
	}

	out := &QAHeaderFields{
		SigTPM: extra["sig_tpm"],
		SigPQ:  extra["sig_pq"],
		Extra:  extra,
	}

	if out.SigTPM == "" || out.SigPQ == "" {
		return nil, fmt.Errorf("%w: missing sig_tpm or sig_pq", ErrBadRequest)
	}
	return out, nil
}
