package qaauthmw

import (
	"errors"
	"net"
	"net/http"
	"strings"
)

// HostPolicy selects which host is treated as canonical host for signing/verification.
type HostPolicy struct {
	// If empty, forwarded headers are NEVER trusted.
	TrustedProxyCIDRs []string

	// If true, also parse RFC 7239 Forwarded header (Forwarded: host=...).
	TrustForwardedHeader bool
}

func (p HostPolicy) CanonicalHost(r *http.Request) (string, error) {
	// Default: use r.Host (what the server believes the host is)
	host := strings.TrimSpace(r.Host)

	// If we can trust forwarded headers, prefer them
	if p.isFromTrustedProxy(r) {
		if p.TrustForwardedHeader {
			if h := forwardedHost(r.Header.Get("Forwarded")); h != "" {
				host = h
			}
		}
		if xfh := firstCSV(r.Header.Get("X-Forwarded-Host")); xfh != "" {
			host = xfh
		}
	}

	host = NormalizeHost(host)
	if host == "" {
		return "", errors.New("empty host")
	}
	return host, nil
}

// NormalizeHost makes host deterministic but DOES NOT guess ports.
// Recommendation: keep port if present; strip only junk.
func NormalizeHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}

	// X-Forwarded-Host can be "a,b" — we handle that before, but safe anyway:
	h = firstCSV(h)

	// strip any whitespace
	h = strings.TrimSpace(h)

	// strip trailing dot (rare, but can happen)
	h = strings.TrimSuffix(h, ".")

	// lowercase for stability
	h = strings.ToLower(h)

	return h
}

func firstCSV(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, ','); i >= 0 {
		return strings.TrimSpace(v[:i])
	}
	return v
}

// Parse Forwarded: host=example.com:443;proto=https
func forwardedHost(forwarded string) string {
	// Minimal safe parse: take first "host=" token in the first forwarded-entry.
	// Forwarded can be comma-separated list of entries.
	fwd := firstCSV(forwarded)
	fwd = strings.TrimSpace(fwd)
	if fwd == "" {
		return ""
	}

	parts := strings.Split(fwd, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) < 5 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(p), "host=") {
			val := strings.TrimSpace(p[5:])
			val = strings.Trim(val, `"`)
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func (p HostPolicy) isFromTrustedProxy(r *http.Request) bool {
	if len(p.TrustedProxyCIDRs) == 0 {
		return false
	}

	remoteIP := clientRemoteIP(r.RemoteAddr)
	if remoteIP == nil {
		return false
	}

	for _, cidr := range p.TrustedProxyCIDRs {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || ipnet == nil {
			continue
		}
		if ipnet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func clientRemoteIP(remoteAddr string) net.IP {
	// remoteAddr usually "IP:port"
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		// maybe it's already just an IP
		return net.ParseIP(strings.TrimSpace(remoteAddr))
	}
	return net.ParseIP(host)
}
