package qaauthmw

import (
	"net/http/httptest"
	"testing"
)

func TestHostPolicy_TrustForwardedHost_FromTrustedProxy(t *testing.T) {
	hp := HostPolicy{
		TrustedProxyCIDRs:    []string{"10.0.0.0/8"},
		TrustForwardedHeader: true,
	}

	req := httptest.NewRequest("GET", "http://internal/private", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("Forwarded", `host=api.websitea.com`)
	req.Host = "internal"

	host, err := hp.CanonicalHost(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if host != "api.websitea.com" {
		t.Fatalf("expected forwarded host, got %q", host)
	}
}

func TestHostPolicy_IgnoreForwardedHost_FromUntrustedProxy(t *testing.T) {
	hp := HostPolicy{
		TrustedProxyCIDRs:    []string{"10.0.0.0/8"},
		TrustForwardedHeader: true,
	}

	req := httptest.NewRequest("GET", "http://internal/private", nil)
	req.RemoteAddr = "192.168.1.10:1234" // not in 10.0.0.0/8
	req.Header.Set("Forwarded", `host=api.websitea.com`)
	req.Host = "internal"

	host, err := hp.CanonicalHost(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if host != "internal" {
		t.Fatalf("expected req.Host, got %q", host)
	}
}
