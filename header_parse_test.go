package qaauthmw

import "testing"

func TestParseAuthorizationQuantumAuth_OK(t *testing.T) {
	_, err := ParseAuthorizationQuantumAuth(`QuantumAuth sig_tpm="a", sig_pq="b"`)
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestParseAuthorizationQuantumAuth_BadScheme(t *testing.T) {
	_, err := ParseAuthorizationQuantumAuth(`Bearer abc`)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseAuthorizationQuantumAuth_MissingFields(t *testing.T) {
	_, err := ParseAuthorizationQuantumAuth(`QuantumAuth sig_tpm="a"`)
	if err == nil {
		t.Fatalf("expected error")
	}
}
