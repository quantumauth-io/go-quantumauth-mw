package qaauthmw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemoteVerifier_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/auth/verify" {
			t.Fatalf("expected /auth/verify, got %s", r.URL.Path)
		}

		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}

		// Minimal expectations
		if req["method"] == "" || req["path"] == "" {
			t.Fatalf("expected method/path in request")
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"authenticated": true,
			"user_id":       "user-abc",
		})
	}))
	defer srv.Close()

	rv := &RemoteVerifier{BaseURL: srv.URL}

	out, err := rv.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/private",
		Headers: map[string]string{"Authorization": "x", "X-QuantumAuth-Canonical-B64": "y"},
		// Encrypted is optional now; omit it
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out == nil || !out.Authenticated || out.UserID != "user-abc" {
		t.Fatalf("unexpected out: %+v", out)
	}
}

func TestRemoteVerifier_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"authenticated":false}`))
	}))
	defer srv.Close()

	rv := &RemoteVerifier{BaseURL: srv.URL}

	_, err := rv.Verify(context.Background(), VerifyInput{
		Method:  "GET",
		Path:    "/private",
		Headers: map[string]string{"Authorization": "x", "X-QuantumAuth-Canonical-B64": "y"},
	})
	if err == nil {
		t.Fatalf("expected err")
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}
