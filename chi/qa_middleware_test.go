package qachi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	qaauthmw "github.com/quantumauth-io/go-quantumauth-mw"
	"github.com/quantumauth-io/go-quantumauth-mw/headers"
)

type verifierFunc func(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error)

func (f verifierFunc) Verify(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error) {
	return f(ctx, in)
}

// V2 requires *all* these headers to be present, otherwise extractQAHeadersV2() returns nil -> 401 (RequireAuth=true).
func setQAHeadersV2(req *http.Request) {
	req.Header.Set(string(headers.HeaderAuthorization), `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)

	req.Header.Set(string(headers.HeaderQAAppID), "app-1")
	req.Header.Set(string(headers.HeaderQAAudience), "api.example.com")
	req.Header.Set(string(headers.HeaderQATimestamp), "1700000000")
	req.Header.Set(string(headers.HeaderQAChallengeID), "challenge-1")
	req.Header.Set(string(headers.HeaderQAUserID), "user-1")
	req.Header.Set(string(headers.HeaderQADeviceID), "device-1")

	// Optional
	req.Header.Set(string(headers.HeaderQAVersion), "1")
}

func TestMiddleware_Unauthorized_StopsChain(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error) {
		return &qaauthmw.VerifyResult{Authenticated: false}, qaauthmw.ErrUnauthorized
	})

	mw := QAMiddleware(v)

	protected := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called on unauthorized")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_OK_SetsUserIDInContext(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error) {
		return &qaauthmw.VerifyResult{Authenticated: true, UserID: "user-chi"}, nil
	})

	mw := QAMiddleware(v)

	protected := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := qaauthmw.UserIDFromContext(r.Context())
		if !ok || uid != "user-chi" {
			t.Fatalf("expected user id in context, got ok=%v uid=%q", ok, uid)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestUserIDHelper(t *testing.T) {
	ctx := context.WithValue(context.Background(), qaauthmw.CtxUserIDKey, "user-ctx")
	uid, ok := UserID(ctx)
	if !ok || uid != "user-ctx" {
		t.Fatalf("expected ok + user id, got ok=%v uid=%q", ok, uid)
	}
}
