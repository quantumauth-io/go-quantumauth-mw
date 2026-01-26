package qaauthmw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quantumauth-io/go-quantumauth-mw/headers"
)

type verifierFunc func(ctx context.Context, in VerifyInput) (*VerifyResult, error)

func (f verifierFunc) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
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

	// Optional (keep if you want to assert versioning later)
	req.Header.Set(string(headers.HeaderQAVersion), "1")
}

func TestMiddleware_RequireAuth_MissingHeaders_401(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		t.Fatalf("verifier should not be called when headers missing")
		return nil, nil
	})

	mw := Middleware(v, WithRequireAuth(true))

	protected := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called when missing headers")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	rr := httptest.NewRecorder()

	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_OptionalAuth_MissingHeaders_PassThrough(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		t.Fatalf("verifier should not be called when headers missing and RequireAuth=false")
		return nil, nil
	})

	mw := Middleware(v, WithRequireAuth(false))

	protected := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/public", nil)
	rr := httptest.NewRecorder()

	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidAuthorization_400(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		t.Fatalf("verifier should not be called on invalid Authorization")
		return nil, nil
	})

	mw := Middleware(v)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called on invalid Authorization")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)
	req.Header.Set(string(headers.HeaderAuthorization), "Bearer nope") // invalid shape -> ParseAuthorizationQuantumAuth fails

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestMiddleware_VerifierUnauthorized_401(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		return &VerifyResult{Authenticated: false}, ErrUnauthorized
	})

	mw := Middleware(v)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called when unauthorized")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_VerifierOK_SetsUserIDInContext(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		return &VerifyResult{Authenticated: true, UserID: "user-123"}, nil
	})

	mw := Middleware(v)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := UserIDFromContext(r.Context())
		if !ok || uid != "user-123" {
			t.Fatalf("expected user id in context, got ok=%v uid=%q", ok, uid)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestQaMiddlewareWithRemote_OK(t *testing.T) {
	qa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// respond like QA backend
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"user_id":"user-remote"}`))
	}))
	defer qa.Close()

	mw := QAMiddlewareWithRemote(qa.URL)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := UserIDFromContext(r.Context())
		if !ok || uid != "user-remote" {
			t.Fatalf("expected user id=user-remote, got ok=%v uid=%q", ok, uid)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestNewRemoteVerifier_UsesDefaultBaseURL(t *testing.T) {
	rv := NewRemoteVerifier()
	if rv.BaseURL != DefaultRemoteBaseURL {
		t.Fatalf("expected default base url %q, got %q", DefaultRemoteBaseURL, rv.BaseURL)
	}
}

func TestWithPathFunc_IsApplied(t *testing.T) {
	var gotPath string

	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		gotPath = in.Path
		return &VerifyResult{Authenticated: true, UserID: "u"}, nil
	})

	mw := Middleware(v, WithPathFunc(func(r *http.Request) string {
		return "/forced"
	}))

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/original", nil)
	setQAHeadersV2(req)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if gotPath != "/forced" {
		t.Fatalf("expected path '/forced', got %q", gotPath)
	}
}

func TestQaMiddleware_Default_FastFailsWithBadRequest(t *testing.T) {
	// Default middleware uses remote verifier; we want to fail before any remote call.
	// To do that, make headers pass extraction, but make Authorization invalid.
	h := QAMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be reached")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)
	req.Header.Set(string(headers.HeaderAuthorization), "Bearer nope") // triggers fast-fail BadRequest

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestWithUnauthorizedHandler_IsCalled(t *testing.T) {
	called := false

	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		return &VerifyResult{Authenticated: false}, ErrUnauthorized
	})

	h := Middleware(v, WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called when unauthorized")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected unauthorized handler to be called")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected 418, got %d", rr.Code)
	}
}

func TestWithBadRequestHandler_IsCalled(t *testing.T) {
	called := false

	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		t.Fatalf("verifier should not be called on bad request")
		return nil, nil
	})

	h := Middleware(v, WithBadRequestHandler(func(w http.ResponseWriter, r *http.Request, err error) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called on bad request")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	setQAHeadersV2(req)
	req.Header.Set(string(headers.HeaderAuthorization), "Bearer nope") // invalid -> bad request

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected bad request handler to be called")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected 418, got %d", rr.Code)
	}
}
