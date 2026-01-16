package qaauthmw

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

type verifierFunc func(ctx context.Context, in VerifyInput) (*VerifyResult, error)

func (f verifierFunc) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	return f(ctx, in)
}

func okAuthHeaders(t *testing.T) map[string]string {
	t.Helper()

	// canonical itself can be anything; middleware just checks base64 is valid
	canonical := "method=GET\npath=/private\nhost=api.example.com\n"
	canonB64 := base64.StdEncoding.EncodeToString([]byte(canonical))

	return map[string]string{
		"Authorization":               `QuantumAuth sig_tpm="tpm" , sig_pq="pq"`,
		"X-QuantumAuth-Canonical-B64": canonB64,
	}
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
	req.Header.Set("Authorization", "Bearer nope")
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.StdEncoding.EncodeToString([]byte("x")))
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidCanonicalBase64_400(t *testing.T) {
	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		t.Fatalf("verifier should not be called on invalid canonical base64")
		return nil, nil
	})

	mw := Middleware(v)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called on invalid canonical base64")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", "not-base64!!")
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
	for k, v := range okAuthHeaders(t) {
		req.Header.Set(k, v)
	}
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
	for k, v := range okAuthHeaders(t) {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_ForwardsHostToVerifier(t *testing.T) {
	var gotHost string

	v := verifierFunc(func(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
		gotHost = in.Headers["Host"]
		return &VerifyResult{Authenticated: true, UserID: "u"}, nil
	})

	// Default HostPolicy uses r.Host (forwarded headers not trusted).
	mw := Middleware(v)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	for k, v := range okAuthHeaders(t) {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotHost != "api.example.com" {
		t.Fatalf("expected Host forwarded as api.example.com, got %q", gotHost)
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
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.StdEncoding.EncodeToString([]byte("x")))

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
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.StdEncoding.EncodeToString([]byte("x")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if gotPath != "/forced" {
		t.Fatalf("expected path '/forced', got %q", gotPath)
	}
}

func TestQaMiddleware_Default_FastFailsWithBadRequest(t *testing.T) {
	h := QAMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be reached")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)

	// Provide headers so we pass "missing headers" check,
	// but still trigger fast-fail (BadRequest) before any remote call.
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.StdEncoding.EncodeToString([]byte("x")))

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
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.StdEncoding.EncodeToString([]byte("x")))

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
	req.Header.Set("Authorization", "Bearer nope")
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.StdEncoding.EncodeToString([]byte("x")))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected bad request handler to be called")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected 418, got %d", rr.Code)
	}
}
