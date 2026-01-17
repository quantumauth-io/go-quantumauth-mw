package qagin

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	qaauthmw "github.com/quantumauth-io/go-quantumauth-mw"
)

type verifierFunc func(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error)

func (f verifierFunc) Verify(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error) {
	return f(ctx, in)
}

func TestMiddleware_Unauthorized_Aborts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	v := verifierFunc(func(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error) {
		return &qaauthmw.VerifyResult{Authenticated: false}, qaauthmw.ErrUnauthorized
	})

	r := gin.New()
	r.Use(Middleware(v)) // <-- inject verifier via adapter's Middleware

	called := false
	r.GET("/private", func(c *gin.Context) {
		called = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.RawStdEncoding.EncodeToString([]byte("x")))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if called {
		t.Fatalf("handler should not be called when unauthorized")
	}
}

func TestMiddleware_OK_AllowsAndSetsUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	v := verifierFunc(func(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error) {
		return &qaauthmw.VerifyResult{Authenticated: true, UserID: "user-gin"}, nil
	})

	r := gin.New()
	r.Use(Middleware(v)) // <-- inject verifier via adapter's Middleware

	r.GET("/private", func(c *gin.Context) {
		uid, ok := UserID(c)
		if !ok || uid != "user-gin" {
			t.Fatalf("expected user id in gin context, got ok=%v uid=%q", ok, uid)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.RawStdEncoding.EncodeToString([]byte("x")))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestQAMiddlewareWithRemote_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)

	qa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"user_id":"user-gin-remote"}`))
	}))
	defer qa.Close()

	r := gin.New()
	r.Use(QAMiddlewareWithRemote(qa.URL))

	r.GET("/private", func(c *gin.Context) {
		uid, ok := UserID(c)
		if !ok || uid != "user-gin-remote" {
			t.Fatalf("expected user id=user-gin-remote, got ok=%v uid=%q", ok, uid)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.RawStdEncoding.EncodeToString([]byte("x")))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestQAMiddleware_Default_FastFailsWithBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(QAMiddleware()) // ✅ gin middleware usage

	r.GET("/private", func(c *gin.Context) {
		t.Fatalf("handler should not be reached")
	})

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/private", nil)
	req.Header.Set("Authorization", `QuantumAuth sig_tpm="tpm", sig_pq="pq"`)
	req.Header.Set("X-QuantumAuth-Canonical-B64", base64.RawStdEncoding.EncodeToString([]byte("x")))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}
