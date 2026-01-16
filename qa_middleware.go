package qaauthmw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// -------------------------
// Context keys + helpers
// -------------------------

type ctxKey string

const (
	CtxUserIDKey ctxKey = "quantumauth_user_id"
)

// DefaultRemoteBaseURL is the default QuantumAuth backend base URL for remote verification.
const DefaultRemoteBaseURL = "https://api.quantumauth.io/quantum-auth/v1"

// QAMiddleware returns a ready-to-use QuantumAuth middleware that verifies requests
// by calling the QuantumAuth backend (remote verification).
//
// Developers can just:
//
//	r.Use(qaauthmw.QaMiddleware())
//
// Override by calling QaMiddlewareWithRemote(...) or using Middleware(...) directly.
func QAMiddleware(opts ...Option) func(http.Handler) http.Handler {
	return QAMiddlewareWithRemote(DefaultRemoteBaseURL, opts...)
}

// QaMiddlewareWithRemote is the same as QaMiddleware but lets callers override the backend base URL.
// Example:
//
//	r.Use(qaauthmw.QaMiddlewareWithRemote("http://localhost:8081/quantum-auth/v1"))
func QAMiddlewareWithRemote(baseURL string, opts ...Option) func(http.Handler) http.Handler {
	v := &RemoteVerifier{BaseURL: baseURL}
	return Middleware(v, opts...)
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(CtxUserIDKey)
	s, ok := v.(string)
	return s, ok && s != ""
}

// -------------------------
// Options
// -------------------------

type Options struct {
	// If true, missing QA headers yields 401.
	// If false, requests without QA headers pass through.
	RequireAuth bool

	// Computes the request path to send for verification.
	// Default uses r.URL.Path.
	PathFunc func(r *http.Request) string

	// Builds the "encrypted" field. Must return non-empty JSON to satisfy:
	//   Encrypted json.RawMessage `json:"encrypted" binding:"required"`
	EncryptedFunc func(r *http.Request) json.RawMessage

	// Determines which host value is forwarded to QA backend for verification.
	// This host is the one bound into the canonical string (host of the protected API),
	// NOT the QA backend host.
	HostPolicy HostPolicy

	// Optional: customize unauthorized response.
	OnUnauthorized func(w http.ResponseWriter, r *http.Request)

	// Optional: customize bad request response.
	OnBadRequest func(w http.ResponseWriter, r *http.Request, err error)
}

type Option func(*Options)

func WithRequireAuth(v bool) Option {
	return func(o *Options) { o.RequireAuth = v }
}

func WithPathFunc(f func(r *http.Request) string) Option {
	return func(o *Options) { o.PathFunc = f }
}

func WithEncryptedFunc(f func(r *http.Request) json.RawMessage) Option {
	return func(o *Options) { o.EncryptedFunc = f }
}

func WithHostPolicy(p HostPolicy) Option {
	return func(o *Options) { o.HostPolicy = p }
}

func WithUnauthorizedHandler(f func(w http.ResponseWriter, r *http.Request)) Option {
	return func(o *Options) { o.OnUnauthorized = f }
}

func WithBadRequestHandler(f func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(o *Options) { o.OnBadRequest = f }
}

// -------------------------
// Middleware
// -------------------------

func Middleware(v Verifier, opts ...Option) func(next http.Handler) http.Handler {
	o := &Options{
		RequireAuth: true,
		PathFunc: func(r *http.Request) string {
			if r.URL != nil {
				return r.URL.Path
			}
			return ""
		},
		EncryptedFunc: func(r *http.Request) json.RawMessage {
			return nil // no encrypted body today
		},
		HostPolicy: HostPolicy{
			TrustedProxyCIDRs:    nil,   // forwarded headers not trusted by default
			TrustForwardedHeader: false, // Forwarded: host=... disabled by default
		},
		OnUnauthorized: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		},
		OnBadRequest: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "invalid auth request", http.StatusBadRequest)
		},
	}
	for _, opt := range opts {
		opt(o)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			qaHeaders := extractQAHeaders(r, o.HostPolicy)

			// 1) Missing QA headers
			if qaHeaders == nil {
				if o.RequireAuth {
					o.OnUnauthorized(w, r)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// 2) Fast-fail: Authorization header shape + required fields
			if _, err := ParseAuthorizationQuantumAuth(qaHeaders["Authorization"]); err != nil {
				o.OnBadRequest(w, r, err)
				return
			}

			// 3) Fast-fail: canonical must be valid base64
			if _, err := base64.StdEncoding.DecodeString(
				qaHeaders["X-QuantumAuth-Canonical-B64"],
			); err != nil {
				o.OnBadRequest(w, r, fmt.Errorf("%w: invalid canonical base64", ErrBadRequest))
				return
			}

			// 5) Call verifier (remote or local)
			in := VerifyInput{
				Method:    r.Method,
				Path:      o.PathFunc(r),
				Headers:   qaHeaders,
				Encrypted: o.EncryptedFunc(r),
			}

			res, err := v.Verify(r.Context(), in)
			if err != nil {
				if errors.Is(err, ErrUnauthorized) {
					o.OnUnauthorized(w, r)
					return
				}
				if errors.Is(err, ErrBadRequest) {
					o.OnBadRequest(w, r, err)
					return
				}
				http.Error(w, "auth service error", http.StatusBadGateway)
				return
			}
			if res == nil || !res.Authenticated || strings.TrimSpace(res.UserID) == "" {
				o.OnUnauthorized(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), CtxUserIDKey, res.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractQAHeaders collects only what QA backend needs.
// Host is computed from HostPolicy to ensure it matches the host used in canonical signing.
func extractQAHeaders(r *http.Request, hp HostPolicy) map[string]string {
	auth := r.Header.Get("Authorization")
	canon := r.Header.Get("X-QuantumAuth-Canonical-B64")
	if strings.TrimSpace(auth) == "" || strings.TrimSpace(canon) == "" {
		return nil
	}

	out := map[string]string{
		"Authorization":               auth,
		"X-QuantumAuth-Canonical-B64": canon,
	}

	if host, err := hp.CanonicalHost(r); err == nil && host != "" {
		out["Host"] = host
	}

	return out
}

// -------------------------
// Small internal helpers
// -------------------------

func bytesTrimSpace(b []byte) []byte {
	// avoid importing bytes just for TrimSpace
	i := 0
	j := len(b)

	for i < j {
		switch b[i] {
		case ' ', '\n', '\r', '\t':
			i++
		default:
			goto right
		}
	}
right:
	for j > i {
		switch b[j-1] {
		case ' ', '\n', '\r', '\t':
			j--
		default:
			break
		}
	}
	return b[i:j]
}
