package qaauthmw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/quantumauth-io/go-quantumauth-mw/headers"
)

// -------------------------
// Context keys + helpers
// -------------------------

type ctxKey string

const (
	CtxUserIDKey ctxKey = "quantumauth_user_id"
)

const DefaultRemoteBaseURL = "https://api.quantumauth.io/quantum-auth/v1"

func QAMiddleware(opts ...Option) func(http.Handler) http.Handler {
	return QAMiddlewareWithRemote(DefaultRemoteBaseURL, opts...)
}

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
	RequireAuth       bool
	PathFunc          func(r *http.Request) string
	ComputeBodySHA256 bool
	BodyReader        func(r *http.Request) ([]byte, error)
	HostPolicy        HostPolicy
	OnUnauthorized    func(w http.ResponseWriter, r *http.Request)
	OnBadRequest      func(w http.ResponseWriter, r *http.Request, err error)
}

type Option func(*Options)

func WithRequireAuth(v bool) Option { return func(o *Options) { o.RequireAuth = v } }
func WithPathFunc(f func(r *http.Request) string) Option {
	return func(o *Options) { o.PathFunc = f }
}
func WithHostPolicy(p HostPolicy) Option  { return func(o *Options) { o.HostPolicy = p } }
func WithComputeBodySHA256(v bool) Option { return func(o *Options) { o.ComputeBodySHA256 = v } }
func WithBodyReader(f func(r *http.Request) ([]byte, error)) Option {
	return func(o *Options) { o.BodyReader = f }
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
		ComputeBodySHA256: true,
		BodyReader: func(r *http.Request) ([]byte, error) {
			// Read body and restore it so downstream handlers still see it.
			if r.Body == nil {
				return nil, nil
			}
			b, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(b))
			return b, nil
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
			qaHeaders := extractQAHeadersV2(r, o.HostPolicy)

			if qaHeaders == nil {
				if o.RequireAuth {
					o.OnUnauthorized(w, r)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// 2) Fast-fail Authorization header shape
			if _, err := ParseAuthorizationQuantumAuth(qaHeaders["Authorization"]); err != nil {
				o.OnBadRequest(w, r, err)
				return
			}

			// 3) Compute body SHA (optional but recommended)
			var body []byte
			if o.ComputeBodySHA256 {
				var err error
				body, err = o.BodyReader(r)
				if err != nil {
					o.OnBadRequest(w, r, fmt.Errorf("%w: read body failed", ErrBadRequest))
					return
				}
				sum := sha256.Sum256(body)
				qaHeaders["X-QuantumAuth-Body-SHA256"] = hex.EncodeToString(sum[:])
			}

			// 4) Call verifier (remote or local)
			in := VerifyInput{
				Method:  r.Method,
				Path:    o.PathFunc(r),
				Headers: qaHeaders,
				// If your verifier needs the body bytes directly, pass it:
				Body: body,
				// Keep this for future use if you want:
				Encrypted: json.RawMessage(nil),
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

func extractQAHeadersV2(r *http.Request, hp HostPolicy) map[string]string {
	// Required
	auth := strings.TrimSpace(r.Header.Get(string(headers.HeaderAuthorization)))
	if auth == "" {
		return nil
	}

	appID := strings.TrimSpace(r.Header.Get(string(headers.HeaderQAAppID)))
	aud := strings.TrimSpace(r.Header.Get(string(headers.HeaderQAAudience)))
	ts := strings.TrimSpace(r.Header.Get(string(headers.HeaderQATimestamp)))
	challengeID := strings.TrimSpace(r.Header.Get(string(headers.HeaderQAChallengeID)))
	userID := strings.TrimSpace(r.Header.Get(string(headers.HeaderQAUserID)))
	deviceID := strings.TrimSpace(r.Header.Get(string(headers.HeaderQADeviceID)))

	// Optional (may be set by client; middleware may overwrite body sha later)
	bodySHA := strings.TrimSpace(r.Header.Get(string(headers.HeaderQABodySHA256)))
	ver := strings.TrimSpace(r.Header.Get(string(headers.HeaderQAVersion)))

	if appID == "" || aud == "" || ts == "" || challengeID == "" || userID == "" || deviceID == "" {
		return nil
	}

	out := map[string]string{
		string(headers.HeaderAuthorization): auth,
		string(headers.HeaderQAAppID):       appID,
		string(headers.HeaderQAAudience):    aud,
		string(headers.HeaderQATimestamp):   ts,
		string(headers.HeaderQAChallengeID): challengeID,
		string(headers.HeaderQAUserID):      userID,
		string(headers.HeaderQADeviceID):    deviceID,
	}

	if ver != "" {
		out[string(headers.HeaderQAVersion)] = ver
	}
	if bodySHA != "" {
		out[string(headers.HeaderQABodySHA256)] = bodySHA
	}

	return out
}
