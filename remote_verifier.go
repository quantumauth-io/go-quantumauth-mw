package qaauthmw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type RemoteVerifier struct {
	// Example: https://api.quantumauth.io/quantum-auth/v1
	// The middleware will POST {BaseURL}/auth/verify
	BaseURL string

	// Optional: provide a custom client; defaults to a sane one.
	Client *http.Client

	// Optional: allow injecting extra headers to QA backend (api key, etc.)
	ExtraHeaders map[string]string
}

type authVerifyRequest struct {
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Encrypted json.RawMessage   `json:"encrypted,omitempty"`
}

type authVerifyResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
}

func NewRemoteVerifier() *RemoteVerifier {
	return &RemoteVerifier{BaseURL: DefaultRemoteBaseURL}
}

func (r *RemoteVerifier) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	if strings.TrimSpace(in.Method) == "" || strings.TrimSpace(in.Path) == "" {
		return nil, fmt.Errorf("%w: missing method/path", ErrBadRequest)
	}
	if len(in.Headers) == 0 {
		return nil, fmt.Errorf("%w: missing headers", ErrBadRequest)
	}

	cl := r.Client
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}

	base := strings.TrimSpace(r.BaseURL)
	if base == "" {
		base = DefaultRemoteBaseURL
	}
	url := strings.TrimRight(base, "/") + "/auth/verify"
	reqBody, err := json.Marshal(authVerifyRequest{
		Method:    in.Method,
		Path:      in.Path,
		Headers:   in.Headers,
		Encrypted: in.Encrypted,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal verify request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	for k, v := range r.ExtraHeaders {
		if strings.TrimSpace(k) != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("verify request failed: %w", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap
	switch resp.StatusCode {
	case http.StatusOK:
		var out authVerifyResponse
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, fmt.Errorf("decode verify response: %w", err)
		}
		// backend says OK, but still sanity-check
		if !out.Authenticated || out.UserID == "" {
			return &VerifyResult{Authenticated: false}, ErrUnauthorized
		}
		return &VerifyResult{Authenticated: true, UserID: out.UserID}, nil

	case http.StatusUnauthorized:
		return &VerifyResult{Authenticated: false}, ErrUnauthorized

	case http.StatusBadRequest:
		return nil, fmt.Errorf("%w: %s", ErrBadRequest, strings.TrimSpace(string(b)))

	default:
		// treat other codes as backend error (don’t map to unauthorized)
		return nil, fmt.Errorf("verify backend status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
}
