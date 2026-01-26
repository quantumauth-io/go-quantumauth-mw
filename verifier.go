package qaauthmw

import (
	"context"
	"encoding/json"
	"errors"
)

var (
	// ErrUnauthorized means the request was well-formed but failed auth.
	ErrUnauthorized = errors.New("quantumauth: unauthorized")
	// ErrBadRequest means the request could not be verified due to missing/invalid inputs.
	ErrBadRequest = errors.New("quantumauth: bad request")
)

type VerifyInput struct {
	Method    string
	Path      string
	Headers   map[string]string
	Body      []byte
	Encrypted json.RawMessage
}

type VerifyResult struct {
	Authenticated bool
	UserID        string
}

type Verifier interface {
	Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error)
}
