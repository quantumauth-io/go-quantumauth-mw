// Package qachi exists for symmetry with other framework adapters.
// Chi already uses net/http middleware signatures, so the core middleware
// can be used directly without importing this package.
package qachi

import (
	"context"
	"net/http"

	qaauthmw "github.com/quantumauth-io/go-quantumauth-mw"
)

// Middleware returns a chi-compatible middleware (which is just net/http middleware).
func QAMiddleware(v qaauthmw.Verifier, opts ...qaauthmw.Option) func(http.Handler) http.Handler {
	return qaauthmw.Middleware(v, opts...)
}

func UserID(ctx context.Context) (string, bool) {
	return qaauthmw.UserIDFromContext(ctx)
}
