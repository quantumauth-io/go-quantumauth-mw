package qagin

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	qaauthmw "github.com/quantumauth-io/go-quantumauth-mw"
)

// QaMiddleware is the zero-config Gin middleware (remote verification).
func QAMiddleware(opts ...qaauthmw.Option) gin.HandlerFunc {
	return QAMiddlewareWithRemote(qaauthmw.DefaultRemoteBaseURL, opts...)
}

// QaMiddlewareWithRemote overrides the QuantumAuth backend base URL.
func QAMiddlewareWithRemote(baseURL string, opts ...qaauthmw.Option) gin.HandlerFunc {
	v := &qaauthmw.RemoteVerifier{BaseURL: baseURL}
	return Middleware(v, opts...)
}

func Middleware(v qaauthmw.Verifier, opts ...qaauthmw.Option) gin.HandlerFunc {
	fmt.Printf("[QA] gin middleware verifier=%T\n", v)
	mw := qaauthmw.Middleware(v, opts...)
	return func(c *gin.Context) {

		called := false
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)

		if !called {
			c.Abort()
			return
		}
	}
}

func UserID(c *gin.Context) (string, bool) {
	return qaauthmw.UserIDFromContext(c.Request.Context())
}
