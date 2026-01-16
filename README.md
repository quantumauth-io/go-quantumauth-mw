# go-quantumauth-mw
![Powered by QuantumAuth](https://img.shields.io/badge/Powered%20By-QuantumAuth-1a1a1a?style=for-the-badge&logo=dependabot)

QuantumAuth middleware for Go HTTP servers.

This package allows Go backends to **verify QuantumAuth requests** signed by the QuantumAuth Client (TPM + Post-Quantum signatures), using either:

- the **hosted QuantumAuth backend** (default), or
- a **custom / self-hosted verifier**

Supported frameworks:
- `net/http`
- `gin`
- `chi`

---

## Badges

![Go Version](https://img.shields.io/badge/go-1.25+-blue)
![Build](https://github.com/quantumauth-io/go-quantumauth-mw/actions/workflows/coverage.yml/badge.svg)
![Codecov](https://codecov.io/gh/quantumauth-io/go-quantumauth-mw/branch/main/graph/badge.svg)

---

## Installation

```bash
go get github.com/quantumauth-io/go-quantumauth-mw
```

---

## How QuantumAuth Works (Quick Overview)

1. A frontend (web app) requests a **challenge** from the QuantumAuth browser extension
2. The local QuantumAuth Client:
    - builds a canonical request
    - signs it with **TPM + PQ keys**
3. The frontend sends the signed headers to your backend
4. This middleware:
    - extracts the QuantumAuth headers
    - validates request shape
    - verifies signatures via the QuantumAuth backend
5. On success, the **authenticated user ID** is injected into the request context

---

## net/http Usage

### Zero-config (recommended)

Uses the hosted QuantumAuth backend automatically.

```go
import (
    "net/http"

    qaauthmw "github.com/quantumauth-io/go-quantumauth-mw"
)

mux := http.NewServeMux()

mux.Handle("/protected",
    qaauthmw.QaMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        userID, ok := qaauthmw.UserIDFromContext(r.Context())
        if !ok {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }

        w.Write([]byte("Hello user " + userID))
    })),
)

http.ListenAndServe(":8080", mux)
```

---

## Gin Usage

```go
import (
    "github.com/gin-gonic/gin"
    qagin "github.com/quantumauth-io/go-quantumauth-mw/gin"
)

r := gin.Default()
r.Use(qagin.QAMiddleware())

r.GET("/protected", func(c *gin.Context) {
    userID, ok := qagin.UserID(c)
    if !ok {
        c.AbortWithStatus(401)
        return
    }

    c.JSON(200, gin.H{
        "user_id": userID,
    })
})

r.Run(":8080")
```

---

## Chi Usage

```go
import (
    "github.com/go-chi/chi/v5"
    qaauthmw "github.com/quantumauth-io/go-quantumauth-mw"
    qachi "github.com/quantumauth-io/go-quantumauth-mw/chi"
)

r := chi.NewRouter()

r.Use(qachi.Middleware(
    &qaauthmw.RemoteVerifier{},
))

r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
    userID, ok := qachi.UserID(r.Context())
    if !ok {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    w.Write([]byte("Hello user " + userID))
})
```

---

## License

Apache-2.0 © QuantumAuth