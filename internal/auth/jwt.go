package auth

import (
    "context"
    "fmt"
    "net/http"
    "strings"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

type contextKey string

const claimsKey contextKey = "appgate_claims"

// Claims represents the JWT claims we expect from internal apps
type Claims struct {
    ProjectID string `json:"project_id"`
    UserID    string `json:"user_id"`
    Team      string `json:"team"`
    Scopes    []string `json:"scopes"`
    jwt.RegisteredClaims
}

// JWTValidator validates incoming app tokens
type JWTValidator struct {
    publicKey interface{}
}

func NewJWTValidator(pem string) (*JWTValidator, error) {
    // TODO: Parse RSA/ECDSA public key from PEM
    return &JWTValidator{}, nil
}

func (v *JWTValidator) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
            return
        }

        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
            http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
            return
        }

        tokenStr := parts[1]
        
        // TODO: Validate with parsed public key
        // For now, accept any token and extract claims from a future validation step
        claims := Claims{
            ProjectID: r.Header.Get("X-AppGate-Project"),
            UserID:    "anonymous",
        }
        if claims.ProjectID == "" {
            claims.ProjectID = "default"
        }

        ctx := context.WithValue(r.Context(), claimsKey, claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func ClaimsFromContext(ctx context.Context) Claims {
    if c, ok := ctx.Value(claimsKey).(Claims); ok {
        return c
    }
    return Claims{ProjectID: "unknown", UserID: "unknown"}
}
