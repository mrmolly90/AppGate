package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

type contextKey string

const (
	// IdentityKey is the context key for the authenticated identity.
	IdentityKey contextKey = "identity"
	// RolesKey is the context key for the authenticated roles.
	RolesKey contextKey = "roles"
)

// Claims represents standard JWT claims.
type Claims struct {
	Sub   string   `json:"sub"`
	Exp   int64    `json:"exp"`
	Iat   int64    `json:"iat"`
	Roles []string `json:"roles,omitempty"`
}

// Middleware provides JWT-based authentication for the control plane API.
type Middleware struct {
	logger    *zap.SugaredLogger
	secret    string
	skipPaths map[string]bool
}

// NewMiddleware creates a new auth middleware.
func NewMiddleware(logger *zap.SugaredLogger) *Middleware {
	secret := getEnv("APPGATE_JWT_SECRET", "")
	if secret == "" {
		logger.Warn("APPGATE_JWT_SECRET not set, generating ephemeral secret - all tokens will be invalidated on restart")
		secret = generateEphemeralSecret()
	}
	return &Middleware{
		logger:    logger,
		secret:    secret,
		skipPaths: map[string]bool{"/healthz": true, "/readyz": true, "/metrics": true},
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// generateEphemeralSecret creates a random 256-bit secret for JWT signing.
// NOTE: This means all sessions are invalidated on restart.
// For production, always set APPGATE_JWT_SECRET.
func generateEphemeralSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("failed to generate ephemeral JWT secret: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Middleware is an HTTP middleware that validates Bearer tokens.
func (m *Middleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health and metrics endpoints
		if m.skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
			return
		}

		// Validate JWT with HMAC-SHA256
		claims, err := m.validateToken(token)
		if err != nil {
			m.logger.Warnw("JWT validation failed", "error", err)
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), IdentityKey, claims.Sub)
		ctx = context.WithValue(ctx, RolesKey, claims.Roles)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateToken validates a JWT token using HMAC-SHA256.
func (m *Middleware) validateToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedToken
	}
	if header.Alg != "HS256" {
		return nil, ErrUnsupportedAlgorithm
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(m.secret))
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, ErrInvalidSignature
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrMalformedToken
	}

	// Validate expiration
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, ErrTokenExpired
	}

	// Validate issued-at
	if claims.Iat > 0 && time.Now().Unix() < claims.Iat-300 {
		return nil, ErrTokenNotYetValid
	}

	if claims.Sub == "" {
		return nil, ErrMissingSubject
	}

	return &claims, nil
}

// GetIdentity extracts the authenticated identity from the request context.
func GetIdentity(r *http.Request) string {
	if id, ok := r.Context().Value(IdentityKey).(string); ok {
		return id
	}
	return "anonymous"
}

// GetRoles extracts the authenticated roles from the request context.
func GetRoles(r *http.Request) []string {
	if roles, ok := r.Context().Value(RolesKey).([]string); ok {
		return roles
	}
	return []string{}
}

// Error types for JWT validation.
var (
	ErrMalformedToken       = &AuthError{"malformed_token", "Token is malformed"}
	ErrUnsupportedAlgorithm = &AuthError{"unsupported_algorithm", "Only HS256 is supported"}
	ErrInvalidSignature     = &AuthError{"invalid_signature", "Token signature is invalid"}
	ErrTokenExpired         = &AuthError{"token_expired", "Token has expired"}
	ErrTokenNotYetValid     = &AuthError{"token_not_yet_valid", "Token is not yet valid"}
	ErrMissingSubject       = &AuthError{"missing_subject", "Token is missing subject claim"}
)

// AuthError represents a structured authentication error.
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *AuthError) Error() string {
	return e.Code + ": " + e.Message
}
