package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const claimsKey contextKey = "appgate_claims"

// Claims represents the JWT claims we expect from internal apps.
type Claims struct {
	ProjectID string   `json:"project_id"`
	UserID    string   `json:"user_id"`
	Team      string   `json:"team"`
	Scopes    []string `json:"scopes"`
	jwt.RegisteredClaims
}

// JWTValidator validates incoming app tokens using RSA/ECDSA public keys.
type JWTValidator struct {
	publicKey interface{}
}

// NewJWTValidator parses a PEM-encoded RSA or ECDSA public key and returns
// a validator. If pemStr is empty, the validator is created but will reject all
// tokens (fail-closed security posture).
func NewJWTValidator(pemStr string) (*JWTValidator, error) {
	if pemStr == "" {
		return &JWTValidator{}, nil
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	var key interface{}
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse certificate: %w", parseErr)
		}
		key = cert.PublicKey
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	switch key.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return &JWTValidator{publicKey: key}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// Middleware returns an HTTP handler that validates Bearer JWT tokens.
// Tokens are verified using the configured public key. Requests without
// a valid token receive a 401 response (fail-closed).
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

		// If no public key is configured, reject all tokens (fail-closed).
		if v.publicKey == nil {
			http.Error(w, `{"error":"authentication not configured"}`, http.StatusInternalServerError)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing algorithm
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
			}
			return v.publicKey, nil
		})
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		if !token.Valid {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// Fill in defaults for optional fields
		if claims.ProjectID == "" {
			claims.ProjectID = "default"
		}
		if claims.UserID == "" {
			claims.UserID = "anonymous"
		}

		ctx := context.WithValue(r.Context(), claimsKey, *claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClaimsFromContext extracts the JWT claims from a request context.
// Returns a default Claims struct with "unknown" values if no claims are present.
func ClaimsFromContext(ctx context.Context) Claims {
	if c, ok := ctx.Value(claimsKey).(Claims); ok {
		return c
	}
	return Claims{ProjectID: "unknown", UserID: "unknown"}
}
