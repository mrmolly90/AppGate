package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// JWTService handles JWT creation and validation.
type JWTService struct {
	signingKey    *rsa.PrivateKey
	verifyingKey  *rsa.PublicKey
	issuer        string
	audience      string
	allowedAlgs   []string
	clockSkew     time.Duration
}

// NewJWTService creates a new JWT service with secure defaults.
func NewJWTService(signingKey *rsa.PrivateKey, issuer, audience string) *JWTService {
	return &JWTService{
		signingKey:   signingKey,
		verifyingKey: &signingKey.PublicKey,
		issuer:       issuer,
		audience:     audience,
		allowedAlgs:  []string{"RS256", "ES256"},
		clockSkew:    30 * time.Second,
	}
}

// Claims represents the JWT claims for AppGate.
type Claims struct {
	jwt.RegisteredClaims
	Roles  []string          `json:"roles"`
	Scope  string            `json:"scope"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CreateToken generates a signed JWT for a given identity.
func (s *JWTService) CreateToken(identityID string, roles []string, scope string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
			Subject:   identityID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-s.clockSkew)),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Roles: roles,
		Scope: scope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "appgate-signing-key-v1"

	signed, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// ValidateToken validates a JWT and returns the claims.
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Algorithm check: prevent algorithm confusion
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			// Also check ECDSA
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}

		// Verify algorithm is in allowlist
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing algorithm header")
		}

		allowed := false
		for _, a := range s.allowedAlgs {
			if alg == a {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("signing algorithm %s not allowed", alg)
		}

		return s.verifyingKey, nil
	},
		// Validation options
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.audience),
		jwt.WithValidMethods(s.allowedAlgs),
		jwt.WithLeeway(s.clockSkew),
	)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// Middleware provides HTTP middleware for JWT validation.
func (s *JWTService) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
			return
		}

		claims, err := s.ValidateToken(parts[1])
		if err != nil {
			log.Warn().Err(err).Msg("JWT validation failed")
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		// Set claims in context
		ctx := contextWithClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns middleware that checks for a required role.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := claimsFromContext(r.Context())
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusForbidden)
				return
			}

			hasRole := false
			for _, r := range claims.Roles {
				if r == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				log.Warn().Str("identity", claims.Subject).Str("required_role", role).Msg("authorization denied")
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Context key type to avoid collisions
type contextKey string

const claimsKey contextKey = "claims"

func contextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ClaimsFromContext retrieves JWT claims from the request context.
// Returns nil, false if no claims are present.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	return claimsFromContext(ctx)
}

func claimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*Claims)
	return claims, ok
}