package auth

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"appgate-control-plane/internal/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
)

type Service struct {
	cfg    *config.Config
	db     *sql.DB
	logger *zap.SugaredLogger
	key    interface{}
}

func NewService(cfg *config.Config, db *sql.DB, logger *zap.SugaredLogger) *Service {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		logger.Warnw("Failed to generate signing key", "error", err)
	}
	return &Service{cfg: cfg, db: db, logger: logger, key: priv}
}

func (s *Service) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Service) HandleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.key != nil {
		now := time.Now().UTC()
		claims := jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    "https://appgate.example.com",
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{"appgate-gateway"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
		}
		token := jwt.NewWithClaims(jwt.GetSigningMethod("EdDSA"), claims)
		token.Header["kid"] = "appgate-key-v1"
		signedToken, err := token.SignedString(s.key)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create token")
			http.Error(w, `{"error":"token_creation_failed"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": signedToken, "token_type": "bearer", "expires_in": "3600"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": "dev-token", "token_type": "bearer"})
}

func (s *Service) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": "refreshed", "token_type": "bearer"})
}

func (s *Service) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"active": true, "sub": "anonymous"})
}

func (s *Service) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
}
