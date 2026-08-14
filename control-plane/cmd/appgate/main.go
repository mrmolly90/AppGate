package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"appgate-control-plane/internal/api"
	"appgate-control-plane/internal/auth"
	"appgate-control-plane/internal/database"
)

func main() {
	// Structured logger
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()

	// Configuration from environment
	cfg := loadConfig()

	if cfg.DatabaseURL == "" {
		log.Fatal().Msg("DATABASE_URL is required")
	}

	// Initialize database
	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer db.Close()

	// Run migrations
	if err := db.Migrate(); err != nil {
		log.Fatal().Err(err).Msg("failed to run database migrations")
	}

	// Load signing keys
	signingKey, err := loadSigningKey(cfg.SigningKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load signing key")
	}

	// Initialize JWT service
	jwtService := auth.NewJWTService(signingKey, cfg.JWTIssuer, cfg.JWTAudience)

	// Initialize router
	router := mux.NewRouter()
	router.Use(api.SecurityHeaders)

	// Health checks
	router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Methods("GET")

	router.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	}).Methods("GET")

	// API routes
	apiHandler := api.NewHandler(db, jwtService)
	apiRouter := router.PathPrefix("/v1").Subrouter()

	// Public API (with rate limiting)
	authLimiter := api.NewIPRateLimiter(10, 1.0) // 10 burst, 1 per second refill
	apiRouter.Handle("/auth/token", api.RateLimitMiddleware(authLimiter, apiHandler.CreateToken)).Methods("POST")

	// Protected API (admin)
	adminRouter := apiRouter.PathPrefix("").Subrouter()
	adminRouter.Use(jwtService.Middleware)
	adminRouter.Use(auth.RequireRole("admin"))

	adminRouter.HandleFunc("/policies", apiHandler.ListPolicies).Methods("GET")
	adminRouter.HandleFunc("/policies", apiHandler.CreatePolicy).Methods("POST")
	adminRouter.HandleFunc("/policies/{id}", apiHandler.GetPolicy).Methods("GET")
	adminRouter.HandleFunc("/policies/{id}", apiHandler.UpdatePolicy).Methods("PUT")
	adminRouter.HandleFunc("/policies/{id}", apiHandler.DeletePolicy).Methods("DELETE")
	adminRouter.HandleFunc("/gateways", apiHandler.ListGateways).Methods("GET")
	adminRouter.HandleFunc("/gateways/{id}", apiHandler.GetGateway).Methods("GET")
	adminRouter.HandleFunc("/audit", apiHandler.ListAuditEvents).Methods("GET")

	// Gateway API (internal, mTLS)
	gatewayRouter := apiRouter.PathPrefix("").Subrouter()
	gatewayRouter.Use(jwtService.Middleware)
	gatewayRouter.Use(auth.RequireRole("gateway"))

	gatewayRouter.HandleFunc("/gateways/register", apiHandler.RegisterGateway).Methods("POST")
	gatewayRouter.HandleFunc("/policies/evaluate", apiHandler.EvaluatePolicy).Methods("POST")
	gatewayRouter.HandleFunc("/audit", apiHandler.CreateAuditEvent).Methods("POST")
	gatewayRouter.HandleFunc("/providers", apiHandler.ListProviders).Methods("GET")

	// Server with graceful shutdown
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info().Str("port", cfg.Port).Msg("control plane starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server failed")
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("forced shutdown")
	}
	log.Info().Msg("server stopped")
}

type Config struct {
	Port           string
	DatabaseURL    string
	SigningKeyPath string
	JWTIssuer      string
	JWTAudience    string
}

func loadConfig() Config {
	return Config{
		Port:           getEnv("PORT", "8443"),
		DatabaseURL:    getEnv("DATABASE_URL", ""),
		SigningKeyPath: getEnv("SIGNING_KEY_PATH", "/etc/appgate/keys/signing.pem"),
		JWTIssuer:      getEnv("JWT_ISSUER", "appgate-control-plane"),
		JWTAudience:    getEnv("JWT_AUDIENCE", "appgate-gateway"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key: %w", err)
	}
	return jwt.ParseRSAPrivateKeyFromPEM(data)
}