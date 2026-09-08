package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"appgate-control-plane/internal/api"
	"appgate-control-plane/internal/audit"
	"appgate-control-plane/internal/auth"
	"appgate-control-plane/internal/policy"
	"appgate-control-plane/internal/proxy"
	pkgapi "appgate-control-plane/pkg/api"
	"appgate-control-plane/pkg/store"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// ── Configuration from Environment ─────────────────────────────────
	dbDSN := getEnv("APPGATE_PG_DSN", "postgres://appgate:appgate@localhost:5432/appgate?sslmode=disable")
	redisURL := getEnv("APPGATE_REDIS_URL", "redis://localhost:6379/0")
	listenAddr := getEnv("APPGATE_LISTEN_ADDR", ":8080")
	metricsAddr := getEnv("APPGATE_METRICS_ADDR", ":9090")
	grpcAddr := getEnv("APPGATE_GRPC_ADDR", ":9091")

	// ── Database ──────────────────────────────────────────────────────
	var db *sql.DB
	if dbDSN != "" {
		db, err = openDB(dbDSN)
		if err != nil {
			sugar.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()
		sugar.Info("Database connected")
	}

	// ── Redis ─────────────────────────────────────────────────────────
	var redisClient *redis.Client
	if redisURL != "" {
		redisClient, err = store.NewRedis(redisURL)
		if err != nil {
			sugar.Warnf("Redis not available (running in degraded mode): %v", err)
		}
	}

	// ── Initialize Internal Components ────────────────────────────────
	auditLogger := audit.NewLogger(sugar)
	authMiddleware := auth.NewMiddleware(sugar)
	proxyHandler := proxy.NewHandler(sugar, db, redisClient)
	policyEngine := policy.NewEngine(sugar, db)

	// ── Router ────────────────────────────────────────────────────────
	router := mux.NewRouter()

	// ── Middleware ────────────────────────────────────────────────────
	router.Use(api.RequestIDMiddleware)
	router.Use(api.SecurityHeaders)
	router.Use(api.PanicRecoveryMiddleware(sugar))
	router.Use(api.MetricsMiddleware)
	router.Use(api.CORSMiddleware([]string{}))
	router.Use(authMiddleware.Middleware)

	// ── Health & Metrics ─────────────────────────────────────────────
	router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy"}`)
	}).Methods("GET")

	router.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if db != nil {
			if err := db.PingContext(r.Context()); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{"status":"unhealthy","reason":"database unreachable"}`)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ready"}`)
	}).Methods("GET")

	// ── Metrics ──────────────────────────────────────────────────────
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// ── API Routes ──────────────────────────────────────────────────
	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	// Policy evaluation endpoint (uses the in-memory policy engine)
	apiRouter.HandleFunc("/evaluate", func(w http.ResponseWriter, r *http.Request) {
		// Restrict body size to prevent abuse
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
		identity := auth.GetIdentity(r)
		var req struct {
			Action   string `json:"action"`
			Resource string `json:"resource"`
			Provider string `json:"provider"`
			Model    string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if req.Action == "" && req.Resource == "" && req.Provider == "" && req.Model == "" {
			api.WriteJSONError(w, http.StatusBadRequest, "invalid_request", "action/resource or provider/model is required")
			return
		}
		var result policy.EvaluationResult
		if req.Provider != "" || req.Model != "" {
			result = policyEngine.EvaluateRequest(identity, auth.GetRoles(r), req.Provider, req.Model)
		} else {
			result = policyEngine.Evaluate(identity, req.Action, req.Resource)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}).Methods("POST")

	if db != nil {
		// Policy routes
		apiRouter.HandleFunc("/policies", api.HandleListPolicies(db)).Methods("GET")
		apiRouter.HandleFunc("/policies", api.HandleCreatePolicy(db)).Methods("POST")
		apiRouter.HandleFunc("/policies/{id}", api.HandleGetPolicy(db)).Methods("GET")
		apiRouter.HandleFunc("/policies/{id}", api.HandleUpdatePolicy(db)).Methods("PUT")
		apiRouter.HandleFunc("/policies/{id}", api.HandleDeletePolicy(db)).Methods("DELETE")
		apiRouter.HandleFunc("/policies/{id}/validate", api.HandleValidatePolicy(db)).Methods("GET")
		// Audit routes
		apiRouter.HandleFunc("/audit", api.HandleQueryAudit(db)).Methods("GET")
		apiRouter.HandleFunc("/audit/export", api.HandleExportAudit(db)).Methods("GET")
		apiRouter.HandleFunc("/audit/batch", api.HandleAuditBatch(db)).Methods("POST")
		// Backend routes
		backendStore := store.NewBackendStore(db)
		apiRouter.HandleFunc("/backends", pkgapi.ListBackends(backendStore)).Methods("GET")
		apiRouter.HandleFunc("/backends", pkgapi.CreateBackend(backendStore)).Methods("POST")
		apiRouter.HandleFunc("/backends/{id}", pkgapi.GetBackend(backendStore)).Methods("GET")
		apiRouter.HandleFunc("/backends/{id}", pkgapi.UpdateBackend(backendStore)).Methods("PUT")
		apiRouter.HandleFunc("/backends/{id}", pkgapi.DeleteBackend(backendStore)).Methods("DELETE")
		apiRouter.HandleFunc("/backends/{id}/health", pkgapi.TriggerHealthCheck(backendStore)).Methods("POST")
		// Route routes
		routeStore := store.NewRouteStore(db)
		apiRouter.HandleFunc("/routes", pkgapi.ListRoutes(routeStore)).Methods("GET")
		apiRouter.HandleFunc("/routes", pkgapi.CreateRoute(routeStore)).Methods("POST")
		apiRouter.HandleFunc("/routes/{id}", pkgapi.GetRoute(routeStore)).Methods("GET")
		apiRouter.HandleFunc("/routes/{id}", pkgapi.UpdateRoute(routeStore)).Methods("PUT")
		apiRouter.HandleFunc("/routes/{id}", pkgapi.DeleteRoute(routeStore)).Methods("DELETE")
		// API Key routes
		apiKeyStore := store.NewAPIKeyStore(db)
		apiRouter.HandleFunc("/api-keys", pkgapi.ListAPIKeys(apiKeyStore)).Methods("GET")
		apiRouter.HandleFunc("/api-keys", pkgapi.CreateAPIKey(apiKeyStore)).Methods("POST")
		apiRouter.HandleFunc("/api-keys/{id}", pkgapi.RevokeAPIKey(apiKeyStore)).Methods("DELETE")
		// Audit store routes
		auditStore := store.NewAuditStore(db)
		apiRouter.HandleFunc("/audit-logs", pkgapi.ListAuditLogs(auditStore)).Methods("GET")
		apiRouter.HandleFunc("/audit-logs/summary", pkgapi.AuditSummary(auditStore)).Methods("GET")
	}

	if redisClient != nil {
		apiRouter.HandleFunc("/gateways", api.HandleListGateways(redisClient)).Methods("GET")
		apiRouter.HandleFunc("/nodes", pkgapi.ListNodes(redisClient)).Methods("GET")
		apiRouter.HandleFunc("/nodes/{id}/drain", pkgapi.DrainNode(redisClient)).Methods("POST")
		apiRouter.HandleFunc("/nodes/{id}/reload", pkgapi.ReloadNode(redisClient)).Methods("POST")
	}

	// ── Admin Routes ─────────────────────────────────────────────────
	adminRouter := router.PathPrefix("/admin").Subrouter()
	adminRouter.HandleFunc("/health", proxyHandler.HealthHandler).Methods("GET")
	adminRouter.HandleFunc("/config/reload", proxyHandler.ConfigReloadHandler).Methods("POST")

	// ── Config Push via gRPC ────────────────────────────────────────
	grpcServer := pkgapi.NewGRPCServer(grpcAddr, auditLogger, sugar)
	go func() {
		sugar.Infof("gRPC server listening on %s", grpcAddr)
		if err := grpcServer.Start(); err != nil {
			sugar.Warnf("gRPC server stopped: %v", err)
		}
	}()

	// Admin config push — wired to the gRPC node registry for real node counting
	adminRouter.HandleFunc("/config/push", pkgapi.PushConfig(grpcServer)).Methods("POST")

	// ── HTTP Server ─────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start metrics server
	metricsSrv := &http.Server{
		Addr:    metricsAddr,
		Handler: promhttp.Handler(),
	}

	// ── Shutdown Handling ───────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sugar.Infof("Control plane listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("HTTP server error: %v", err)
		}
	}()

	go func() {
		sugar.Infof("Metrics listening on %s", metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Warnf("Metrics server error: %v", err)
		}
	}()

	<-quit
	sugar.Info("Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	grpcServer.Stop()
	policyEngine.Close()
	proxyHandler.Close()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		sugar.Fatalf("HTTP server forced shutdown: %v", err)
	}
	metricsSrv.Shutdown(shutdownCtx) //nolint:errcheck // best-effort shutdown on metrics server

	sugar.Info("Control plane stopped")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("db.Ping: %w", err)
	}
	return db, nil
}
