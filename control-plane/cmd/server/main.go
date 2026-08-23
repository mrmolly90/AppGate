package main

import (
    "context"
    "database/sql"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "appgate-control-plane/internal/api"
    "appgate-control-plane/internal/audit"
    "appgate-control-plane/internal/auth"
    "appgate-control-plane/internal/config"
    "appgate-control-plane/internal/leader"
    "appgate-control-plane/internal/store"

    "github.com/gorilla/mux"
    "go.uber.org/zap"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()
    sugar := logger.Sugar()

    cfg, err := config.Load()
    if err != nil {
        sugar.Fatalf("Failed to load config: %v", err)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Database (placeholder - no actual connection for now)
    db, _ := sql.Open("postgres", cfg.DatabaseURL)
    defer db.Close()

    // etcd store
    etcdStore, err := store.NewEtcdStore(ctx, cfg.EtcdEndpoints, 5*time.Second)
    if err != nil {
        sugar.Fatalf("Failed to connect to etcd: %v", err)
    }
    defer etcdStore.Close()

    // Leader election
    elector, err := leader.NewElector(etcdStore.Client(), cfg.LeaderElectionKey, cfg.InstanceID, logger)
    if err != nil {
        sugar.Fatalf("Failed to create leader elector: %v", err)
    }
    go elector.Run(ctx)

    // Auth service
    authService := auth.NewService(cfg, db, sugar)

    // Audit logger
    auditLogger := audit.NewLogger(db, sugar)

    // Router
    router := mux.NewRouter()
    router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        fmt.Fprintln(w, "ok")
    }).Methods("GET")
    router.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
        if elector.IsLeader() || elector.IsHealthy() {
            w.WriteHeader(http.StatusOK)
            fmt.Fprintln(w, "ready")
        } else {
            w.WriteHeader(http.StatusServiceUnavailable)
            fmt.Fprintln(w, "not_ready")
        }
    }).Methods("GET")

    // API v1
    apiV1 := router.PathPrefix("/v1").Subrouter()
    apiV1.Use(authService.Middleware())
    apiV1.Use(auditLogger.Middleware())

    apiV1.HandleFunc("/auth/token", authService.HandleToken).Methods("POST")
    apiV1.HandleFunc("/auth/refresh", authService.HandleRefresh).Methods("POST")
    apiV1.HandleFunc("/auth/revoke", authService.HandleRevoke).Methods("POST")
    apiV1.HandleFunc("/auth/introspect", authService.HandleIntrospect).Methods("GET")

    apiV1.HandleFunc("/policies", api.HandleListPolicies(db)).Methods("GET")
    apiV1.HandleFunc("/policies", api.HandleCreatePolicy(db, elector)).Methods("POST")
    apiV1.HandleFunc("/policies/{id}", api.HandleGetPolicy(db)).Methods("GET")
    apiV1.HandleFunc("/policies/{id}", api.HandleUpdatePolicy(db, elector)).Methods("PUT")
    apiV1.HandleFunc("/policies/{id}", api.HandleDeletePolicy(db, elector)).Methods("DELETE")
    apiV1.HandleFunc("/policies/{id}/validate", api.HandleValidatePolicy(db)).Methods("POST")

    apiV1.HandleFunc("/gateways", api.HandleListGateways(etcdStore)).Methods("GET")
    apiV1.HandleFunc("/gateways/register", api.HandleRegisterGateway(etcdStore)).Methods("POST")
    apiV1.HandleFunc("/gateways/heartbeat", api.HandleGatewayHeartbeat(etcdStore)).Methods("POST")

    apiV1.HandleFunc("/audit/events", api.HandleQueryAudit(db)).Methods("GET")
    apiV1.HandleFunc("/audit/events/export", api.HandleExportAudit(db)).Methods("POST")
    apiV1.HandleFunc("/audit/batch", api.HandleAuditBatch(db)).Methods("POST")

    // Public JWKS
    router.HandleFunc("/.well-known/jwks.json", authService.HandleJWKS).Methods("GET")

    server := &http.Server{
        Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
        Handler:      router,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    go func() {
        sugar.Infow("Server listening", "port", cfg.HTTPPort)
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            sugar.Fatalf("Server error: %v", err)
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    sugar.Info("Shutting down...")
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer shutdownCancel()

    if err := server.Shutdown(shutdownCtx); err != nil {
        sugar.Errorw("Forced shutdown", "error", err)
    }

    cancel()
    sugar.Info("Stopped")
}