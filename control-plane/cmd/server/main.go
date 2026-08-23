// =============================================================================
// AppGate Control Plane — Main Entry Point
// =============================================================================
//
// Architecture:
//   - gRPC API with protobuf definitions
//   - etcd as configuration store with watch patterns
//   - Kubernetes operator pattern for CRD management
//   - Leader election for control plane HA
//   - Structured logging with zap + OpenTelemetry tracing
//   - Circuit breaker pattern for downstream calls
//   - Rate limiting with token bucket algorithm
// =============================================================================

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"appgate-control-plane/internal/config"
	"appgate-control-plane/internal/leader"
	"appgate-control-plane/internal/operator"
	"appgate-control-plane/internal/ratelimit"
	"appgate-control-plane/internal/store"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Version   = "0.2.0"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// ── Structured logger ─────────────────────────────────────────
	logger, _ := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapcore.InfoLevel),
		Encoding:         "json",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}.Build()
	defer logger.Sync()

	sugar := logger.Sugar()

	// ── Load configuration ────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		sugar.Fatalf("Failed to load config: %v", err)
	}

	sugar.Infow("Starting AppGate Control Plane",
		"version", Version,
		"commit", Commit,
		"build_time", BuildTime,
		"go_version", runtime.Version(),
		"etcd_endpoints", cfg.EtcdEndpoints,
	)

	// ── Context with graceful shutdown ────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Initialize etcd store ─────────────────────────────────────
	etcdStore, err := store.NewEtcdStore(ctx, cfg.EtcdEndpoints, cfg.EtcdDialTimeout)
	if err != nil {
		sugar.Fatalf("Failed to connect to etcd: %v", err)
	}
	defer etcdStore.Close()

	// ── Leader election ───────────────────────────────────────────
	elector, err := leader.NewElector(etcdStore.Client(), cfg.LeaderElectionKey, cfg.InstanceID)
	if err != nil {
		sugar.Fatalf("Failed to create leader elector: %v", err)
	}

	go elector.Run(ctx)
	sugar.Info("Leader election started")

	// ── Rate limiter ──────────────────────────────────────────────
	rateLimiter := ratelimit.NewTokenBucket(cfg.RateLimitPerSecond, cfg.RateLimitBurst)

	// ── Kubernetes operator ───────────────────────────────────────
	if cfg.EnableOperator {
		mgr, err := operator.NewManager(cfg)
		if err != nil {
			sugar.Warnw("Failed to create operator manager (non-fatal)", "error", err)
		} else {
			go func() {
				if err := mgr.Start(ctx); err != nil {
					sugar.Errorw("Operator manager stopped", "error", err)
				}
			}()
			sugar.Info("Kubernetes operator started")
		}
	}

	// ── HTTP server with pprof ────────────────────────────────────
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Readiness check
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if elector.IsLeader() {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ready")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "not leader")
		}
	})

	// pprof endpoints (debugging)
	mux.HandleFunc("/debug/pprof/", http.DefaultServeMux.ServeHTTP)

	// API routes
	mux.Handle("/v1/", apiHandler(cfg, etcdStore, rateLimiter, elector, sugar))

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ── Graceful shutdown ─────────────────────────────────────────
	go func() {
		sugar.Infow("HTTP server listening", "port", cfg.HTTPPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	sugar.Infow("Shutting down", "signal", sig.String())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		sugar.Errorw("HTTP server forced shutdown", "error", err)
	}

	sugar.Info("Control plane stopped")
}

func apiHandler(
	cfg *config.Config,
	etcdStore *store.EtcdStore,
	rateLimiter *ratelimit.TokenBucket,
	elector *leader.Elector,
	logger *zap.SugaredLogger,
) http.Handler {
	mux := http.NewServeMux()

	// Policy CRUD
	mux.HandleFunc("/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement policy CRUD handlers
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"policies":[]}`)
	})

	// Audit events
	mux.HandleFunc("/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"events":[]}`)
	})

	return mux
}
