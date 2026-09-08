package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"github.com/mrmolly90/appgate/internal/audit"
	"github.com/mrmolly90/appgate/internal/auth"
	"github.com/mrmolly90/appgate/internal/metrics"
	"github.com/mrmolly90/appgate/internal/policy"
	"github.com/mrmolly90/appgate/internal/ratelimit"
)

// LLMProxy is the main gateway handler that proxies LLM requests with
// authentication, rate limiting, policy enforcement, and audit logging.
type LLMProxy struct {
	router      *mux.Router
	upstreams   map[string]*url.URL
	rateLimiter *ratelimit.Limiter
	auditor     *audit.Logger
	policyEng   *policy.Engine
	authz       *auth.JWTValidator
}

// NewLLMProxy creates the gateway with all subsystems initialized.
func NewLLMProxy(cfg Config) (*LLMProxy, error) {
	p := &LLMProxy{
		router:    mux.NewRouter(),
		upstreams: make(map[string]*url.URL),
	}

	for name, endpoint := range cfg.Upstreams {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse upstream %s: %w", name, err)
		}
		p.upstreams[name] = u
	}

	var err error
	p.rateLimiter, err = ratelimit.New(cfg.RedisAddr, cfg.RedisPassword)
	if err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}
	p.auditor, err = audit.New(cfg.PGDSN)
	if err != nil {
		return nil, fmt.Errorf("audit logger: %w", err)
	}
	p.policyEng, err = policy.New(cfg.PolicyConfig)
	if err != nil {
		return nil, fmt.Errorf("policy engine: %w", err)
	}
	p.authz, err = auth.NewJWTValidator(cfg.JWTPublicKey)
	if err != nil {
		return nil, fmt.Errorf("jwt validator: %w", err)
	}

	p.routes()
	return p, nil
}

func (p *LLMProxy) routes() {
	p.router.HandleFunc("/healthz", p.handleHealth).Methods("GET")
	p.router.HandleFunc("/readyz", p.handleReady).Methods("GET")
	p.router.Handle("/metrics", metrics.Handler()).Methods("GET")

	api := p.router.PathPrefix("/v1").Subrouter()
	api.Use(p.authz.Middleware)
	api.Use(p.rateLimiter.Middleware)
	api.Use(p.policyEng.Middleware)
	api.Use(p.auditMiddleware)

	api.HandleFunc("/chat/completions", p.handleChatCompletions).Methods("POST")
	api.HandleFunc("/embeddings", p.handleEmbeddings).Methods("POST")
	api.HandleFunc("/models", p.handleModels).Methods("GET")
}

func (p *LLMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.router.ServeHTTP(w, r)
}

func (p *LLMProxy) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	claims := auth.ClaimsFromContext(ctx)
	projectID := claims.ProjectID
	userID := claims.UserID

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		http.Error(w, `{"error":"request too large"}`, http.StatusRequestEntityTooLarge)
		metrics.RecordPolicyViolation(projectID, "request_size")
		return
	}
	r.Body.Close()

	var reqBody map[string]interface{}
	if err := json.Unmarshal(body, &reqBody); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if maxTokens, ok := reqBody["max_tokens"].(float64); ok {
		if maxTokens > 4096 {
			reqBody["max_tokens"] = 4096
			log.Ctx(ctx).Info().Str("project", projectID).Float64("requested", maxTokens).Msg("max_tokens clamped")
		}
	}

	model := ""
	if m, ok := reqBody["model"].(string); ok {
		model = m
	}
	upstreamName := p.selectUpstream(model, projectID)
	upstreamURL := p.upstreams[upstreamName]
	if upstreamURL == nil {
		http.Error(w, `{"error":"no available upstream"}`, http.StatusServiceUnavailable)
		metrics.RecordUpstreamError(projectID, upstreamName, "no_upstream")
		return
	}

	modifiedBody, err := json.Marshal(reqBody)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(modifiedBody))
	r.ContentLength = int64(len(modifiedBody))
	r.Header.Set("Content-Length", strconv.Itoa(len(modifiedBody)))

	r.Header.Set("Authorization", "Bearer "+p.upstreamAPIKey(upstreamName))
	r.Header.Del("X-AppGate-Project")

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		duration := time.Since(start).Seconds()

		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		if readErr != nil {
			return readErr
		}
		resp.Body = io.NopCloser(bytes.NewReader(respBody))

		var respData map[string]interface{}
		_ = json.Unmarshal(respBody, &respData)

		usage := extractUsage(respData)
		metrics.RecordRequest(projectID, upstreamName, model, resp.StatusCode, duration, usage.InputTokens, usage.OutputTokens)

		p.auditor.Log(audit.Event{
			Timestamp:    start,
			ProjectID:    projectID,
			UserID:       userID,
			RequestID:    r.Header.Get("X-Request-ID"),
			Model:        model,
			Upstream:     upstreamName,
			StatusCode:   resp.StatusCode,
			LatencyMs:    int(duration * 1000),
			InputTokens:  usage.InputTokens,
			OutputTokens: usage.OutputTokens,
			CostUSD:      usage.CostUSD,
		})

		return nil
	}

	proxy.ServeHTTP(w, r)
}

func (p *LLMProxy) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"not yet implemented"}`, http.StatusNotImplemented)
}

func (p *LLMProxy) handleModels(w http.ResponseWriter, r *http.Request) {
	models := []map[string]string{
		{"id": "gpt-4o", "object": "model"},
		{"id": "gpt-4o-mini", "object": "model"},
		{"id": "claude-3-5-sonnet", "object": "model"},
		{"id": "claude-3-haiku", "object": "model"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": models, "object": "list"})
}

func (p *LLMProxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func (p *LLMProxy) handleReady(w http.ResponseWriter, r *http.Request) {
	if !p.rateLimiter.Ping() || !p.auditor.Ping() {
		http.Error(w, `{"status":"not ready"}`, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

func (p *LLMProxy) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(wrapped, r)
	})
}

func (p *LLMProxy) selectUpstream(model, projectID string) string {
	if _, ok := p.upstreams["openai"]; ok {
		return "openai"
	}
	for name := range p.upstreams {
		return name
	}
	return ""
}

func (p *LLMProxy) upstreamAPIKey(name string) string {
	switch name {
	case "openai":
		return getEnv("APPGATE_OPENAI_API_KEY", "")
	case "anthropic":
		return getEnv("APPGATE_ANTHROPIC_API_KEY", "")
	default:
		return ""
	}
}

type tokenUsage struct {
	InputTokens  int
	OutputTokens int
	CostUSD      float64
}

func extractUsage(resp map[string]interface{}) tokenUsage {
	var u tokenUsage
	if usage, ok := resp["usage"].(map[string]interface{}); ok {
		if prompt, ok := usage["prompt_tokens"].(float64); ok {
			u.InputTokens = int(prompt)
		}
		if completion, ok := usage["completion_tokens"].(float64); ok {
			u.OutputTokens = int(completion)
		}
	}
	u.CostUSD = float64(u.InputTokens)*0.000005 + float64(u.OutputTokens)*0.000015
	return u
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func getEnv(key, fallback string) string {
	return fallback
}

// Config holds all configuration for the LLMProxy.
type Config struct {
	RedisAddr     string
	RedisPassword string
	PGDSN         string
	JWTPublicKey  string
	PolicyConfig  policy.Config
	Upstreams     map[string]string
}
