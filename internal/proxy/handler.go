package proxy

import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httputil"
    "net/url"
    "time"

    "github.com/gorilla/mux"
    "github.com/mrmolly90/appgate/internal/audit"
    "github.com/mrmolly90/appgate/internal/auth"
    "github.com/mrmolly90/appgate/internal/metrics"
    "github.com/mrmolly90/appgate/internal/policy"
    "github.com/mrmolly90/appgate/internal/ratelimit"
    "github.com/rs/zerolog/log"
)

// LLMProxy is the main gateway handler
type LLMProxy struct {
    router      *mux.Router
    upstreams   map[string]*url.URL
    rateLimiter *ratelimit.Limiter
    auditor     *audit.Logger
    policyEng   *policy.Engine
    authz       *auth.JWTValidator
}

// NewLLMProxy creates the gateway
func NewLLMProxy(cfg Config) (*LLMProxy, error) {
    p := &LLMProxy{
        router:    mux.NewRouter(),
        upstreams: make(map[string]*url.URL),
    }

    // Initialize upstream URLs
    for name, endpoint := range cfg.Upstreams {
        u, err := url.Parse(endpoint)
        if err != nil {
            return nil, err
        }
        p.upstreams[name] = u
    }

    // Initialize subsystems
    var err error
    p.rateLimiter, err = ratelimit.New(cfg.RedisAddr, cfg.RedisPassword)
    if err != nil {
        return nil, err
    }
    p.auditor, err = audit.New(cfg.PGDSN)
    if err != nil {
        return nil, err
    }
    p.policyEng, err = policy.New(cfg.PolicyConfig)
    if err != nil {
        return nil, err
    }
    p.authz, err = auth.NewJWTValidator(cfg.JWTPublicKey)
    if err != nil {
        return nil, err
    }

    // Register routes
    p.routes()
    return p, nil
}

func (p *LLMProxy) routes() {
    // Health checks (no auth)
    p.router.HandleFunc("/healthz", p.handleHealth).Methods("GET")
    p.router.HandleFunc("/readyz", p.handleReady).Methods("GET")

    // Metrics (no auth, Prometheus scrapes)
    p.router.Handle("/metrics", metrics.Handler()).Methods("GET")

    // LLM proxy routes (auth required)
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

// handleChatCompletions proxies to upstream LLM with full governance
func (p *LLMProxy) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    ctx := r.Context()

    // Extract project/team from JWT claims
    claims := auth.ClaimsFromContext(ctx)
    projectID := claims.ProjectID
    userID := claims.UserID

    // Parse and inspect request body
    body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB max
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

    // Apply token quota ceiling
    if maxTokens, ok := reqBody["max_tokens"].(float64); ok {
        if maxTokens > 4096 {
            reqBody["max_tokens"] = 4096 // Hard ceiling
            log.Ctx(ctx).Info().Str("project", projectID).Float64("requested", maxTokens).Msg("max_tokens clamped")
        }
    }

    // Model routing: select upstream based on preference + policy
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

    // Re-serialize modified body
    modifiedBody, _ := json.Marshal(reqBody)
    r.Body = io.NopCloser(bytes.NewReader(modifiedBody))
    r.ContentLength = int64(len(modifiedBody))
    r.Header.Set("Content-Length", string(len(modifiedBody)))

    // Inject upstream API key (gateway holds it, not the client)
    r.Header.Set("Authorization", "Bearer "+p.upstreamAPIKey(upstreamName))
    r.Header.Del("X-AppGate-Project") // Internal header, don't forward

    // Proxy the request
    proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
    proxy.ModifyResponse = func(resp *http.Response) error {
        duration := time.Since(start).Seconds()
        
        // Parse response for audit
        respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
        resp.Body = io.NopCloser(bytes.NewReader(respBody))

        var respData map[string]interface{}
        json.Unmarshal(respBody, &respData)

        usage := extractUsage(respData)
        
        // Record metrics
        metrics.RecordRequest(projectID, upstreamName, model, resp.StatusCode, duration, usage.InputTokens, usage.OutputTokens)
        
        // Audit log
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
    // Similar pattern to chat completions
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
    // Check dependencies
    if !p.rateLimiter.Ping() || !p.auditor.Ping() {
        http.Error(w, `{"status":"not ready"}`, http.StatusServiceUnavailable)
        return
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status":"ready"}`))
}

func (p *LLMProxy) auditMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Wrap response writer to capture status code
        wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
        next.ServeHTTP(wrapped, r)
    })
}

func (p *LLMProxy) selectUpstream(model, projectID string) string {
    // TODO: Implement intelligent routing based on:
    // - Project budget remaining
    // - Model availability
    // - Latency requirements
    // - Cost optimization
    // For now, default to OpenAI
    if _, ok := p.upstreams["openai"]; ok {
        return "openai"
    }
    for name := range p.upstreams {
        return name
    }
    return ""
}

func (p *LLMProxy) upstreamAPIKey(name string) string {
    // TODO: Load from env/secrets
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
    // Rough cost estimation
    u.CostUSD = float64(u.InputTokens)*0.000005 + float64(u.OutputTokens)*0.000015
    return u
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func getEnv(key, fallback string) string {
    // TODO: implement
    return fallback
}

type Config struct {
    RedisAddr     string
    RedisPassword string
    PGDSN         string
    JWTPublicKey  string
    PolicyConfig  policy.Config
    Upstreams     map[string]string
}
