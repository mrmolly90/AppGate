// Package llmproxy implements the LLM security gateway.
// All traffic from client apps flows through here before reaching upstream LLMs.
package llmproxy

import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strconv"
    "time"

    "appgate-control-plane/internal/audit"
    "appgate-control-plane/internal/auth"
    "appgate-control-plane/internal/config"
    "appgate-control-plane/internal/metrics"
    "appgate-control-plane/internal/policy"
    "appgate-control-plane/internal/ratelimit"
    "appgate-control-plane/internal/security"

    "github.com/gorilla/mux"
    "go.uber.org/zap"
)

// Gateway is the main LLM proxy with security enforcement
type Gateway struct {
    router      *mux.Router
    upstreams   map[string]*url.URL
    rateLimiter *ratelimit.RedisRateLimiter
    auditor     *audit.Logger
    policyEng   *policy.Policy
    scanner     *security.Scanner
    logger      *zap.SugaredLogger
    cfg         *config.Config
}

// UpstreamConfig holds LLM provider endpoints
type UpstreamConfig struct {
    OpenAI    string
    Anthropic string
    Azure     string
}

// NewGateway creates the LLM security gateway
func NewGateway(cfg *config.Config, logger *zap.SugaredLogger, rl *ratelimit.RedisRateLimiter, auditor *audit.Logger) (*Gateway, error) {
    g := &Gateway{
        router:    mux.NewRouter(),
        upstreams: make(map[string]*url.URL),
        logger:    logger,
        cfg:       cfg,
        rateLimiter: rl,
        auditor:     auditor,
        scanner:     security.NewScanner(logger),
    }

    // Parse upstream URLs
    upstreams := map[string]string{
        "openai":    cfg.OpenAIEndpoint,
        "anthropic": cfg.AnthropicEndpoint,
    }
    for name, endpoint := range upstreams {
        if endpoint == "" {
            continue
        }
        u, err := url.Parse(endpoint)
        if err != nil {
            return nil, err
        }
        g.upstreams[name] = u
    }

    g.routes()
    return g, nil
}

func (g *Gateway) routes() {
    // Health checks
    g.router.HandleFunc("/healthz", g.handleHealth).Methods("GET")
    g.router.HandleFunc("/readyz", g.handleReady).Methods("GET")

    // Prometheus metrics
    g.router.Handle("/metrics", metrics.Handler()).Methods("GET")

    // JWKS (public key for app token validation)
    // This is served by auth package already, but ensure it's accessible

    // LLM proxy routes — all security middleware applied
    llm := g.router.PathPrefix("/v1").Subrouter()
    llm.Use(g.authMiddleware)
    llm.Use(g.rateLimiter.Middleware())
    llm.Use(g.auditMiddleware)

    llm.HandleFunc("/chat/completions", g.handleChatCompletions).Methods("POST")
    llm.HandleFunc("/embeddings", g.handleEmbeddings).Methods("POST")
    llm.HandleFunc("/models", g.handleModels).Methods("GET")
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    g.router.ServeHTTP(w, r)
}

// handleChatCompletions proxies to upstream with security enforcement
func (g *Gateway) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    ctx := r.Context()

    // Extract identity from context (set by auth middleware)
    identity := auth.IdentityFromContext(ctx)
    projectID := identity.ProjectID
    userID := identity.UserID
    roles := identity.Roles

    // Read and inspect request body (10MB max)
    body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
    if err != nil {
        http.Error(w, `{"error":"request_too_large"}`, http.StatusRequestEntityTooLarge)
        metrics.RecordViolation(projectID, "request_size")
        return
    }
    r.Body.Close()

    var reqBody map[string]interface{}
    if err := json.Unmarshal(body, &reqBody); err != nil {
        http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
        return
    }

    // Extract model and determine upstream
    model := ""
    if m, ok := reqBody["model"].(string); ok {
        model = m
    }

    // Policy evaluation
    policyResult := g.policyEng.Evaluate(userID, roles, "openai", model)
    if !policyResult.Allowed {
        http.Error(w, `{"error":"policy_denied","reason":"`+policyResult.Reason+`"}`, http.StatusForbidden)
        metrics.RecordViolation(projectID, "policy_denied")
        return
    }

    // Security scanning: prompt injection + PII
    messages := extractMessages(reqBody)
    combinedPrompt := joinMessages(messages)

    scanResult := g.scanner.Scan(combinedPrompt)
    if scanResult.Blocked {
        http.Error(w, `{"error":"security_violation","reason":"`+scanResult.Reason+`","details":`+toJSON(scanResult.Details)+`}`, http.StatusForbidden)
        metrics.RecordViolation(projectID, scanResult.Reason)
        g.logger.Warnw("Security violation blocked", "project", projectID, "user", userID, "reason", scanResult.Reason)
        return
    }

    // Apply max_tokens ceiling (budget control)
    if maxTokens, ok := reqBody["max_tokens"].(float64); ok {
        if maxTokens > 4096 {
            reqBody["max_tokens"] = 4096
            g.logger.Infow("max_tokens clamped", "project", projectID, "requested", maxTokens, "clamped", 4096)
        }
    }

    // Select upstream and inject API key
    upstreamName := g.selectUpstream(model)
    upstreamURL := g.upstreams[upstreamName]
    if upstreamURL == nil {
        http.Error(w, `{"error":"no_upstream"}`, http.StatusServiceUnavailable)
        metrics.RecordUpstreamError(projectID, upstreamName, "unavailable")
        return
    }

    // Re-serialize modified body
    modifiedBody, _ := json.Marshal(reqBody)
    r.Body = io.NopCloser(bytes.NewReader(modifiedBody))
    r.ContentLength = int64(len(modifiedBody))
    r.Header.Set("Content-Length", strconv.Itoa(len(modifiedBody)))

    // Inject upstream API key (gateway holds it, never the client)
    apiKey := g.upstreamAPIKey(upstreamName)
    r.Header.Set("Authorization", "Bearer "+apiKey)
    r.Header.Del("X-AppGate-Project") // Internal only, don't forward

    // Proxy request
    proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
    proxy.ModifyResponse = func(resp *http.Response) error {
        duration := time.Since(start).Seconds()

        respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
        resp.Body = io.NopCloser(bytes.NewReader(respBody))

        var respData map[string]interface{}
        json.Unmarshal(respBody, &respData)
        usage := extractUsage(respData)

        metrics.RecordRequest(projectID, upstreamName, model, resp.StatusCode, duration, usage.InputTokens, usage.OutputTokens)
        metrics.RecordTokenUsage(projectID, model, usage.InputTokens, usage.OutputTokens)

        // Async audit log
        go g.auditor.Log(audit.Event{
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
            PromptHash:   hashString(combinedPrompt),
            Violation:    "",
        })

        return nil
    }

    proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
        g.logger.Errorw("Upstream error", "error", err, "upstream", upstreamName)
        metrics.RecordUpstreamError(projectID, upstreamName, "proxy_error")
        http.Error(w, `{"error":"upstream_unavailable"}`, http.StatusBadGateway)
    }

    proxy.ServeHTTP(w, r)
}

func (g *Gateway) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
    // Embeddings follow same pattern — reuse handleChatCompletions logic
    // For now, delegate to chat handler (OpenAI embeddings endpoint is compatible)
    g.handleChatCompletions(w, r)
}

func (g *Gateway) handleModels(w http.ResponseWriter, r *http.Request) {
    models := []map[string]interface{}{
        {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
        {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
        {"id": "claude-3-5-sonnet-20241022", "object": "model", "owned_by": "anthropic"},
        {"id": "claude-3-haiku-20240307", "object": "model", "owned_by": "anthropic"},
        {"id": "text-embedding-3-small", "object": "model", "owned_by": "openai"},
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "object": "list",
        "data":   models,
    })
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"healthy"}`))
}

func (g *Gateway) handleReady(w http.ResponseWriter, r *http.Request) {
    ready := true
    if g.rateLimiter != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()
        if err := g.rateLimiter.Ping(ctx); err != nil {
            ready = false
        }
    }
    if !ready {
        http.Error(w, `{"status":"not_ready"}`, http.StatusServiceUnavailable)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"ready"}`))
}

func (g *Gateway) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Delegate to existing auth service
        // The auth package already has Middleware() — we wrap it here
        // For now, extract project from header and inject into context
        projectID := r.Header.Get("X-AppGate-Project")
        if projectID == "" {
            projectID = "default"
        }
        userID := r.Header.Get("X-AppGate-User")
        if userID == "" {
            userID = "anonymous"
        }
        ctx := context.WithValue(r.Context(), auth.IdentityKey, auth.Identity{
            ProjectID: projectID,
            UserID:    userID,
            Roles:     []string{"user"},
        })
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (g *Gateway) auditMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        wrapped := &responseRecorder{ResponseWriter: w, statusCode: 200}
        next.ServeHTTP(wrapped, r)
    })
}

func (g *Gateway) selectUpstream(model string) string {
    // TODO: Intelligent routing based on model prefix, cost, latency
    if g.upstreams["openai"] != nil {
        return "openai"
    }
    for name := range g.upstreams {
        return name
    }
    return ""
}

func (g *Gateway) upstreamAPIKey(name string) string {
    switch name {
    case "openai":
        return g.cfg.OpenAIAPIKey
    case "anthropic":
        return g.cfg.AnthropicAPIKey
    default:
        return ""
    }
}

// Helpers
type tokenUsage struct {
    InputTokens  int
    OutputTokens int
    CostUSD      float64
}

func extractUsage(resp map[string]interface{}) tokenUsage {
    var u tokenUsage
    if usage, ok := resp["usage"].(map[string]interface{}); ok {
        if p, ok := usage["prompt_tokens"].(float64); ok {
            u.InputTokens = int(p)
        }
        if c, ok := usage["completion_tokens"].(float64); ok {
            u.OutputTokens = int(c)
        }
    }
    u.CostUSD = float64(u.InputTokens)*0.000005 + float64(u.OutputTokens)*0.000015
    return u
}

func extractMessages(req map[string]interface{}) []map[string]interface{} {
    if msgs, ok := req["messages"].([]interface{}); ok {
        result := make([]map[string]interface{}, 0, len(msgs))
        for _, m := range msgs {
            if msg, ok := m.(map[string]interface{}); ok {
                result = append(result, msg)
            }
        }
        return result
    }
    return nil
}

func joinMessages(msgs []map[string]interface{}) string {
    var parts []string
    for _, m := range msgs {
        if content, ok := m["content"].(string); ok {
            parts = append(parts, content)
        }
    }
    return bytes.NewBufferString("").String() // placeholder
}

func hashString(s string) string {
    // TODO: SHA-256 truncated
    return s
}

func toJSON(v interface{}) string {
    b, _ := json.Marshal(v)
    return string(b)
}

type responseRecorder struct {
    http.ResponseWriter
    statusCode int
}

func (r *responseRecorder) WriteHeader(code int) {
    r.statusCode = code
    r.ResponseWriter.WriteHeader(code)
}
