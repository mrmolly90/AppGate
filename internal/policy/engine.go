package policy

import (
    "encoding/json"
    "net/http"
    "regexp"
    "strings"

    "github.com/mrmolly90/appgate/internal/metrics"
    "github.com/rs/zerolog/log"
)

// Engine enforces security policies on LLM traffic
type Engine struct {
    config Config
}

type Config struct {
    PromptInjectionEnabled bool
    PromptInjectionThreshold float64
    PIIDetectionEnabled    bool
    PIIRedactionMode       string // mask | block | log
    MaxPromptLength        int
    BlockedPatterns        []string
}

func New(cfg Config) (*Engine, error) {
    return &Engine{config: cfg}, nil
}

func (e *Engine) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Only inspect POST bodies (chat completions, embeddings)
        if r.Method != "POST" {
            next.ServeHTTP(w, r)
            return
        }

        // Read body for inspection
        // NOTE: In production, use a TeeReader to avoid double-read
        // For now, rely on proxy handler doing the heavy lifting
        
        next.ServeHTTP(w, r)
    })
}

// InspectPrompt runs all security checks on a prompt string
func (e *Engine) InspectPrompt(projectID, prompt string) (bool, string, map[string]interface{}) {
    violations := make(map[string]interface{})
    
    // 1. Prompt Injection Detection (heuristic + pattern)
    if e.config.PromptInjectionEnabled {
        score := e.detectPromptInjection(prompt)
        if score > e.config.PromptInjectionThreshold {
            violations["prompt_injection"] = map[string]interface{}{
                "score": score,
                "matched_patterns": e.matchInjectionPatterns(prompt),
            }
            metrics.RecordPolicyViolation(projectID, "prompt_injection")
            log.Warn().Str("project", projectID).Float64("score", score).Msg("prompt injection detected")
            return false, "prompt_injection_detected", violations
        }
    }

    // 2. PII Detection
    if e.config.PIIDetectionEnabled {
        piiFound := e.detectPII(prompt)
        if len(piiFound) > 0 {
            violations["pii_detected"] = piiFound
            metrics.RecordPolicyViolation(projectID, "pii")
            
            switch e.config.PIIRedactionMode {
            case "block":
                return false, "pii_blocked", violations
            case "mask":
                // Return redacted version
                return true, "pii_masked", violations
            case "log":
                // Allow but log
                log.Warn().Str("project", projectID).Interface("pii", piiFound).Msg("pii detected in prompt")
            }
        }
    }

    // 3. Length check
    if e.config.MaxPromptLength > 0 && len(prompt) > e.config.MaxPromptLength {
        return false, "prompt_too_long", violations
    }

    return true, "ok", violations
}

// detectPromptInjection returns a 0.0-1.0 confidence score
func (e *Engine) detectPromptInjection(prompt string) float64 {
    score := 0.0
    lower := strings.ToLower(prompt)
    
    // Known injection markers
    markers := []string{
        "ignore previous instructions",
        "ignore your previous",
        "disregard all prior",
        "system override",
        "you are now in",
        "new instruction:",
        "developer mode",
        "jailbreak",
        "DAN mode",
        "do anything now",
    }
    
    for _, marker := range markers {
        if strings.Contains(lower, marker) {
            score += 0.3
        }
    }
    
    // Delimiter abuse (common in injection)
    if strings.Count(prompt, "\"") > 20 || strings.Count(prompt, "'") > 20 {
        score += 0.2
    }
    
    // Excessive newlines (layering attacks)
    if strings.Count(prompt, "\n") > 10 {
        score += 0.1
    }
    
    if score > 1.0 {
        score = 1.0
    }
    return score
}

func (e *Engine) matchInjectionPatterns(prompt string) []string {
    var matched []string
    lower := strings.ToLower(prompt)
    
    patterns := map[string]string{
        "ignore_instructions": `ignore\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions|commands|directions)`,
        "system_override":     `system\s*(?:override|prompt|instruction)`,
        "role_change":         `you\s+are\s+now\s+(?:a|an|in)\s+`,
    }
    
    for name, pattern := range patterns {
        re := regexp.MustCompile(`(?i)` + pattern)
        if re.MatchString(prompt) {
            matched = append(matched, name)
        }
    }
    return matched
}

func (e *Engine) detectPII(prompt string) map[string][]string {
    found := make(map[string][]string)
    
    // Regex patterns for common PII
    patterns := map[string]*regexp.Regexp{
        "ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
        "email":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
        "phone":       regexp.MustCompile(`\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b`),
        "credit_card": regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`),
        "api_key":     regexp.MustCompile(`\b(?:sk-|pk-|Bearer\s)[A-Za-z0-9_-]{20,}\b`),
    }
    
    for category, re := range patterns {
        matches := re.FindAllString(prompt, -1)
        if len(matches) > 0 {
            found[category] = matches
        }
    }
    
    return found
}

func (e *Engine) RedactPII(prompt string, pii map[string][]string) string {
    result := prompt
    for _, matches := range pii {
        for _, match := range matches {
            result = strings.Replace(result, match, "[REDACTED]", -1)
        }
    }
    return result
}
