// Package security implements prompt security scanning.
// Detects prompt injection, PII leakage, and toxic content.
package security

import (
    "regexp"
    "strings"

    "go.uber.org/zap"
)

// Scanner performs security analysis on LLM prompts
type Scanner struct {
    logger *zap.SugaredLogger
    config ScanConfig
}

type ScanConfig struct {
    PromptInjectionEnabled bool
    PromptInjectionThreshold float64
    PIIDetectionEnabled    bool
    PIIRedactionMode       string // mask | block | log
    MaxPromptLength        int
    BlockedPatterns        []string
}

type Result struct {
    Blocked bool
    Reason  string
    Details map[string]interface{}
}

func NewScanner(logger *zap.SugaredLogger) *Scanner {
    return &Scanner{
        logger: logger,
        config: ScanConfig{
            PromptInjectionEnabled:     true,
            PromptInjectionThreshold:   0.5,
            PIIDetectionEnabled:        true,
            PIIRedactionMode:          "block",
            MaxPromptLength:           100000,
            BlockedPatterns:           []string{},
        },
    }
}

func (s *Scanner) Scan(prompt string) Result {
    // 1. Length check
    if s.config.MaxPromptLength > 0 && len(prompt) > s.config.MaxPromptLength {
        return Result{Blocked: true, Reason: "prompt_too_long", Details: map[string]interface{}{
            "max_allowed": s.config.MaxPromptLength,
            "actual":      len(prompt),
        }}
    }

    // 2. Prompt injection detection
    if s.config.PromptInjectionEnabled {
        score := s.detectInjection(prompt)
        if score >= s.config.PromptInjectionThreshold {
            matched := s.matchInjectionPatterns(prompt)
            return Result{Blocked: true, Reason: "prompt_injection", Details: map[string]interface{}{
                "score":    score,
                "patterns": matched,
            }}
        }
    }

    // 3. PII detection
    if s.config.PIIDetectionEnabled {
        pii := s.detectPII(prompt)
        if len(pii) > 0 {
            switch s.config.PIIRedactionMode {
            case "block":
                return Result{Blocked: true, Reason: "pii_detected", Details: pii}
            case "log":
                s.logger.Warnw("PII detected in prompt", "pii_types", pii)
            }
        }
    }

    // 4. Blocked custom patterns
    for _, pattern := range s.config.BlockedPatterns {
        if strings.Contains(strings.ToLower(prompt), strings.ToLower(pattern)) {
            return Result{Blocked: true, Reason: "blocked_pattern", Details: map[string]interface{}{"pattern": pattern}}
        }
    }

    return Result{Blocked: false, Reason: "ok"}
}

func (s *Scanner) detectInjection(prompt string) float64 {
    score := 0.0
    lower := strings.ToLower(prompt)

    // Known injection markers (weighted by severity)
    markers := map[string]float64{
        "ignore previous instructions": 0.4,
        "ignore your previous":         0.4,
        "disregard all prior":          0.4,
        "system override":              0.35,
        "you are now in":               0.3,
        "new instruction:":             0.3,
        "developer mode":               0.25,
        "jailbreak":                    0.3,
        "dan mode":                     0.3,
        "do anything now":              0.3,
        "ignore the above":             0.25,
        "forget everything":            0.25,
        "roleplay as":                  0.15,
        "simulate":                     0.1,
        "pretend to be":                0.1,
    }

    for marker, weight := range markers {
        if strings.Contains(lower, marker) {
            score += weight
        }
    }

    // Structural heuristics
    if strings.Count(prompt, "\"") > 20 || strings.Count(prompt, "'") > 20 {
        score += 0.15
    }
    if strings.Count(prompt, "\n") > 15 {
        score += 0.1
    }
    if strings.Count(prompt, "```") > 2 {
        score += 0.1
    }

    if score > 1.0 {
        score = 1.0
    }
    return score
}

func (s *Scanner) matchInjectionPatterns(prompt string) []string {
    var matched []string
    lower := strings.ToLower(prompt)

    patterns := map[string]string{
        "ignore_instructions": `ignore\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|commands?|directions?)`,
        "system_override":     `system\s*(?:override|prompt|instruction)`,
        "role_change":         `you\s+are\s+now\s+(?:a|an|in)\s+`,
        "delimiter_abuse":     `["']\s*>\s*["']`,
    }

    for name, pattern := range patterns {
        re := regexp.MustCompile(`(?i)` + pattern)
        if re.MatchString(prompt) {
            matched = append(matched, name)
        }
    }
    return matched
}

func (s *Scanner) detectPII(prompt string) map[string][]string {
    found := make(map[string][]string)

    patterns := map[string]*regexp.Regexp{
        "ssn":         regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`),
        "email":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
        "phone_us":    regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
        "credit_card": regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`),
        "api_key":     regexp.MustCompile(`\b(?:sk-|pk-|Bearer\s)[A-Za-z0-9_-]{20,}\b`),
        "ip_address":  regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
    }

    for category, re := range patterns {
        matches := re.FindAllString(prompt, -1)
        if len(matches) > 0 {
            found[category] = matches
        }
    }

    return found
}

func (s *Scanner) RedactPII(prompt string) string {
    pii := s.detectPII(prompt)
    result := prompt
    for _, matches := range pii {
        for _, match := range matches {
            result = strings.Replace(result, match, "[REDACTED]", -1)
        }
    }
    return result
}
