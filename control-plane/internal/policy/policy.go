package policy

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Policy represents an access control policy.
type Policy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
	Spec      PolicySpec `json:"spec"`
}

// PolicySpec is the core policy definition.
type PolicySpec struct {
	Name      string          `json:"name" yaml:"name"`
	Subjects  SubjectSelector `json:"subjects" yaml:"subjects"`
	Providers []string        `json:"providers" yaml:"providers"`
	Models    []string        `json:"models" yaml:"models"`
	Limits    RateLimits      `json:"limits" yaml:"limits"`
	Logging   LoggingConfig   `json:"logging" yaml:"logging"`
}

// SubjectSelector selects which identities this policy applies to.
type SubjectSelector struct {
	Roles  []string `json:"roles,omitempty" yaml:"roles,omitempty"`
	Users  []string `json:"users,omitempty" yaml:"users,omitempty"`
	Groups []string `json:"groups,omitempty" yaml:"groups,omitempty"`
}

// RateLimits define request rate constraints.
type RateLimits struct {
	RequestsPerMinute int `json:"requests_per_minute" yaml:"requests_per_minute"`
	TokensPerMinute   int `json:"tokens_per_minute,omitempty" yaml:"tokens_per_minute,omitempty"`
	ConcurrentLimit   int `json:"concurrent_limit,omitempty" yaml:"concurrent_limit,omitempty"`
}

// LoggingConfig controls what is logged for this policy.
type LoggingConfig struct {
	MetadataOnly        bool `json:"metadata_only" yaml:"metadata_only"`
	LogPrompts          bool `json:"log_prompts" yaml:"log_prompts"`
	LogResponses        bool `json:"log_responses" yaml:"log_responses"`
	RetentionDays       int  `json:"retention_days" yaml:"retention_days"`
}

// PolicyEvaluationResult is the result of evaluating a policy.
type PolicyEvaluationResult struct {
	Allowed      bool   `json:"allowed"`
	PolicyID     string `json:"policy_id,omitempty"`
	PolicyName   string `json:"policy_name,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// NewPolicy creates a new policy with default values.
func NewPolicy(name string, spec PolicySpec, createdBy string) *Policy {
	return &Policy{
		ID:        uuid.New().String(),
		Name:      name,
		Version:   1,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		CreatedBy: createdBy,
		Spec:      spec,
	}
}

// Validate checks that a policy spec is valid.
func (s *PolicySpec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("policy must have a name")
	}
	if len(s.Subjects.Roles) == 0 && len(s.Subjects.Users) == 0 && len(s.Subjects.Groups) == 0 {
		return fmt.Errorf("policy must have at least one subject selector")
	}
	if len(s.Providers) == 0 {
		return fmt.Errorf("policy must specify at least one provider")
	}
	if len(s.Models) == 0 {
		return fmt.Errorf("policy must specify at least one model")
	}
	if s.Limits.RequestsPerMinute <= 0 {
		return fmt.Errorf("requests_per_minute must be positive")
	}
	return nil
}

// Evaluate checks if a request matches this policy.
func (p *Policy) Evaluate(identityID string, roles []string, provider string, model string) *PolicyEvaluationResult {
	// Check subject match
	subjectMatch := false
	for _, role := range roles {
		for _, policyRole := range p.Spec.Subjects.Roles {
			if role == policyRole {
				subjectMatch = true
				break
			}
		}
	}
	if !subjectMatch {
		for _, user := range p.Spec.Subjects.Users {
			if identityID == user {
				subjectMatch = true
				break
			}
		}
	}
	if !subjectMatch {
		return &PolicyEvaluationResult{Allowed: false, Reason: "subject not matched"}
	}

	// Check provider
	providerMatch := false
	for _, p := range p.Spec.Providers {
		if provider == p {
			providerMatch = true
			break
		}
	}
	if !providerMatch {
		return &PolicyEvaluationResult{Allowed: false, Reason: "provider not allowed"}
	}

	// Check model
	modelMatch := false
	for _, m := range p.Spec.Models {
		if model == m {
			modelMatch = true
			break
		}
	}
	if !modelMatch {
		return &PolicyEvaluationResult{Allowed: false, Reason: "model not allowed"}
	}

	return &PolicyEvaluationResult{
		Allowed:    true,
		PolicyID:   p.ID,
		PolicyName: p.Name,
		Reason:     "allowed by policy",
	}
}