// =============================================================================
// AppGate Control Plane — Configuration
// =============================================================================
//
// Viper-based configuration loading with environment variable overrides.
// Supports YAML config files and env vars for 12-factor app compliance.
// =============================================================================

package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the control plane.
type Config struct {
	// HTTP server
	HTTPPort int `mapstructure:"http_port"`

	// etcd
	EtcdEndpoints   []string      `mapstructure:"etcd_endpoints"`
	EtcdDialTimeout time.Duration `mapstructure:"etcd_dial_timeout"`

	// Leader election
	LeaderElectionKey string `mapstructure:"leader_election_key"`
	InstanceID        string `mapstructure:"instance_id"`

	// Rate limiting
	RateLimitPerSecond int `mapstructure:"rate_limit_per_second"`
	RateLimitBurst     int `mapstructure:"rate_limit_burst"`

	// Kubernetes operator
	EnableOperator bool   `mapstructure:"enable_operator"`
	KubeConfigPath string `mapstructure:"kube_config_path"`

	// Observability
	OTLPEndpoint string `mapstructure:"otlp_endpoint"`
	LogLevel     string `mapstructure:"log_level"`
}

// Load loads configuration from file and environment variables.
func Load() (*Config, error) {
	v := viper.New()

	// Default values
	v.SetDefault("http_port", 8080)
	v.SetDefault("etcd_endpoints", []string{"localhost:2379"})
	v.SetDefault("etcd_dial_timeout", 5*time.Second)
	v.SetDefault("leader_election_key", "/appgate/leader")
	v.SetDefault("instance_id", fmt.Sprintf("control-plane-%d", time.Now().UnixNano()))
	v.SetDefault("rate_limit_per_second", 100)
	v.SetDefault("rate_limit_burst", 200)
	v.SetDefault("enable_operator", false)
	v.SetDefault("kube_config_path", "")
	v.SetDefault("otlp_endpoint", "http://otel-collector:4317")
	v.SetDefault("log_level", "info")

	// Config file
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/appgate/")
	v.AddConfigPath(".")

	// Environment variables
	v.SetEnvPrefix("APPGATE")
	v.AutomaticEnv()

	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
