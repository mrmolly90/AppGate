// =============================================================================
// AppGate Control Plane — Configuration (Production)
// =============================================================================

package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	HTTPPort           int           `mapstructure:"http_port"`
	EtcdEndpoints      []string      `mapstructure:"etcd_endpoints"`
	EtcdDialTimeout    time.Duration `mapstructure:"etcd_dial_timeout"`
	LeaderElectionKey  string        `mapstructure:"leader_election_key"`
	InstanceID         string        `mapstructure:"instance_id"`
	RateLimitPerSecond int           `mapstructure:"rate_limit_per_second"`
	RateLimitBurst     int           `mapstructure:"rate_limit_burst"`
	EnableOperator     bool          `mapstructure:"enable_operator"`
	KubeConfigPath     string        `mapstructure:"kube_config_path"`
	OTLPEndpoint       string        `mapstructure:"otlp_endpoint"`
	LogLevel           string        `mapstructure:"log_level"`
	TLSCertPath        string        `mapstructure:"tls_cert_path"`
	TLSKeyPath         string        `mapstructure:"tls_key_path"`
	RedisURL           string        `mapstructure:"redis_url"`
	DatabaseURL        string        `mapstructure:"database_url"`
}

func Load() (*Config, error) {
	v := viper.New()

	v.SetDefault("http_port", 8080)
	v.SetDefault("grpc_port", 9090)
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
	v.SetDefault("tls_cert_path", "/etc/appgate/tls/cert.pem")
	v.SetDefault("tls_key_path", "/etc/appgate/tls/key.pem")
	v.SetDefault("redis_url", "redis://localhost:6379")
	v.SetDefault("database_url", "postgres://localhost:5432/appgate")

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/appgate/")
	v.AddConfigPath(".")

	v.SetEnvPrefix("APPGATE")
	v.AutomaticEnv()

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
