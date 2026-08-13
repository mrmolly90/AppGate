module appgate-control-plane

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/jackc/pgx/v5 v5.5.5
	github.com/prometheus/client_golang v1.19.0
	github.com/rs/cors v1.10.1
	github.com/rs/zerolog v1.32.0
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.24.0
	go.opentelemetry.io/otel/sdk v1.24.0
	golang.org/x/crypto v0.21.0
	gopkg.in/yaml.v3 v3.0.1
)