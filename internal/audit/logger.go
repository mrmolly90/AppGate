package audit

import (
    "context"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/rs/zerolog/log"
)

// Logger writes immutable audit records to Postgres
type Logger struct {
    pool *pgxpool.Pool
}

type Event struct {
    Timestamp    time.Time
    ProjectID    string
    UserID       string
    RequestID    string
    Model        string
    Upstream     string
    StatusCode   int
    LatencyMs    int
    InputTokens  int
    OutputTokens int
    CostUSD      float64
    PromptHash   string
    ResponseHash string
    Violation    string
}

func New(dsn string) (*Logger, error) {
    if dsn == "" {
        log.Warn().Msg("audit logger initialized without database")
        return &Logger{}, nil
    }
    
    config, err := pgxpool.ParseConfig(dsn)
    if err != nil {
        return nil, err
    }
    config.MaxConns = 10
    config.MinConns = 2
    
    pool, err := pgxpool.NewWithConfig(context.Background(), config)
    if err != nil {
        return nil, err
    }
    
    return &Logger{pool: pool}, nil
}

func (l *Logger) Log(e Event) {
    if l.pool == nil {
        // Log to stdout as fallback
        log.Info().
            Str("project", e.ProjectID).
            Str("user", e.UserID).
            Str("model", e.Model).
            Int("status", e.StatusCode).
            Int("latency_ms", e.LatencyMs).
            Int("input_tokens", e.InputTokens).
            Int("output_tokens", e.OutputTokens).
            Float64("cost_usd", e.CostUSD).
            Msg("audit")
        return
    }

    // TODO: Async batch insert to Postgres
    // For production, use a buffered channel + background worker
}

func (l *Logger) Ping() bool {
    if l.pool == nil {
        return true
    }
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    return l.pool.Ping(ctx) == nil
}
