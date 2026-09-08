package audit

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logger writes immutable audit records to Postgres asynchronously.
// Events are pushed to a buffered channel and flushed by a background
// worker in batches, so the request path never blocks on DB I/O.
type Logger struct {
	pool    *pgxpool.Pool
	events  chan Event
	logger  zerolog.Logger
	done    chan struct{}
	stopped bool
}

// Event represents a single immutable audit record.
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

const (
	batchSize     = 100
	queueCapacity = 10000
)

// New creates an audit logger. If dsn is empty, events are written to
// stdout as a fallback so the caller can still function in dev mode.
func New(dsn string) (*Logger, error) {
	l := &Logger{
		events: make(chan Event, queueCapacity),
		done:   make(chan struct{}),
		logger: log.With().Str("component", "audit").Logger(),
	}

	if dsn == "" {
		l.logger.Warn().Msg("audit logger initialized without database, stdout fallback")
		go l.run(nil)
		return l, nil
	}

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	l.pool = pool
	go l.run(pool)
	return l, nil
}

func (l *Logger) run(pool *pgxpool.Pool) {
	batch := make([]Event, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if pool == nil {
			for _, e := range batch {
				l.logToStdout(e)
			}
		} else {
			l.insertBatch(context.Background(), batch)
		}
		batch = batch[:0]
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case e, ok := <-l.events:
			if !ok {
				flush()
				close(l.done)
				return
			}
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (l *Logger) insertBatch(ctx context.Context, events []Event) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		l.logger.Error().Err(err).Msg("audit batch begin failed")
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	rows := make([][]interface{}, 0, len(events))
	for _, e := range events {
		rows = append(rows, []interface{}{
			e.Timestamp, e.ProjectID, e.UserID, e.RequestID, e.Model,
			e.Upstream, e.StatusCode, e.LatencyMs, e.InputTokens,
			e.OutputTokens, e.CostUSD, e.PromptHash, e.ResponseHash,
			e.Violation,
		})
	}

	_, err = tx.CopyFrom(ctx,
		pgx.Identifier{"audit_events"},
		[]string{"timestamp", "project_id", "user_id", "request_id", "model",
			"upstream", "status_code", "latency_ms", "input_tokens",
			"output_tokens", "cost_usd", "prompt_hash", "response_hash", "violation"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		l.logger.Error().Err(err).Int("events", len(events)).Msg("audit batch insert failed")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		l.logger.Error().Err(err).Msg("audit batch commit failed")
	}
}

func (l *Logger) Log(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	select {
	case l.events <- e:
	default:
		l.logger.Warn().Str("project", e.ProjectID).Msg("audit queue full, dropping event")
	}
}

func (l *Logger) logToStdout(e Event) {
	l.logger.Info().
		Str("project", e.ProjectID).
		Str("user", e.UserID).
		Str("request_id", e.RequestID).
		Str("model", e.Model).
		Str("upstream", e.Upstream).
		Int("status", e.StatusCode).
		Int("latency_ms", e.LatencyMs).
		Int("input_tokens", e.InputTokens).
		Int("output_tokens", e.OutputTokens).
		Float64("cost_usd", e.CostUSD).
		Str("prompt_hash", e.PromptHash).
		Str("response_hash", e.ResponseHash).
		Str("violation", e.Violation).
		Msg("audit")
}

func (l *Logger) Ping() bool {
	if l.pool == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return l.pool.Ping(ctx) == nil
}

func (l *Logger) Close() {
	if l.stopped {
		return
	}
	l.stopped = true
	close(l.events)
	select {
	case <-l.done:
	case <-time.After(5 * time.Second):
		l.logger.Warn().Msg("audit logger close timed out")
	}
	if l.pool != nil {
		l.pool.Close()
	}
}
