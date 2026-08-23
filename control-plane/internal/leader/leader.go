package leader

import (
    "context"
    "fmt"
    "sync"
    "time"

    clientv3 "go.etcd.io/etcd/client/v3"
    "go.etcd.io/etcd/client/v3/concurrency"
    "go.uber.org/zap"
)

type Elector struct {
    client       *clientv3.Client
    session      *concurrency.Session
    election     *concurrency.Election
    key          string
    id           string
    mu           sync.RWMutex
    isLeader     bool
    isHealthy    bool
    logger       *zap.Logger
    shutdownCh   chan struct{}
}

func NewElector(client *clientv3.Client, key, id string, logger *zap.Logger) (*Elector, error) {
    if client == nil {
        return nil, fmt.Errorf("etcd client is nil")
    }
    if key == "" {
        return nil, fmt.Errorf("leader election key is empty")
    }
    if id == "" {
        return nil, fmt.Errorf("instance ID is empty")
    }

    return &Elector{
        client:     client,
        key:        key,
        id:         id,
        logger:     logger,
        isHealthy:  true,
        shutdownCh: make(chan struct{}),
    }, nil
}

func (e *Elector) Run(ctx context.Context) {
    defer close(e.shutdownCh)

    for {
        select {
        case <-ctx.Done():
            e.logger.Info("Leader election context cancelled, exiting")
            return
        default:
        }

        session, err := e.createSession(ctx)
        if err != nil {
            e.logger.Error("Failed to create etcd session", zap.Error(err))
            e.setHealthy(false)
            time.Sleep(e.backoffDuration())
            continue
        }

        e.mu.Lock()
        e.session = session
        e.mu.Unlock()

        election := concurrency.NewElection(session, e.key)
        e.election = election

        if err := election.Campaign(ctx, e.id); err != nil {
            e.logger.Error("Leader election campaign failed", zap.Error(err))
            session.Close()
            e.setHealthy(false)
            time.Sleep(e.backoffDuration())
            continue
        }

        e.mu.Lock()
        e.isLeader = true
        e.isHealthy = true
        e.mu.Unlock()

        e.logger.Info("Elected as leader", zap.String("id", e.id))

        select {
        case <-session.Done():
            e.logger.Warn("Leader session expired")
        case <-ctx.Done():
            e.logger.Info("Leader election context cancelled")
            if err := e.resign(context.Background()); err != nil {
                e.logger.Error("Failed to resign leadership", zap.Error(err))
            }
            return
        }

        e.mu.Lock()
        e.isLeader = false
        e.mu.Unlock()

        e.logger.Info("Leader step down")
    }
}

func (e *Elector) createSession(ctx context.Context) (*concurrency.Session, error) {
    jitter := time.Duration(e.idHash()%3000) * time.Millisecond
    ttl := 10 + int(jitter.Milliseconds()/1000)
    return concurrency.NewSession(e.client, concurrency.WithTTL(ttl))
}

func (e *Elector) idHash() int64 {
    var h int64
    for i, c := range e.id {
        h += int64(c) * int64(i+1)
    }
    if h < 0 {
        h = -h
    }
    return h
}

func (e *Elector) backoffDuration() time.Duration {
    base := 5 * time.Second
    jitter := time.Duration(e.idHash()%2000) * time.Millisecond
    return base + jitter
}

func (e *Elector) IsLeader() bool {
    e.mu.RLock()
    defer e.mu.RUnlock()
    return e.isLeader
}

func (e *Elector) IsHealthy() bool {
    e.mu.RLock()
    defer e.mu.RUnlock()
    return e.isHealthy
}

func (e *Elector) LeaderID(ctx context.Context) (string, error) {
    e.mu.RLock()
    election := e.election
    e.mu.RUnlock()

    if election == nil {
        return "", fmt.Errorf("election not initialized")
    }

    resp, err := election.Leader(ctx)
    if err != nil {
        return "", fmt.Errorf("failed to get leader: %w", err)
    }

    if len(resp.Kvs) == 0 {
        return "", fmt.Errorf("no leader elected")
    }

    return string(resp.Kvs[0].Value), nil
}

func (e *Elector) Resign(ctx context.Context) error {
    e.mu.RLock()
    election := e.election
    isLeader := e.isLeader
    e.mu.RUnlock()

    if !isLeader || election == nil {
        return nil
    }

    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    if err := election.Resign(ctx); err != nil {
        return fmt.Errorf("failed to resign leadership: %w", err)
    }

    e.mu.Lock()
    e.isLeader = false
    e.mu.Unlock()

    e.logger.Info("Leadership resigned successfully")
    return nil
}

func (e *Elector) resign(ctx context.Context) error {
    return e.Resign(ctx)
}

func (e *Elector) setHealthy(healthy bool) {
    e.mu.Lock()
    defer e.mu.Unlock()
    e.isHealthy = healthy
}