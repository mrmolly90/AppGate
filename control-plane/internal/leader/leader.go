// =============================================================================
// AppGate Control Plane — Leader Election
// =============================================================================
//
// etcd-based leader election for control plane HA.
// Uses etcd's concurrency package for distributed mutex.
// =============================================================================

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

// Elector manages leader election using etcd.
type Elector struct {
	client   *clientv3.Client
	session  *concurrency.Session
	election *concurrency.Election
	key      string
	id       string
	mu       sync.RWMutex
	isLeader bool
	logger   *zap.Logger
}

// NewElector creates a new leader elector.
func NewElector(client *clientv3.Client, key, id string) (*Elector, error) {
	return &Elector{
		client: client,
		key:    key,
		id:     id,
		logger: zap.NewNop(),
	}, nil
}

// Run starts the leader election loop. Blocks until context is cancelled.
func (e *Elector) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		session, err := concurrency.NewSession(e.client, concurrency.WithTTL(10))
		if err != nil {
			e.logger.Error("Failed to create etcd session", zap.Error(err))
			time.Sleep(5 * time.Second)
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
			time.Sleep(5 * time.Second)
			continue
		}

		e.mu.Lock()
		e.isLeader = true
		e.mu.Unlock()

		e.logger.Info("Elected as leader", zap.String("id", e.id))

		// Hold leadership until session expires or context cancelled
		select {
		case <-session.Done():
			e.logger.Warn("Leader session expired")
		case <-ctx.Done():
			e.logger.Info("Leader election context cancelled")
			e.resign()
			return
		}

		e.mu.Lock()
		e.isLeader = false
		e.mu.Unlock()

		e.logger.Info("Leader step down")
	}
}

// IsLeader returns whether this instance is the current leader.
func (e *Elector) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isLeader
}

// LeaderID returns the current leader's ID.
func (e *Elector) LeaderID(ctx context.Context) (string, error) {
	if e.election == nil {
		return "", fmt.Errorf("election not initialized")
	}
	resp, err := e.election.Leader(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get leader: %w", err)
	}
	return string(resp.Kvs[0].Value), nil
}

// resign steps down as leader.
func (e *Elector) resign() {
	if e.election != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.election.Resign(ctx); err != nil {
			e.logger.Error("Failed to resign leadership", zap.Error(err))
		}
	}
}
