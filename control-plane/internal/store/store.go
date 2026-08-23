// =============================================================================
// AppGate Control Plane — etcd Store
// =============================================================================
//
// etcd client wrapper with watch patterns for configuration changes.
// Provides a consistent interface for reading and watching configuration.
// =============================================================================

package store

import (
	"context"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

// EtcdStore wraps an etcd client with convenience methods.
type EtcdStore struct {
	client *clientv3.Client
	logger *zap.Logger
}

// NewEtcdStore creates a new etcd client and returns a store wrapper.
func NewEtcdStore(ctx context.Context, endpoints []string, dialTimeout time.Duration) (*EtcdStore, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: dialTimeout,
		Logger:      zap.NewNop(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	// Verify connectivity
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	if _, err := cli.Get(ctx, "/appgate/health"); err != nil {
		return nil, fmt.Errorf("failed to connect to etcd: %w", err)
	}

	return &EtcdStore{
		client: cli,
		logger: zap.NewNop(),
	}, nil
}

// Client returns the underlying etcd client.
func (s *EtcdStore) Client() *clientv3.Client {
	return s.client
}

// Close closes the etcd client connection.
func (s *EtcdStore) Close() error {
	return s.client.Close()
}

// Get retrieves a value from etcd.
func (s *EtcdStore) Get(ctx context.Context, key string) (string, error) {
	resp, err := s.client.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("etcd get failed: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return "", fmt.Errorf("key not found: %s", key)
	}
	return string(resp.Kvs[0].Value), nil
}

// Put stores a value in etcd.
func (s *EtcdStore) Put(ctx context.Context, key, value string) error {
	_, err := s.client.Put(ctx, key, value)
	if err != nil {
		return fmt.Errorf("etcd put failed: %w", err)
	}
	return nil
}

// Watch watches a key for changes and sends updates on the returned channel.
func (s *EtcdStore) Watch(ctx context.Context, key string) <-chan string {
	ch := make(chan string, 100)

	go func() {
		defer close(ch)

		wch := s.client.Watch(ctx, key)
		for wresp := range wch {
			for _, ev := range wresp.Events {
				select {
				case ch <- string(ev.Kv.Value):
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return ch
}

// List returns all keys with a given prefix.
func (s *EtcdStore) List(ctx context.Context, prefix string) (map[string]string, error) {
	resp, err := s.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd list failed: %w", err)
	}

	result := make(map[string]string, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		result[string(kv.Key)] = string(kv.Value)
	}
	return result, nil
}

// Delete removes a key from etcd.
func (s *EtcdStore) Delete(ctx context.Context, key string) error {
	_, err := s.client.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("etcd delete failed: %w", err)
	}
	return nil
}
