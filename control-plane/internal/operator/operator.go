package operator

import (
    "context"
    "fmt"
    "sigs.k8s.io/controller-runtime/pkg/manager"
    "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

type Manager struct {
    mgr manager.Manager
}

func NewManager(cfg *Config) (*Manager, error) {
    mgr, err := manager.New(nil, manager.Options{
        Metrics: server.Options{BindAddress: "0"},
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create manager: %w", err)
    }
    return &Manager{mgr: mgr}, nil
}

func (m *Manager) Start(ctx context.Context) error {
    return m.mgr.Start(ctx)
}

type Config struct {
    KubeConfig interface{}
}