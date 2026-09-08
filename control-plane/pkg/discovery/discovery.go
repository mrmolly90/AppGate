package discovery

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// ServiceDiscovery watches for backend changes via Consul or static config
type ServiceDiscovery struct {
	consulAddr string
	logger     *zap.SugaredLogger
}

// NewServiceDiscovery creates a discovery client
func NewServiceDiscovery(consulAddr string, logger *zap.SugaredLogger) *ServiceDiscovery {
	return &ServiceDiscovery{
		consulAddr: consulAddr,
		logger:     logger,
	}
}

// Watch polls for service changes (simplified - integrate Consul client for production)
func (d *ServiceDiscovery) Watch(ctx context.Context) {
	if d.consulAddr == "" {
		d.logger.Info("Consul not configured, using static backends")
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// TODO: Implement Consul service catalog polling
			d.logger.Debug("Polling Consul for service changes")
		}
	}
}
