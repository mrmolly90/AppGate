// =============================================================================
// AppGate Control Plane — Kubernetes Operator
// =============================================================================
//
// controller-runtime based operator for managing AppGate CRDs.
// Watches Gateway and Policy resources and reconciles state.
// =============================================================================

package operator

import (
	"fmt"

	"appgate-control-plane/internal/config"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// NewManager creates a new controller-runtime manager for the operator.
func NewManager(cfg *config.Config) (manager.Manager, error) {
	options := ctrl.Options{
		MetricsBindAddress:     ":8081",
		HealthProbeBindAddress: ":8082",
		LeaderElection:         true,
		LeaderElectionID:       "appgate-operator-leader",
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// TODO: Register controllers and webhooks here
	// SetupScheme(mgr)
	// NewGatewayReconciler(mgr)
	// NewPolicyReconciler(mgr)

	return mgr, nil
}
