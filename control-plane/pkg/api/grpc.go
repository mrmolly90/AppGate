package api

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"appgate-control-plane/internal/audit"
	"appgate-control-plane/internal/metrics"
	"appgate-control-plane/pkg/api/pb"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// GRPCServer manages gateway node connections and provides the node registry.
// The protobuf service (pb.GatewayControlPlane) is registered on the underlying
// grpc.Server so gateways can connect, stream config, heartbeat, report audit
// events, and request certificates.
type GRPCServer struct {
	pb.UnimplementedGatewayControlPlaneServer // satisfies the proto interface

	auditLogger *audit.Logger
	logger      *zap.SugaredLogger
	addr        string
	server      *grpc.Server
	stopped     bool

	// Connected nodes
	nodes   map[string]*NodeConnection
	nodesMu sync.RWMutex

	// configSubs holds per-node buffered channels for config pushes.
	configSubs   map[string]chan *pb.ConfigUpdate
	configSubsMu sync.RWMutex
}

// NodeConnection tracks a connected gateway.
type NodeConnection struct {
	NodeID    string
	Connected time.Time
	Region    string
	Version   string
}

// NewGRPCServer creates the gRPC control plane server with the real protobuf
// service registered. Production knobs: keepalive enforcement, max message
// sizes, and connection timeout tuned for high gateway fan-in.
func NewGRPCServer(addr string, auditLogger *audit.Logger, logger *zap.SugaredLogger) *GRPCServer {
	gs := grpc.NewServer(
		grpc.MaxConcurrentStreams(1000),
		grpc.ConnectionTimeout(30*time.Second),
		grpc.MaxRecvMsgSize(16*1024*1024), // 16 MiB
		grpc.MaxSendMsgSize(16*1024*1024),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  60 * time.Second,
			Timeout:               20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	s := &GRPCServer{
		addr:        addr,
		auditLogger: auditLogger,
		logger:      logger,
		server:      gs,
		nodes:       make(map[string]*NodeConnection),
		configSubs:  make(map[string]chan *pb.ConfigUpdate),
	}

	// Register the real protobuf service so gateways can RPC.
	pb.RegisterGatewayControlPlaneServer(gs, s)
	return s
}

// Start begins listening for gRPC connections.
func (s *GRPCServer) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.addr, err)
	}
	s.logger.Infof("gRPC server listening on %s", s.addr)
	return s.server.Serve(lis)
}

// Stop gracefully stops the gRPC server.
func (s *GRPCServer) Stop() {
	s.logger.Info("Stopping gRPC server...")
	// Mark stopped to reject new registrations before draining connections.
	s.nodesMu.Lock()
	s.stopped = true
	s.nodesMu.Unlock()
	s.server.GracefulStop()
}

// NodeCount returns the number of currently connected gateway nodes.
func (s *GRPCServer) NodeCount() int {
	s.nodesMu.RLock()
	defer s.nodesMu.RUnlock()
	return len(s.nodes)
}

// ListNodes returns the currently connected gateway nodes.
func (s *GRPCServer) ListNodes() []NodeConnection {
	s.nodesMu.RLock()
	defer s.nodesMu.RUnlock()
	nodes := make([]NodeConnection, 0, len(s.nodes))
	for _, n := range s.nodes {
		nodes = append(nodes, *n)
	}
	return nodes
}

// RegisterNode adds or updates a gateway node in the registry.
func (s *GRPCServer) RegisterNode(nodeID, version, region string) {
	s.nodesMu.Lock()
	defer s.nodesMu.Unlock()
	if s.stopped {
		s.logger.Warnw("Rejecting node registration after shutdown", "node_id", nodeID)
		return
	}
	s.nodes[nodeID] = &NodeConnection{
		NodeID:    nodeID,
		Connected: time.Now().UTC(),
		Region:    region,
		Version:   version,
	}
	metrics.GatewayRegistrations.Inc()
	s.auditLogger.Record(
		"gateway.registered",
		nodeID,
		"register",
		"gateway",
		"allowed",
		"",
		"control-plane",
		map[string]string{"version": version, "region": region},
	)
}

// UnregisterNode removes a gateway node from the registry.
func (s *GRPCServer) UnregisterNode(nodeID string) {
	s.nodesMu.Lock()
	defer s.nodesMu.Unlock()
	delete(s.nodes, nodeID)
	s.auditLogger.Record(
		"gateway.unregistered",
		nodeID,
		"unregister",
		"gateway",
		"allowed",
		"",
		"control-plane",
		nil,
	)
}

// ── Protobuf service implementation ──────────────────────────────────────────

// StreamConfig opens a long-lived bidirectional stream. The gateway announces
// itself on connect and receives configuration updates pushed by the control
// plane.
func (s *GRPCServer) StreamConfig(stream pb.GatewayControlPlane_StreamConfigServer) error {
	// First message must be the registration with node identity.
	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to read registration: %v", err)
	}
	if req.GetNodeId() == "" {
		return status.Error(codes.InvalidArgument, "node_id is required")
	}

	nodeID := req.GetNodeId()
	s.RegisterNode(nodeID, req.GetVersion(), req.GetRegion())
	defer s.UnregisterNode(nodeID)

	s.logger.Infow("Gateway stream established",
		"node_id", nodeID,
		"version", req.GetVersion(),
		"region", req.GetRegion())

	updates := make(chan *pb.ConfigUpdate, 32)
	s.configSubsMu.Lock()
	s.configSubs[nodeID] = updates
	s.configSubsMu.Unlock()
	defer func() {
		s.configSubsMu.Lock()
		delete(s.configSubs, nodeID)
		s.configSubsMu.Unlock()
	}()

	// Push goroutine: forward config updates enqueued via PushConfig to the
	// gateway over the stream.
	go func() {
		for u := range updates {
			if err := stream.Send(u); err != nil {
				s.logger.Warnw("Failed to send config update to gateway",
					"node_id", nodeID, "error", err)
				return
			}
		}
	}()

	// Read loop: keep the stream alive, process gateway acks/heartbeats.
	for {
		msg, err := stream.Recv()
		if err != nil {
			s.logger.Infow("Gateway stream closed", "node_id", nodeID, "error", err)
			return err
		}
		if msg.GetNodeId() != "" {
			s.touchNode(msg.GetNodeId())
		}
	}
}

// touchNode updates the last-seen timestamp for a node, if present.
func (s *GRPCServer) touchNode(nodeID string) {
	s.nodesMu.Lock()
	defer s.nodesMu.Unlock()
	if conn, ok := s.nodes[nodeID]; ok {
		conn.Connected = time.Now().UTC()
	}
}

// Heartbeat is called periodically by gateways to report health.
func (s *GRPCServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req == nil || req.GetNodeId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "node_id is required")
	}

	s.nodesMu.Lock()
	if conn, ok := s.nodes[req.GetNodeId()]; ok {
		conn.Connected = time.Now().UTC()
	} else {
		s.nodes[req.GetNodeId()] = &NodeConnection{
			NodeID:    req.GetNodeId(),
			Connected: time.Now().UTC(),
			Region:    "unknown",
			Version:   "unknown",
		}
	}
	s.nodesMu.Unlock()

	s.auditLogger.Record(
		"gateway.heartbeat",
		req.GetNodeId(),
		"heartbeat",
		"gateway",
		"allowed",
		"",
		"gateway",
		nil,
	)

	return &pb.HeartbeatResponse{Command: "ok"}, nil
}

// ReportAudit receives a stream of audit events from a gateway.
func (s *GRPCServer) ReportAudit(stream pb.GatewayControlPlane_ReportAuditServer) error {
	var accepted int32
	for {
		ev, err := stream.Recv()
		if err != nil {
			if err == nil || err.Error() == "EOF" {
				break
			}
			return err
		}
		eventType := ev.GetEventType()
		if eventType == "" {
			eventType = "gateway.report"
		}
		s.auditLogger.Record(
			eventType,
			ev.GetActorId(),
			ev.GetAction(),
			ev.GetResource(),
			ev.GetResult(),
			ev.GetCorrelationId(),
			ev.GetSource(),
			nil,
		)
		metrics.AuditEvents.WithLabelValues(eventType).Inc()
		accepted++
	}
	return stream.SendAndClose(&pb.AuditAck{AcceptedCount: accepted})
}

// RequestCertificate issues mTLS certificates (placeholder for cert manager).
func (s *GRPCServer) RequestCertificate(ctx context.Context, req *pb.CertificateRequest) (*pb.CertificateResponse, error) {
	if req == nil || req.GetNodeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}
	// TODO: Integrate with cert-manager or an in-process CA.
	return nil, status.Errorf(codes.Unimplemented, "certificate issuance not yet implemented")
}

// PushConfigToNode enqueues a config update to a single connected node. It is
// used by the admin config push endpoint to deliver real config deltas.
// Returns false if the node is not connected or its stream buffer is full.
func (s *GRPCServer) PushConfigToNode(nodeID, configID string, backends, routes []string) bool {
	s.configSubsMu.RLock()
	ch, ok := s.configSubs[nodeID]
	s.configSubsMu.RUnlock()
	if !ok {
		return false
	}
	select {
	case ch <- &pb.ConfigUpdate{
		ConfigId: configID,
		Backends: backends,
		Routes:   routes,
	}:
		return true
	default:
		s.logger.Warnw("Config update buffer full for node, dropping", "node_id", nodeID)
		return false
	}
}

// PushConfigToAll enqueues a config update to every connected node.
func (s *GRPCServer) PushConfigToAll(configID string, backends, routes []string) int {
	s.configSubsMu.RLock()
	ids := make([]string, 0, len(s.configSubs))
	for id := range s.configSubs {
		ids = append(ids, id)
	}
	s.configSubsMu.RUnlock()

	delivered := 0
	for _, id := range ids {
		if s.PushConfigToNode(id, configID, backends, routes) {
			delivered++
		}
	}
	return delivered
}

// Client helpers for control-plane-to-gateway push (optional).

// NewGRPCClientConn dials a gateway/control-plane peer for config push.
// Provided for future control-plane-to-control-plane or control-plane-to-gateway
// communication. Returns a client connection.
func NewGRPCClientConn(addr string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16*1024*1024), grpc.MaxCallSendMsgSize(16*1024*1024)),
	)
}
