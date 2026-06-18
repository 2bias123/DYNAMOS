package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/Jorrit05/DYNAMOS/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// exitFn is a seam so tests can drive the convergent teardown to completion
// without leaving the test process.
var exitFn = os.Exit

type gatewayServer struct {
	pb.UnimplementedPolicyCheckpointGatewayServer

	expected Identity
	store    *Store

	stop       chan struct{}
	stopOnce   sync.Once
	stopReason atomic.Value

	lastActivity atomic.Int64

	grpcServer *grpc.Server
}

func newGatewayServer(expected Identity, s *Store) *gatewayServer {
	g := &gatewayServer{
		expected: expected,
		store:    s,
		stop:     make(chan struct{}),
	}
	g.touch()
	return g
}

func (g *gatewayServer) touch() {
	g.lastActivity.Store(time.Now().UnixNano())
}

// triggerShutdown is the sole path that closes g.stop. All three teardown
// sources (explicit Shutdown RPC, SubscribeStateEvents stream loss,
// inactivity timeout) funnel through here. sync.Once makes it idempotent
// and panic-free under concurrent invocation.
func (g *gatewayServer) triggerShutdown(reason string) {
	g.stopOnce.Do(func() {
		g.stopReason.Store(reason)
		close(g.stop)
	})
}

// watchShutdown blocks until g.stop is closed, audits the shutdown,
// fsyncs the audit file, gracefully stops the gRPC server, then exits.
// Started exactly once from main.
func (g *gatewayServer) watchShutdown(drain time.Duration) {
	<-g.stop
	reason, _ := g.stopReason.Load().(string)
	_ = g.store.Audit(AuditRecord{
		Op:       "shutdown",
		Decision: "ALLOW",
		Reason:   reason,
		Identity: g.expected,
	})
	_ = g.store.Sync()
	time.Sleep(drain)
	if g.grpcServer != nil {
		g.grpcServer.GracefulStop()
	}
	exitFn(0)
}

// inactivityWatcher polls every (timeout/10) and triggers shutdown if no
// RPC has touched lastActivity within timeout. The crash case (stateful MS
// dies without calling Shutdown) is otherwise reaped only by Kubernetes'
// ActiveDeadlineSeconds — which marks the Job Failed.
func (g *gatewayServer) inactivityWatcher(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	period := timeout / 10
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			last := time.Unix(0, g.lastActivity.Load())
			if time.Since(last) >= timeout {
				g.triggerShutdown(fmt.Sprintf("inactivity timeout (%s)", timeout))
				return
			}
		}
	}
}

func identityEqual(a, b Identity) bool {
	return a.Steward == b.Steward &&
		a.User == b.User &&
		a.RequestType == b.RequestType &&
		a.JobID == b.JobID &&
		a.LocalJobName == b.LocalJobName
}

func identityFromProto(p *pb.Identity) Identity {
	if p == nil {
		return Identity{}
	}
	return Identity{
		Steward:      p.Steward,
		User:         p.User,
		RequestType:  p.RequestType,
		JobID:        p.JobId,
		LocalJobName: p.LocalJobName,
	}
}

// verifyIdentity returns nil on a five-field match. On any mismatch it
// returns codes.PermissionDenied and audits op=identity_mismatch with the
// received-vs-expected diff in reason.
func (g *gatewayServer) verifyIdentity(received *pb.Identity, op, class, key string) error {
	got := identityFromProto(received)
	if identityEqual(got, g.expected) {
		return nil
	}
	_ = g.store.Audit(AuditRecord{
		Op:         "identity_mismatch",
		StateClass: class,
		StateKey:   key,
		Decision:   "DENY",
		Reason: fmt.Sprintf(
			"received{steward=%q user=%q requestType=%q jobId=%q localJobName=%q} expected{steward=%q user=%q requestType=%q jobId=%q localJobName=%q} during %s",
			got.Steward, got.User, got.RequestType, got.JobID, got.LocalJobName,
			g.expected.Steward, g.expected.User, g.expected.RequestType, g.expected.JobID, g.expected.LocalJobName,
			op,
		),
		Identity: got,
	})
	return status.Error(codes.PermissionDenied, "identity mismatch")
}

func (g *gatewayServer) RequestStateWrite(ctx context.Context, req *pb.StateWriteRequest) (*pb.StateDecision, error) {
	g.touch()
	if err := g.verifyIdentity(req.GetIdentity(), "write", req.GetStateClass(), req.GetStateKey()); err != nil {
		return nil, err
	}

	if err := g.store.Write(req.GetStateClass(), req.GetStateKey(), req.GetPayload()); err != nil {
		if errors.Is(err, ErrInvalidIdentifier) {
			_ = g.store.Audit(AuditRecord{
				Op: "write", StateClass: req.GetStateClass(), StateKey: req.GetStateKey(),
				Decision: "DENY", Reason: err.Error(), Identity: g.expected,
			})
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	now := time.Now().Unix()
	_ = g.store.Audit(AuditRecord{
		Op: "write", StateClass: req.GetStateClass(), StateKey: req.GetStateKey(),
		Decision: "ALLOW", Reason: "stub", Identity: g.expected,
	})
	return &pb.StateDecision{
		Allowed:                  true,
		Reason:                   "stub",
		WrittenUnixSeconds:       now,
		AgreementHash:            "",
		RetentionSecondsRemaining: 0,
	}, nil
}

func (g *gatewayServer) ValidateStateRead(ctx context.Context, req *pb.StateReadRequest) (*pb.StateReadResponse, error) {
	g.touch()
	if err := g.verifyIdentity(req.GetIdentity(), "read", req.GetStateClass(), req.GetStateKey()); err != nil {
		return nil, err
	}

	payload, err := g.store.Read(req.GetStateClass(), req.GetStateKey())
	if err != nil {
		if errors.Is(err, ErrInvalidIdentifier) {
			_ = g.store.Audit(AuditRecord{
				Op: "read", StateClass: req.GetStateClass(), StateKey: req.GetStateKey(),
				Decision: "DENY", Reason: err.Error(), Identity: g.expected,
			})
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if os.IsNotExist(err) {
			_ = g.store.Audit(AuditRecord{
				Op: "read", StateClass: req.GetStateClass(), StateKey: req.GetStateKey(),
				Decision: "DENY", Reason: "not found", Identity: g.expected,
			})
			return &pb.StateReadResponse{Allowed: false, Reason: "not found"}, nil
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	_ = g.store.Audit(AuditRecord{
		Op: "read", StateClass: req.GetStateClass(), StateKey: req.GetStateKey(),
		Decision: "ALLOW", Reason: "stub", Identity: g.expected,
	})
	return &pb.StateReadResponse{
		Allowed: true,
		Reason:  "stub",
		Payload: payload,
	}, nil
}

// SubscribeStateEvents sends one AGREEMENT_CHANGED ack, then blocks until
// either the gateway shuts down or the client stream breaks. A break that
// is NOT preceded by an in-flight shutdown means the dependent MS died
// (crash case), which §1.7 says we must treat as a fast shutdown trigger.
func (g *gatewayServer) SubscribeStateEvents(req *pb.SubscribeRequest, stream pb.PolicyCheckpointGateway_SubscribeStateEventsServer) error {
	g.touch()
	if err := g.verifyIdentity(req.GetIdentity(), "subscribe", "", ""); err != nil {
		return err
	}

	initial := &pb.StateEvent{
		Kind:   pb.StateEvent_AGREEMENT_CHANGED,
		Reason: "subscribe ack (stub)",
	}
	if err := stream.Send(initial); err != nil {
		return err
	}

	select {
	case <-g.stop:
		return nil
	case <-stream.Context().Done():
		select {
		case <-g.stop:
			return nil
		default:
			g.triggerShutdown("subscriber stream lost")
			return nil
		}
	}
}

func (g *gatewayServer) Shutdown(ctx context.Context, req *pb.ShutdownRequest) (*emptypb.Empty, error) {
	g.touch()
	if err := g.verifyIdentity(req.GetIdentity(), "shutdown", "", ""); err != nil {
		return nil, err
	}
	reason := req.GetReason()
	if reason == "" {
		reason = "explicit Shutdown"
	} else {
		reason = "explicit Shutdown: " + reason
	}
	g.triggerShutdown(reason)
	return &emptypb.Empty{}, nil
}
