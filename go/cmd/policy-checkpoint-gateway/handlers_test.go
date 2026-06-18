package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/Jorrit05/DYNAMOS/pkg/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"gotest.tools/assert"
)

var testExpected = Identity{
	Steward:      "UVA",
	User:         "u@x",
	RequestType:  "sqlDataRequest",
	JobID:        "jobX",
	LocalJobName: "jobX-1",
}

func testProtoIdentity() *pb.Identity {
	return &pb.Identity{
		Steward:      testExpected.Steward,
		User:         testExpected.User,
		RequestType:  testExpected.RequestType,
		JobId:        testExpected.JobID,
		LocalJobName: testExpected.LocalJobName,
	}
}

func newTestGateway(t *testing.T) (*gatewayServer, *Store) {
	t.Helper()
	s, err := NewStore(t.TempDir())
	assert.NilError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	g := newGatewayServer(testExpected, s)
	return g, s
}

func bootBufconnServer(t *testing.T, g *gatewayServer) (pb.PolicyCheckpointGatewayClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterPolicyCheckpointGatewayServer(srv, g)
	g.grpcServer = srv

	go func() { _ = srv.Serve(lis) }()

	dial := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.NewClient("passthrough://bufconn",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.NilError(t, err)

	cleanup := func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
	return pb.NewPolicyCheckpointGatewayClient(conn), cleanup
}

func TestRequestStateWriteAllow(t *testing.T) {
	g, s := newTestGateway(t)
	client, cleanup := bootBufconnServer(t, g)
	defer cleanup()

	resp, err := client.RequestStateWrite(context.Background(), &pb.StateWriteRequest{
		Identity:   testProtoIdentity(),
		StateClass: "kv",
		StateKey:   "k1",
		Payload:    []byte("payload-bytes"),
	})
	assert.NilError(t, err)
	if !resp.Allowed {
		t.Fatalf("expected Allowed=true, got %+v", resp)
	}
	if resp.Reason != "stub" {
		t.Errorf("expected Reason=stub, got %q", resp.Reason)
	}
	if resp.WrittenUnixSeconds == 0 {
		t.Errorf("expected WrittenUnixSeconds set, got 0")
	}

	got, err := os.ReadFile(filepath.Join(s.DataDir(), "kv", "k1.bin"))
	assert.NilError(t, err)
	if !bytes.Equal(got, []byte("payload-bytes")) {
		t.Fatalf("payload mismatch on disk: %q", got)
	}
}

func TestValidateStateReadHitAndMiss(t *testing.T) {
	g, _ := newTestGateway(t)
	client, cleanup := bootBufconnServer(t, g)
	defer cleanup()

	_, err := client.RequestStateWrite(context.Background(), &pb.StateWriteRequest{
		Identity: testProtoIdentity(), StateClass: "kv", StateKey: "k1", Payload: []byte("xyz"),
	})
	assert.NilError(t, err)

	hit, err := client.ValidateStateRead(context.Background(), &pb.StateReadRequest{
		Identity: testProtoIdentity(), StateClass: "kv", StateKey: "k1",
	})
	assert.NilError(t, err)
	if !hit.Allowed || !bytes.Equal(hit.Payload, []byte("xyz")) {
		t.Fatalf("hit response wrong: %+v", hit)
	}

	miss, err := client.ValidateStateRead(context.Background(), &pb.StateReadRequest{
		Identity: testProtoIdentity(), StateClass: "kv", StateKey: "absent",
	})
	assert.NilError(t, err)
	if miss.Allowed || miss.Reason != "not found" {
		t.Fatalf("miss response wrong: %+v", miss)
	}
}

func TestIdentityMismatchEveryRPC(t *testing.T) {
	g, s := newTestGateway(t)
	client, cleanup := bootBufconnServer(t, g)
	defer cleanup()

	bad := &pb.Identity{Steward: "WRONG", User: "u@x", RequestType: "sqlDataRequest", JobId: "jobX", LocalJobName: "jobX-1"}

	t.Run("write", func(t *testing.T) {
		_, err := client.RequestStateWrite(context.Background(), &pb.StateWriteRequest{
			Identity: bad, StateClass: "kv", StateKey: "k1", Payload: []byte("p"),
		})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("read", func(t *testing.T) {
		_, err := client.ValidateStateRead(context.Background(), &pb.StateReadRequest{
			Identity: bad, StateClass: "kv", StateKey: "k1",
		})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("subscribe", func(t *testing.T) {
		stream, err := client.SubscribeStateEvents(context.Background(), &pb.SubscribeRequest{
			Identity: bad, SubscriberId: "sub-1",
		})
		assert.NilError(t, err)
		_, err = stream.Recv()
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("shutdown", func(t *testing.T) {
		_, err := client.Shutdown(context.Background(), &pb.ShutdownRequest{
			Identity: bad, Reason: "test",
		})
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	raw, err := os.ReadFile(filepath.Join(s.AuditDir(), "audit.log"))
	assert.NilError(t, err)
	mismatches := bytes.Count(raw, []byte(`"op":"identity_mismatch"`))
	if mismatches != 4 {
		t.Fatalf("expected 4 identity_mismatch audit lines, got %d. Log:\n%s", mismatches, raw)
	}

	select {
	case <-g.stop:
		t.Fatal("identity mismatch must not trigger shutdown")
	default:
	}
}

func TestInvalidClassReturnsInvalidArgument(t *testing.T) {
	g, _ := newTestGateway(t)
	client, cleanup := bootBufconnServer(t, g)
	defer cleanup()

	_, err := client.RequestStateWrite(context.Background(), &pb.StateWriteRequest{
		Identity: testProtoIdentity(), StateClass: "bad/class", StateKey: "k1", Payload: []byte("p"),
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = client.ValidateStateRead(context.Background(), &pb.StateReadRequest{
		Identity: testProtoIdentity(), StateClass: "bad/class", StateKey: "k1",
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSubscribeInitialEvent(t *testing.T) {
	g, _ := newTestGateway(t)
	client, cleanup := bootBufconnServer(t, g)
	defer cleanup()

	stream, err := client.SubscribeStateEvents(context.Background(), &pb.SubscribeRequest{
		Identity: testProtoIdentity(), SubscriberId: "sub-1",
	})
	assert.NilError(t, err)
	ev, err := stream.Recv()
	assert.NilError(t, err)
	if ev.Kind != pb.StateEvent_AGREEMENT_CHANGED {
		t.Fatalf("first event kind = %v, want AGREEMENT_CHANGED", ev.Kind)
	}
}

func TestTriggerShutdownIdempotentUnderConcurrency(t *testing.T) {
	g, _ := newTestGateway(t)
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	reasons := make(chan string, N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					reasons <- "panic"
				}
			}()
			g.triggerShutdown(jitterReason(i))
		}()
	}
	wg.Wait()
	close(reasons)
	for r := range reasons {
		if r == "panic" {
			t.Fatal("triggerShutdown panicked under concurrent invocation")
		}
	}

	select {
	case <-g.stop:
	default:
		t.Fatal("g.stop was not closed after 200 concurrent triggerShutdown calls")
	}

	first, _ := g.stopReason.Load().(string)
	if first == "" {
		t.Fatal("stopReason not set")
	}

	for i := 0; i < 50; i++ {
		g.triggerShutdown("post-close")
	}
	again, _ := g.stopReason.Load().(string)
	if again != first {
		t.Fatalf("stopReason changed after subsequent triggers: %q -> %q", first, again)
	}
}

func jitterReason(i int) string { return "reason-" + string(rune('A'+(i%26))) }

func TestAllThreeTriggersConvergeOnSingleShutdown(t *testing.T) {
	g, s := newTestGateway(t)

	var exitCalls atomic.Int32
	var exitCode atomic.Int32
	exitCode.Store(-1)
	prev := exitFn
	exitFn = func(code int) {
		exitCalls.Add(1)
		exitCode.Store(int32(code))
	}
	defer func() { exitFn = prev }()

	done := make(chan struct{})
	go func() {
		g.watchShutdown(10 * time.Millisecond)
		close(done)
	}()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); g.triggerShutdown("explicit Shutdown: test") }()
	go func() { defer wg.Done(); g.triggerShutdown("subscriber stream lost") }()
	go func() { defer wg.Done(); g.triggerShutdown("inactivity timeout (test)") }()
	wg.Wait()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchShutdown did not return within 2s")
	}

	if exitCalls.Load() != 1 {
		t.Fatalf("exitFn called %d times, want exactly 1", exitCalls.Load())
	}
	if exitCode.Load() != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode.Load())
	}

	raw, err := os.ReadFile(filepath.Join(s.AuditDir(), "audit.log"))
	assert.NilError(t, err)
	shutdownLines := bytes.Count(raw, []byte(`"op":"shutdown"`))
	if shutdownLines != 1 {
		t.Fatalf("expected exactly 1 shutdown audit line, got %d. Log:\n%s", shutdownLines, raw)
	}

	reason, _ := g.stopReason.Load().(string)
	if reason == "" {
		t.Fatal("stopReason not set")
	}
}

func TestInactivityWatcherTriggersShutdown(t *testing.T) {
	g, _ := newTestGateway(t)
	var exitCalls atomic.Int32
	prev := exitFn
	exitFn = func(code int) { exitCalls.Add(1) }
	defer func() { exitFn = prev }()
	go g.watchShutdown(time.Millisecond)

	timeout := 50 * time.Millisecond
	go g.inactivityWatcher(timeout)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("inactivity did not trigger shutdown within 2s")
		case <-time.After(10 * time.Millisecond):
			if exitCalls.Load() == 1 {
				reason, _ := g.stopReason.Load().(string)
				if !strings.Contains(reason, "inactivity") {
					t.Fatalf("stopReason = %q, want inactivity-related", reason)
				}
				return
			}
		}
	}
}

func TestSubscribeStreamLossTriggersShutdown(t *testing.T) {
	g, _ := newTestGateway(t)
	client, cleanup := bootBufconnServer(t, g)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.SubscribeStateEvents(ctx, &pb.SubscribeRequest{
		Identity: testProtoIdentity(), SubscriberId: "sub-1",
	})
	assert.NilError(t, err)
	_, err = stream.Recv()
	assert.NilError(t, err)

	cancel()

	select {
	case <-g.stop:
	case <-time.After(2 * time.Second):
		t.Fatal("stream loss did not close g.stop within 2s")
	}
	reason, _ := g.stopReason.Load().(string)
	if !strings.Contains(reason, "stream lost") {
		t.Fatalf("stopReason = %q, want stream-loss-related", reason)
	}
}

func TestShutdownAuditFlushedBeforeExit(t *testing.T) {
	g, s := newTestGateway(t)

	var auditAtExit []byte
	prev := exitFn
	exitFn = func(code int) {
		b, _ := os.ReadFile(filepath.Join(s.AuditDir(), "audit.log"))
		auditAtExit = append([]byte(nil), b...)
	}
	defer func() { exitFn = prev }()

	done := make(chan struct{})
	go func() {
		g.watchShutdown(time.Millisecond)
		close(done)
	}()

	g.triggerShutdown("explicit Shutdown: flush-test")
	<-done

	var rec map[string]any
	dec := json.NewDecoder(bytes.NewReader(auditAtExit))
	found := false
	for dec.More() {
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode audit: %v", err)
		}
		if rec["op"] == "shutdown" {
			found = true
		}
	}
	if !found {
		t.Fatalf("shutdown audit line not present in audit file at exit time. Audit was:\n%s", auditAtExit)
	}
}

func TestShutdownRPCAcceptedThenConverges(t *testing.T) {
	g, _ := newTestGateway(t)
	client, cleanup := bootBufconnServer(t, g)
	defer cleanup()

	exitCh := make(chan struct{}, 1)
	prev := exitFn
	exitFn = func(code int) {
		select {
		case exitCh <- struct{}{}:
		default:
		}
	}
	defer func() { exitFn = prev }()
	go g.watchShutdown(time.Millisecond)

	_, err := client.Shutdown(context.Background(), &pb.ShutdownRequest{
		Identity: testProtoIdentity(), Reason: "MS SafeExit",
	})
	assert.NilError(t, err)

	select {
	case <-exitCh:
	case <-time.After(2 * time.Second):
		t.Fatal("exitFn not called within 2s of Shutdown RPC")
	}
}

func TestTouchUpdatesActivity(t *testing.T) {
	g, _ := newTestGateway(t)
	old := g.lastActivity.Load()
	time.Sleep(2 * time.Millisecond)
	g.touch()
	if g.lastActivity.Load() <= old {
		t.Fatalf("touch did not advance lastActivity")
	}
}

func TestSilenceUtilities(t *testing.T) {
	// keeps imports honest if a future refactor drops io / strings usage
	_ = io.EOF
	_ = strings.HasPrefix
}
