package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/Jorrit05/DYNAMOS/pkg/lib"
	pb "github.com/Jorrit05/DYNAMOS/pkg/proto"
	"go.opencensus.io/plugin/ocgrpc"
	"google.golang.org/grpc"
)

var (
	port   = flag.Int("port", 0, "The server port (overrides GATEWAY_PORT)")
	logger = lib.InitLogger(logLevel)
)

const drainBeforeStop = time.Second

func setupTracing() {
	if os.Getenv("OC_AGENT_HOST") == "" {
		logger.Info("OC_AGENT_HOST unset; tracing disabled")
		return
	}
	if _, err := lib.InitTracer("policy-checkpoint-gateway"); err != nil {
		logger.Sugar().Warnf("Failed to create ocagent-exporter: %v", err)
	}
}

func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		logger.Sugar().Fatalf("required env %s is empty; readiness fails", name)
	}
	return v
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		logger.Sugar().Fatalf("env %s = %q is not an int: %v", name, raw, err)
	}
	return n
}

func envString(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func loadIdentityFromEnv() Identity {
	return Identity{
		Steward:      requireEnv("DATA_STEWARD_NAME"),
		User:         requireEnv("REQUEST_USER"),
		RequestType:  requireEnv("REQUEST_TYPE"),
		JobID:        requireEnv("JOB_NAME"),
		LocalJobName: requireEnv("LOCAL_JOB_NAME"),
	}
}

func main() {
	flag.Parse()

	setupTracing()

	identity := loadIdentityFromEnv()
	stateDir := envString("STATE_DIR", defaultStateDir)
	inactivity := time.Duration(envInt("INACTIVITY_TIMEOUT_SECONDS", defaultInactivityTimeoutSeconds)) * time.Second
	gatewayPort := *port
	if gatewayPort == 0 {
		gatewayPort = envInt("GATEWAY_PORT", defaultGatewayPort)
	}

	store, err := NewStore(stateDir)
	if err != nil {
		logger.Sugar().Fatalf("Failed to init store: %v", err)
	}

	g := newGatewayServer(identity, store)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", gatewayPort))
	if err != nil {
		logger.Sugar().Fatalf("Failed to listen on %d: %v", gatewayPort, err)
	}
	logger.Sugar().Infof("Serving on %d (stateDir=%s, inactivity=%s)", gatewayPort, stateDir, inactivity)

	grpcServer := grpc.NewServer(grpc.StatsHandler(&ocgrpc.ServerHandler{}))
	pb.RegisterPolicyCheckpointGatewayServer(grpcServer, g)
	pb.RegisterHealthServer(grpcServer, &lib.SharedServer{})
	g.grpcServer = grpcServer

	go g.watchShutdown(drainBeforeStop)
	go g.inactivityWatcher(inactivity)

	if err := grpcServer.Serve(lis); err != nil {
		logger.Sugar().Fatalf("Failed to serve: %v", err)
	}
}
