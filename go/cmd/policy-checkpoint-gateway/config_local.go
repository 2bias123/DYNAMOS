//go:build local
// +build local

package main

import "go.uber.org/zap"

var logLevel = zap.DebugLevel

var defaultGatewayPort = 50049
var defaultStateDir = "/tmp/policy-checkpoint-gateway"
var defaultInactivityTimeoutSeconds = 300
