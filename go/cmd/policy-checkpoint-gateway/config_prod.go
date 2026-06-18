//go:build !local
// +build !local

package main

import "go.uber.org/zap"

var logLevel = zap.DebugLevel

var defaultGatewayPort = 50050
var defaultStateDir = "/state"
var defaultInactivityTimeoutSeconds = 300
