package mschain

import (
	"testing"

	"gotest.tools/assert"
)

func TestGenerateChainRequiresGatewayAggregation(t *testing.T) {
	cases := []struct {
		name   string
		in     []MicroserviceMetadata
		expect bool
	}{
		{
			name: "noFlag",
			in: []MicroserviceMetadata{
				{Name: "sql-query", Label: "dataProvider", AllowedOutputs: []string{"sql-algorithm"}},
				{Name: "sql-algorithm", Label: "computeProvider"},
			},
			expect: false,
		},
		{
			name: "oneFlag",
			in: []MicroserviceMetadata{
				{Name: "sql-query", Label: "dataProvider", AllowedOutputs: []string{"sql-pseudonym"}},
				{Name: "sql-pseudonym", Label: "dataProvider", RequiresGateway: true, AllowedOutputs: []string{"sql-algorithm"}},
				{Name: "sql-algorithm", Label: "computeProvider"},
			},
			expect: true,
		},
		{
			name: "twoFlags",
			in: []MicroserviceMetadata{
				{Name: "a", Label: "dataProvider", RequiresGateway: true, AllowedOutputs: []string{"b"}},
				{Name: "b", Label: "dataProvider", RequiresGateway: true},
			},
			expect: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, requiresGateway, err := GenerateChain(tc.in)
			assert.NilError(t, err)
			assert.Equal(t, tc.expect, requiresGateway)
			if len(chain) != len(tc.in) {
				t.Fatalf("chain length = %d, want %d", len(chain), len(tc.in))
			}
		})
	}
}

func TestGenerateChainCyclePropagatesError(t *testing.T) {
	in := []MicroserviceMetadata{
		{Name: "a", AllowedOutputs: []string{"b"}},
		{Name: "b", AllowedOutputs: []string{"a"}},
	}
	_, requiresGateway, err := GenerateChain(in)
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
	assert.Equal(t, false, requiresGateway)
}
