package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gotest.tools/assert"
)

func TestRelationStateDirectivesRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		in   Relation
	}{
		{
			name: "WithoutStateDirectives",
			in: Relation{
				ID:                      "GUID",
				RequestTypes:            []string{"sqlDataRequest", "genericRequest"},
				DataSets:                []string{"wageGap"},
				AllowedArchetypes:       []string{"computeToData", "dataThroughTtp"},
				AllowedComputeProviders: []string{"SURF"},
			},
		},
		{
			name: "WithStateDirectives",
			in: Relation{
				ID:                      "12345-state-aware",
				RequestTypes:            []string{"sqlDataRequest"},
				DataSets:                []string{"wageGap"},
				AllowedArchetypes:       []string{"computeToData"},
				AllowedComputeProviders: []string{"SURF"},
				StateDirectives: &StateDirectives{
					Allowed:          true,
					RetentionSeconds: 600,
					ResumeAllowed:    true,
					OnRevocation:     "purge",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.in)
			assert.NilError(t, err)

			var out Relation
			err = json.Unmarshal(data, &out)
			assert.NilError(t, err)

			if !reflect.DeepEqual(tc.in, out) {
				t.Errorf("round-trip mismatch:\n  in:  %+v\n  out: %+v", tc.in, out)
			}
		})
	}
}

func TestRelationStateDirectivesOmitempty(t *testing.T) {
	r := Relation{
		ID:                      "GUID",
		RequestTypes:            []string{"sqlDataRequest"},
		DataSets:                []string{"wageGap"},
		AllowedArchetypes:       []string{"computeToData"},
		AllowedComputeProviders: []string{"SURF"},
	}

	data, err := json.Marshal(r)
	assert.NilError(t, err)

	if strings.Contains(string(data), "stateDirectives") {
		t.Errorf("expected omitempty to drop stateDirectives, got: %s", data)
	}
}

func TestRelationDeserializesLegacyFixture(t *testing.T) {
	// Existing on-disk shape (matches configuration/etcd_launch_files/agreements.json
	// and the etcd.txt dump): no stateDirectives key. The schema addition must
	// preserve this exact deserialization.
	fixture := `{
		"ID": "GUID",
		"requestTypes": ["sqlDataRequest", "genericRequest"],
		"dataSets": ["wageGap"],
		"allowedArchetypes": ["computeToData", "dataThroughTtp"],
		"allowedComputeProviders": ["SURF"]
	}`

	var r Relation
	err := json.Unmarshal([]byte(fixture), &r)
	assert.NilError(t, err)

	assert.Equal(t, "GUID", r.ID)
	if r.StateDirectives != nil {
		t.Errorf("expected nil StateDirectives on legacy fixture, got %+v", r.StateDirectives)
	}
	if !reflect.DeepEqual(r.RequestTypes, []string{"sqlDataRequest", "genericRequest"}) {
		t.Errorf("RequestTypes mismatch: %+v", r.RequestTypes)
	}
	if !reflect.DeepEqual(r.AllowedArchetypes, []string{"computeToData", "dataThroughTtp"}) {
		t.Errorf("AllowedArchetypes mismatch: %+v", r.AllowedArchetypes)
	}
}
