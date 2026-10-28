package utils

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNetworkPolicyIdentifier(t *testing.T) {
	first := GetNetworkPolicyIdentifier("policy-with-hyphen", "namespace")
	second := GetNetworkPolicyIdentifier("policy", "with-hyphen-namespace")

	assert.Equal(t, "policy-with-hyphen/namespace", first)
	assert.Equal(t, "policy/with-hyphen-namespace", second)
	assert.NotEqual(t, first, second)
}

func TestDeriveStalePodIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		// stored is the previous snapshot in networkPolicyToPodIdentifierMap, keyed by policy identifier.
		stored               map[string][]string
		policyIdentifier     string
		targetPodIdentifiers map[string]bool
		want                 []string
	}{
		{
			name:                 "no previous snapshot for this NP",
			stored:               map[string][]string{},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: map[string]bool{"rs1@ns": true},
			want:                 nil,
		},
		{
			name:                 "all previously selected identifiers still selected",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "rs2@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: map[string]bool{"rs1@ns": true, "rs2@ns": true},
			want:                 nil,
		},
		{
			name:                 "identifier no longer selected is stale",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "churned@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: map[string]bool{"rs1@ns": true},
			want:                 []string{"churned@ns"},
		},
		{
			name:                 "empty current set makes every previous identifier stale (full NP delete)",
			stored:               map[string][]string{"np/ns": {"rs1@ns", "rs2@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: nil,
			want:                 []string{"rs1@ns", "rs2@ns"},
		},
		{
			name:                 "only this NP's snapshot is consulted",
			stored:               map[string][]string{"np/ns": {"rs1@ns"}, "other-np/ns": {"rs9@ns"}},
			policyIdentifier:     "np/ns",
			targetPodIdentifiers: nil,
			want:                 []string{"rs1@ns"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m sync.Map
			for k, v := range tt.stored {
				m.Store(k, v)
			}
			got := DeriveStalePodIdentifiers(&m, tt.policyIdentifier, tt.targetPodIdentifiers)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestUpdatePodIdentifierToPolicyEndpointMap(t *testing.T) {
	const podIdentifier = "rs1@ns"

	tests := []struct {
		name     string
		tracked  []TrackedPolicyEndpoint
		parentNP string
		incoming []string
		want     []TrackedPolicyEndpoint
	}{
		{
			name:     "first insert for a new identifier",
			tracked:  nil,
			parentNP: "np",
			incoming: []string{"np-abcd"},
			want:     []TrackedPolicyEndpoint{{ParentNP: "np", Name: "np-abcd"}},
		},
		{
			name:     "re-inserting the same slice does not duplicate it",
			tracked:  []TrackedPolicyEndpoint{{ParentNP: "np", Name: "np-abcd"}},
			parentNP: "np",
			incoming: []string{"np-abcd"},
			want:     []TrackedPolicyEndpoint{{ParentNP: "np", Name: "np-abcd"}},
		},
		{
			name:     "a new sibling slice is tracked alongside the existing one",
			tracked:  []TrackedPolicyEndpoint{{ParentNP: "np", Name: "np-abcd"}},
			parentNP: "np",
			incoming: []string{"np-abcd", "np-efgh"},
			want: []TrackedPolicyEndpoint{
				{ParentNP: "np", Name: "np-abcd"}, {ParentNP: "np", Name: "np-efgh"},
			},
		},
		{
			name:     "another policy's slices are preserved",
			tracked:  []TrackedPolicyEndpoint{{ParentNP: "other-np", Name: "other-np-xyz"}},
			parentNP: "np",
			incoming: []string{"np-abcd"},
			want: []TrackedPolicyEndpoint{
				{ParentNP: "other-np", Name: "other-np-xyz"}, {ParentNP: "np", Name: "np-abcd"},
			},
		},
		{
			// The supplied list is authoritative for its parent, so a re-slice drops the
			// obsolete name instead of accumulating it.
			name:     "a re-sliced policy's obsolete name is replaced",
			tracked:  []TrackedPolicyEndpoint{{ParentNP: "np", Name: "np-abcd"}},
			parentNP: "np",
			incoming: []string{"np-wxyz"},
			want:     []TrackedPolicyEndpoint{{ParentNP: "np", Name: "np-wxyz"}},
		},
		{
			// Two policies sharing a truncated name prefix derive the same parent, which is
			// why the parent is recorded rather than derived: neither may evict the other.
			name: "policies sharing a derived prefix do not evict each other",
			tracked: []TrackedPolicyEndpoint{
				{ParentNP: "a-very-long-policy-name-alpha", Name: "a-very-long-policy-name-aaaaa"},
			},
			parentNP: "a-very-long-policy-name-beta",
			incoming: []string{"a-very-long-policy-name-bbbbb"},
			want: []TrackedPolicyEndpoint{
				{ParentNP: "a-very-long-policy-name-alpha", Name: "a-very-long-policy-name-aaaaa"},
				{ParentNP: "a-very-long-policy-name-beta", Name: "a-very-long-policy-name-bbbbb"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m sync.Map
			var mu sync.Mutex
			if tt.tracked != nil {
				m.Store(podIdentifier, tt.tracked)
			}

			UpdatePodIdentifierToPolicyEndpointMap(&m, &mu, podIdentifier, tt.parentNP, tt.incoming)

			assert.ElementsMatch(t, tt.want, TrackedPolicyEndpointsFor(&m, podIdentifier))
		})
	}
}
