package utils

import (
	"slices"
	"sync"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
)

// GetPodListToBeCleanedUp compares old and new pod sets to determine which pods need cleanup
func GetPodListToBeCleanedUp(oldPodSet []npatypes.Pod, newPodSet []npatypes.Pod, podIdentifiers map[string]bool) []npatypes.Pod {
	var podsToBeCleanedUp []npatypes.Pod

	for _, oldPod := range oldPodSet {
		oldPodIdentifier := GetPodIdentifier(oldPod.Name, oldPod.Namespace)

		if !slices.Contains(newPodSet, oldPod) && !podIdentifiers[oldPodIdentifier] {
			podsToBeCleanedUp = append(podsToBeCleanedUp, oldPod)
		}
	}
	return podsToBeCleanedUp
}

// GetNetworkPolicyIdentifier returns an injective in-memory key for a namespaced
// NetworkPolicy. "/" cannot appear in either Kubernetes name component.
func GetNetworkPolicyIdentifier(policyName, policyNamespace string) string {
	return policyName + "/" + policyNamespace
}

// DeriveStalePodIdentifiers finds pod identifiers that are no longer selected by the policy.
// targetPodIdentifiers covers every identifier the policy selects cluster-wide, so it can be
// large under churn.
func DeriveStalePodIdentifiers(networkPolicyToPodIdentifierMap *sync.Map, networkPolicyIdentifier string, targetPodIdentifiers map[string]bool) []string {
	var stalePodIdentifiers []string
	if currentPodIdentifiers, ok := networkPolicyToPodIdentifierMap.Load(networkPolicyIdentifier); ok {
		for _, podIdentifier := range currentPodIdentifiers.([]string) {
			if !targetPodIdentifiers[podIdentifier] {
				stalePodIdentifiers = append(stalePodIdentifiers, podIdentifier)
			}
		}
	}
	return stalePodIdentifiers
}

// TrackedPolicyEndpoint is one entry of podIdentifierToPolicyEndpointMap: a PolicyEndpoint
// name together with the parent policy it belongs to.
//
// ParentNP is recorded rather than derived. A bare PolicyEndpoint name cannot be mapped back
// to its parent reliably -- GetParentNPNameFromPEName strips after the last hyphen, and the
// apiserver truncates a GenerateName base at 58 chars, so two policies agreeing up to the
// last hyphen inside that prefix derive the same string. Writers always hold the live object,
// so they can record the authoritative Spec.PolicyRef.Name instead.
type TrackedPolicyEndpoint struct {
	ParentNP string
	Name     string
}

// TrackedPolicyEndpointsFor returns the entries recorded for a pod identifier, or nil.
func TrackedPolicyEndpointsFor(podIdentifierToPolicyEndpointMap *sync.Map, podIdentifier string) []TrackedPolicyEndpoint {
	if tracked, ok := podIdentifierToPolicyEndpointMap.Load(podIdentifier); ok {
		return tracked.([]TrackedPolicyEndpoint)
	}
	return nil
}

// DeletePolicyEndpointFromPodIdentifierMap removes one PolicyEndpoint, by exact name, from a
// pod identifier's entries. Used by the delete-event scrub, which knows the departing name
// from the request and must remove it whether or not the identifier went stale.
func DeletePolicyEndpointFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier string, policyEndpoint string) {
	deleteMatching(podIdentifierToPolicyEndpointMap, mutex, podIdentifier,
		func(e TrackedPolicyEndpoint) bool { return e.Name == policyEndpoint })
}

// DeleteParentNPFromPodIdentifierMap removes every entry a parent policy recorded for a pod
// identifier, leaving other parents' entries in place. Safe to match on ParentNP because it
// is the recorded Spec.PolicyRef.Name, not a derived prefix.
func DeleteParentNPFromPodIdentifierMap(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier string, parentNP string) {
	deleteMatching(podIdentifierToPolicyEndpointMap, mutex, podIdentifier,
		func(e TrackedPolicyEndpoint) bool { return e.ParentNP == parentNP })
}

// deleteMatching drops entries satisfying match, deleting the key when nothing remains.
func deleteMatching(podIdentifierToPolicyEndpointMap *sync.Map, mutex *sync.Mutex, podIdentifier string, match func(TrackedPolicyEndpoint) bool) {
	mutex.Lock()
	defer mutex.Unlock()

	tracked, ok := podIdentifierToPolicyEndpointMap.Load(podIdentifier)
	if !ok {
		return
	}

	var kept []TrackedPolicyEndpoint
	for _, entry := range tracked.([]TrackedPolicyEndpoint) {
		if match(entry) {
			continue
		}
		kept = append(kept, entry)
	}
	if len(kept) == 0 {
		podIdentifierToPolicyEndpointMap.Delete(podIdentifier)
	} else {
		podIdentifierToPolicyEndpointMap.Store(podIdentifier, kept)
	}
}

// UpdatePodIdentifierToPolicyEndpointMap makes policyEndpointList authoritative for parentNP:
// every entry previously recorded under that parent is replaced, and entries belonging to
// other parents are preserved untouched.
//
// Replacing is what reclaims the names of re-sliced PolicyEndpoints. An identifier a sibling
// slice still selects never becomes stale, so the purge never visits it and the obsolete name
// would otherwise stay forever. Matching on the recorded ParentNP makes that safe -- an
// earlier revision derived the parent from each stored name, which is lossy above 58 chars
// and could evict a *different* policy's names, silently dropping its rules.
func UpdatePodIdentifierToPolicyEndpointMap(podIdentifierMap *sync.Map, mutex *sync.Mutex, podIdentifier string, parentNP string, policyEndpointList []string) {
	mutex.Lock()
	defer mutex.Unlock()

	if len(policyEndpointList) == 0 {
		return
	}

	// Other parents' entries survive; this parent's are rebuilt from policyEndpointList.
	existing, _ := podIdentifierMap.Load(podIdentifier)
	entries, _ := existing.([]TrackedPolicyEndpoint)
	kept := make([]TrackedPolicyEndpoint, 0, len(entries)+len(policyEndpointList))
	for _, entry := range entries {
		if entry.ParentNP != parentNP {
			kept = append(kept, entry)
		}
	}

	for _, policyEndpointName := range policyEndpointList {
		kept = append(kept, TrackedPolicyEndpoint{ParentNP: parentNP, Name: policyEndpointName})
	}
	podIdentifierMap.Store(podIdentifier, kept)
}
