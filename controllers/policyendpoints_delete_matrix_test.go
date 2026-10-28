package controllers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// long parent => GenerateName truncates the slice base at 58 chars, so the derived parent
// differs from PolicyRef.Name. Slice names are built as the apiserver would.
// Every way a NetworkPolicy's PolicyEndpoints can be deleted, against both a short policy
// name and one long enough that GenerateName truncates the slice base. The long variant is
// what proves the parent is recorded rather than derived: with a derived parent these cases
// either strand dead slice names or tear down a still-selected pod.
var longParent = "allow-" + strings.Repeat("x", 54) + "-ingress"

func sliceOf(parent, suffix string) string {
	if len(parent) >= 58 {
		return parent[:58] + suffix
	}
	return parent + "-" + suffix
}

// requireCleaned asserts Map1 holds nothing for an identifier no policy selects any more.
// A retained name keeps the key alive, so ArePoliciesAvailableInLocalCache answers true for a
// workload with no policy -- which in strict mode programs allow-all instead of DEFAULT_DENY.
func requireCleaned(t *testing.T, label string, got []string) {
	t.Helper()
	assert.Emptyf(t, got, "%s: dead slice name(s) retained", label)
}

func TestMatrix_DeleteScenarios(t *testing.T) { runMatrix(t, "pol") }

func TestMatrix_DeleteScenarios_LongName(t *testing.T) { runMatrix(t, longParent) }

func runMatrix(t *testing.T, parent string) {
	rules := []ruleRef{allow("192.168.90.1/32")}
	s1, s2 := sliceOf(parent, "aaaaa"), sliceOf(parent, "bbbbb")

	// 1-slice, local
	t.Run("a", func(t *testing.T) {
		id := identifierOf("lx-pod")
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: s1, parent: parent, pods: []podRef{localPod("lx-pod", "10.1.1.1")}, ingress: rules})
		fx.reconcileAll()
		fx.deleteSlice(s1)
		fx.reconcileDeleted(s1)
		requireCleaned(t, "1-slice deleted, LOCAL identifiers", fx.identifierSlices(id))
	})

	// 1-slice, remote
	t.Run("b", func(t *testing.T) {
		id := identifierOf("rx-pod")
		fx := newPEFixture(t)
		fx.setSlices(sliceSpec{name: s1, parent: parent, pods: []podRef{remotePod("rx-pod", "10.2.1.1")}, ingress: rules})
		fx.reconcileAll()
		fx.deleteSlice(s1)
		fx.reconcileDeleted(s1)
		requireCleaned(t, "1-slice deleted, REMOTE identifiers", fx.identifierSlices(id))
	})

	// 2-slice, local, both gone from cache before either reconcile
	t.Run("c", func(t *testing.T) {
		id := identifierOf("lx-pod")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: s1, parent: parent, pods: []podRef{localPod("lx-pod", "10.1.1.1")}, ingress: rules},
			sliceSpec{name: s2, parent: parent, pods: []podRef{localPod("ly-pod", "10.1.1.2")}, ingress: rules})
		fx.reconcileAll()
		fx.deleteSlice(s1)
		fx.deleteSlice(s2)
		fx.reconcileDeleted(s1)
		fx.reconcileDeleted(s2)
		requireCleaned(t, "2-slice deleted at once, LOCAL identifiers", fx.identifierSlices(id))
	})

	// 2-slice, remote, both gone from cache
	t.Run("d", func(t *testing.T) {
		id := identifierOf("rx-pod")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: s1, parent: parent, pods: []podRef{remotePod("rx-pod", "10.2.1.1")}, ingress: rules},
			sliceSpec{name: s2, parent: parent, pods: []podRef{remotePod("ry-pod", "10.2.1.2")}, ingress: rules})
		fx.reconcileAll()
		fx.deleteSlice(s1)
		fx.deleteSlice(s2)
		fx.reconcileDeleted(s1)
		fx.reconcileDeleted(s2)
		requireCleaned(t, "2-slice deleted at once, REMOTE identifiers", fx.identifierSlices(id))
	})

	// 2-slice, sequential: s1 deleted while s2 still live, then s2
	t.Run("e", func(t *testing.T) {
		idL, idR := identifierOf("lx-pod"), identifierOf("rx-pod")
		fx := newPEFixture(t)
		fx.setSlices(
			sliceSpec{name: s1, parent: parent, pods: []podRef{localPod("lx-pod", "10.1.1.1"), remotePod("rx-pod", "10.2.1.1")}, ingress: rules},
			sliceSpec{name: s2, parent: parent, pods: []podRef{localPod("ly-pod", "10.1.1.2")}, ingress: rules})
		fx.reconcileAll()
		fx.deleteSlice(s1)
		fx.reconcileDeleted(s1)
		fx.deleteSlice(s2)
		fx.reconcileDeleted(s2)
		requireCleaned(t, "2-slice deleted sequentially, LOCAL", fx.identifierSlices(idL))
		requireCleaned(t, "2-slice deleted sequentially, REMOTE", fx.identifierSlices(idR))
	})
}
