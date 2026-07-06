package controllers

import (
	"context"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
)

// TestClusterPolicyEndpoint_StaleDenyOnDeselect verifies that a pod de-selected
// from a ClusterNetworkPolicy has its cluster-policy eBPF state reset without a
// pod restart. It calls cleanupClusterPolicyPod with the pod's identifier absent
// from podIdentifierToClusterPolicyEndpointMap, matching the state the update
// path leaves behind, and asserts the eBPF reset still runs.
func TestClusterPolicyEndpoint_StaleDenyOnDeselect(t *testing.T) {
	const (
		podName = "nginx-6c644f6bd9-nftc9"
		podNS   = "np-target"
	)

	mock := &ebpf.MockBpfClient{}
	r := &ClusterPolicyEndpointsReconciler{ebpfClient: mock}

	targetPod := npatypes.Pod{
		NamespacedName: types.NamespacedName{Name: podName, Namespace: podNS},
	}

	err := r.cleanupClusterPolicyPod(context.Background(), targetPod, "isolate-dark-corner-b7jc4", false)
	assert.NoError(t, err)

	assert.Contains(t, mock.CallLog, "UpdateClusterPolicyEbpfMaps",
		"cleanup skipped the eBPF rule-map reset for a de-selected pod")
	assert.Contains(t, mock.CallLog, "UpdatePodStateEbpfMaps",
		"cleanup skipped the pod-state reset for a de-selected pod")
}
