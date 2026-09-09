package ebpf

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/ipamd/datastore"
)

// ipamCheckpointPath is VPC CNI's per-pod allocation checkpoint, listing the pods
// that have networking on this node. It is tmpfs-backed, so a reboot clears it and
// ipamd rebuilds it. A var so tests can redirect it.
var ipamCheckpointPath = "/var/run/aws-node/ipam.json"

// ipamPod is one pod entry from the checkpoint. A multi-NIC pod has one entry per
// allocation.
type ipamPod struct {
	Name            string
	Namespace       string
	InterfacesCount int
}

// loadIPAMCheckpointPods reads the checkpoint at path, skipping entries with no pod
// name or namespace. A missing file returns an error wrapping os.ErrNotExist.
//
// The file format is datastore.CheckpointData from amazon-vpc-cni-k8s.
func loadIPAMCheckpointPods(path string) ([]ipamPod, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CNI ipam state %s: %w", path, err)
	}

	var state datastore.CheckpointData
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("parse CNI ipam state %s: %w", path, err)
	}

	pods := make([]ipamPod, 0, len(state.Allocations))
	for _, allocation := range state.Allocations {
		if allocation.Metadata.K8SPodName == "" || allocation.Metadata.K8SPodNamespace == "" {
			continue
		}
		pods = append(pods, ipamPod{
			Name:            allocation.Metadata.K8SPodName,
			Namespace:       allocation.Metadata.K8SPodNamespace,
			InterfacesCount: allocation.Metadata.InterfacesCount,
		})
	}
	return pods, nil
}
