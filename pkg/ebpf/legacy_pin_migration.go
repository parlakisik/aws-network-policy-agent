package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

// formatV2MarkerPath is the sentinel file written after a successful one-shot
// legacy-format migration. Its presence makes the migration a no-op on every
// subsequent agent restart.
const formatV2MarkerPath = "/var/run/aws-node/.npa_format_v2"

// migrateLegacyPinsFromCNIState renames per-pod bpffs pin files from the
// legacy "-" separator format to the new "_" format. Runs once per node;
// the markerPath sentinel makes it a no-op on subsequent restarts.
func migrateLegacyPinsFromCNIState(progsDir, mapsDir, ipamPath, markerPath string) error {
	if _, err := os.Stat(markerPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking migration marker %s: %w", markerPath, err)
	}

	pods, err := loadIPAMCheckpointPods(ipamPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	byLegacyID := map[string][]ipamPod{}
	for _, pod := range pods {
		legacyID := utils.LegacyGetPodIdentifier(pod.Name, pod.Namespace)
		byLegacyID[legacyID] = append(byLegacyID[legacyID], pod)
	}

	var totalFailed int
	for legacyID, pods := range byLegacyID {
		// Sort by pod name so the choice of inheriting pod is deterministic.
		// For multi-replica workloads all pods produce the same new ID, so
		// order is irrelevant. For true cross-namespace collisions the first
		// pod's pin gets renamed; the other pods will get fresh per-pod pins
		// via the reconcile loop's normal attach path.
		sort.Slice(pods, func(i, j int) bool {
			return pods[i].Name < pods[j].Name
		})
		p := pods[0]
		newID := utils.GetPodIdentifier(p.Name, p.Namespace)

		if len(pods) > 1 {
			log().Infof("legacy pin %s shared by %d local pods; inheriting to first pod %s/%s (%s); other pods get fresh pins via reconcile",
				legacyID, len(pods), p.Namespace, p.Name, newID)
		}
		renamed, failed := renamePinFamily(progsDir, mapsDir, legacyID, newID)
		totalFailed += failed
		if renamed > 0 {
			log().Infof("migrated %d bpffs pin file(s) for %s/%s: %s -> %s",
				renamed, p.Namespace, p.Name, legacyID, newID)
		}
	}

	if totalFailed > 0 {
		return fmt.Errorf("legacy pin migration incomplete: %d rename(s) failed; will retry on next restart", totalFailed)
	}

	if err := os.MkdirAll(filepath.Dir(markerPath), 0755); err != nil {
		return fmt.Errorf("ensure marker dir for %s: %w", markerPath, err)
	}
	if err := os.WriteFile(markerPath, []byte("v2\n"), 0644); err != nil {
		return fmt.Errorf("write migration marker %s: %w", markerPath, err)
	}
	log().Infof("legacy pin migration complete; marker written at %s", markerPath)
	return nil
}

// renamePinFamily renames every pin of one podIdentifier.
func renamePinFamily(progsDir, mapsDir, legacyID, newID string) (renamed int, failed int) {
	for _, suffix := range progPinSuffixes() {
		switch renamePinIfExists(progsDir+legacyID+"_"+suffix, progsDir+newID+"_"+suffix) {
		case renameOK:
			renamed++
		case renameFailed:
			failed++
		}
	}
	for _, suffix := range mapPinSuffixes() {
		switch renamePinIfExists(mapsDir+legacyID+"_"+suffix, mapsDir+newID+"_"+suffix) {
		case renameOK:
			renamed++
		case renameFailed:
			failed++
		}
	}
	return renamed, failed
}

type renameResult int

const (
	renameSkipped renameResult = iota // source does not exist
	renameOK                          // rename succeeded
	renameFailed                      // source exists but rename failed
)

func renamePinIfExists(src, dst string) renameResult {
	if _, err := os.Stat(src); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log().Warnf("legacy pin migration: stat %s: %v", src, err)
			return renameFailed
		}
		return renameSkipped
	}
	if err := os.Rename(src, dst); err != nil {
		log().Warnf("legacy pin migration: rename %s -> %s: %v", src, dst, err)
		return renameFailed
	}
	return renameOK
}
