package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	goebpfprogs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"golang.org/x/sys/unix"
)

// progPinSuffixes returns the pin file name suffixes of the per-pod TC programs.
// Pins are named "<podIdentifier>_<suffix>".
func progPinSuffixes() []string {
	return []string{utils.TC_INGRESS_PROG, utils.TC_EGRESS_PROG}
}

// mapPinSuffixes returns the pin file name suffixes of the per-pod BPF maps.
// The returned slice is shared and must not be mutated.
func mapPinSuffixes() []string {
	return utils.NamespacedBPFMaps
}

// globalPinPrefix is the file name prefix of the node-wide pins: the conntrack
// cache and policy events. A pod identifier is "<prefix>@<namespace>" and cannot
// contain "_" before the "@", so it never collides with this prefix.
const globalPinPrefix = "global_"

// Reasons the pass was abandoned without reclaiming anything.
const (
	skipInventoryFailed     = "inventory_failed"
	skipNoIpamState         = "no_ipam_state"
	skipUnreadableIpamState = "unreadable_ipam_state"
	skipEmptyIpamState      = "empty_ipam_state"
	skipTCQueryFailed       = "tc_query_failed"
)

// Reasons a pin was kept.
const (
	retainAttached      = "attached"
	retainUnparsablePin = "unparsable_pin"
	retainRemoveFailed  = "remove_failed"
)

// progPinInspector reads the BPF program behind a bpffs program pin.
type progPinInspector interface {
	GetProgFromPinPath(pinPath string) (goebpfprogs.BpfProgInfo, int, error)
}

// bootPinCleanupInput holds the paths and dependencies of one cleanup pass.
type bootPinCleanupInput struct {
	progsDir        string
	mapsDir         string
	ipamPath        string
	attachedProgIDs func() (map[uint32]struct{}, error)
	inspector       progPinInspector
}

// bootPinCleanupResult is the outcome of one cleanup pass.
type bootPinCleanupResult struct {
	candidateIdentifiers int
	orphanIdentifiers    int
	progPinsRemoved      int
	mapPinsRemoved       int
	retained             map[string]int
	// One of the skip reasons above, empty if the pass completed.
	skippedReason string
}

func (r bootPinCleanupResult) String() string {
	return fmt.Sprintf("candidates=%d orphans=%d progPins=%d mapPins=%d retained=%v skipped=%q",
		r.candidateIdentifiers, r.orphanIdentifiers, r.progPinsRemoved, r.mapPinsRemoved,
		r.retained, r.skippedReason)
}

// reclaimOrphanPinsAtBoot runs one cleanup pass over this node's pin directories
// and logs the outcome. Errors are logged, never returned: the agent must start
// either way.
func (l *bpfClient) reclaimOrphanPinsAtBoot(bpfTCClient tc.BpfTc) {
	inspector := l.progInspector
	if inspector == nil {
		inspector = &goebpfprogs.BpfProgram{}
	}

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY,
		mapsDir:         utils.BPF_MAPS_PIN_PATH_DIRECTORY,
		ipamPath:        ipamCheckpointPath,
		attachedProgIDs: func() (map[uint32]struct{}, error) { return attachedTCProgIDs(bpfTCClient) },
		inspector:       inspector,
	})

	log().Infof("Boot orphan pin cleanup done: %s", result)
}

func attachedTCProgIDs(bpfTCClient tc.BpfTc) (map[uint32]struct{}, error) {
	ingressProgIDs, egressProgIDs, err := bpfTCClient.GetAllAttachedProgIds()
	if err != nil {
		return nil, err
	}
	attached := make(map[uint32]struct{}, len(ingressProgIDs)+len(egressProgIDs))
	for _, progID := range ingressProgIDs {
		attached[uint32(progID)] = struct{}{}
	}
	for _, progID := range egressProgIDs {
		attached[uint32(progID)] = struct{}{}
	}
	return attached, nil
}

// cleanupOrphanPinsAtBoot unlinks the pins of pod identifiers that are no longer
// in the IPAM checkpoint, one whole pin family at a time.
//
// Must run before the SDK's RecoverAllBpfProgramsAndMaps, which opens an fd per
// pin and so keeps the program resident after the pin is unlinked.
func cleanupOrphanPinsAtBoot(in bootPinCleanupInput) bootPinCleanupResult {
	res := bootPinCleanupResult{retained: map[string]int{}}

	inventory, err := inventoryPinsByIdentifier(in.progsDir, in.mapsDir)
	if err != nil {
		log().Errorf("boot pin cleanup: cannot inventory pins: %v", err)
		res.skippedReason = skipInventoryFailed
		return res
	}
	if inventory.unparsable > 0 {
		res.retained[retainUnparsablePin] = inventory.unparsable
	}
	res.candidateIdentifiers = len(inventory.identifiers)
	if res.candidateIdentifiers == 0 {
		return res
	}

	pods, err := loadIPAMCheckpointPods(in.ipamPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// An absent checkpoint reads the same as a node with no pods.
			log().Infof("boot pin cleanup: no IPAM checkpoint at %s, keeping all %d pin identifier(s)",
				in.ipamPath, res.candidateIdentifiers)
			res.skippedReason = skipNoIpamState
			return res
		}
		log().Errorf("boot pin cleanup: %v", err)
		res.skippedReason = skipUnreadableIpamState
		return res
	}
	if len(pods) == 0 {
		// A wiped checkpoint reads the same as a node with no pods.
		log().Warnf("boot pin cleanup: IPAM checkpoint %s lists no pods while %d pin identifier(s) exist, keeping all",
			in.ipamPath, res.candidateIdentifiers)
		res.skippedReason = skipEmptyIpamState
		return res
	}

	live := livePodIdentifiers(pods)
	log().Debugf("boot pin cleanup: %d pod(s) in IPAM checkpoint, %d pin identifier(s) on disk",
		len(pods), len(inventory.identifiers))

	orphans := make([]string, 0, len(inventory.identifiers))
	for identifier := range inventory.identifiers {
		if _, isLive := live[identifier]; !isLive {
			orphans = append(orphans, identifier)
		}
	}
	if len(orphans) == 0 {
		return res
	}
	// Stable order for logs and tests.
	sort.Strings(orphans)

	attached, err := in.attachedProgIDs()
	if err != nil {
		log().Errorf("boot pin cleanup: cannot list attached programs, keeping all pins: %v", err)
		res.skippedReason = skipTCQueryFailed
		return res
	}

	for _, identifier := range orphans {
		log().Debugf("boot pin cleanup: %s absent from IPAM checkpoint, %d program and %d map pin(s), checking attachment",
			identifier, len(inventory.progPins[identifier]), len(inventory.mapPins[identifier]))
		if identifierHasAttachedProgram(inventory.progPins[identifier], attached, in.inspector) {
			log().Warnf("boot pin cleanup: %s is absent from the IPAM checkpoint but its program is still attached, keeping its pins", identifier)
			res.retained[retainAttached]++
			continue
		}

		res.orphanIdentifiers++
		progsRemoved, mapsRemoved, failed := removePinFamily(inventory.progPins[identifier], inventory.mapPins[identifier])
		res.progPinsRemoved += progsRemoved
		res.mapPinsRemoved += mapsRemoved
		if failed > 0 {
			res.retained[retainRemoveFailed] += failed
		}
		log().Infof("boot pin cleanup: reclaimed %d program and %d map pin(s) for orphaned identifier %s",
			progsRemoved, mapsRemoved, identifier)
	}

	return res
}

// pinInventory is the set of pins found on disk, grouped by pod identifier.
type pinInventory struct {
	identifiers map[string]struct{}
	progPins    map[string][]string
	mapPins     map[string][]string
	// Number of pin names that did not parse into identifier plus suffix.
	unparsable int
}

func inventoryPinsByIdentifier(progsDir, mapsDir string) (*pinInventory, error) {
	inventory := &pinInventory{
		identifiers: map[string]struct{}{},
		progPins:    map[string][]string{},
		mapPins:     map[string][]string{},
	}
	if err := inventory.scan(progsDir, progPinSuffixes(), true); err != nil {
		return nil, err
	}
	if err := inventory.scan(mapsDir, mapPinSuffixes(), false); err != nil {
		return nil, err
	}
	return inventory, nil
}

func (inv *pinInventory) scan(dir string, suffixes []string, isProgram bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		// Directory absent: nothing pinned yet.
		return nil
	}
	if err != nil {
		return fmt.Errorf("read pin directory %s: %w", dir, err)
	}

	ordered := suffixesLongestFirst(suffixes)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, globalPinPrefix) {
			continue
		}
		identifier, ok := identifierFromPinName(name, ordered)
		if !ok {
			log().Warnf("boot pin cleanup: cannot parse pin name %s, leaving it alone", filepath.Join(dir, name))
			inv.unparsable++
			continue
		}
		inv.identifiers[identifier] = struct{}{}
		path := filepath.Join(dir, name)
		if isProgram {
			inv.progPins[identifier] = append(inv.progPins[identifier], path)
		} else {
			inv.mapPins[identifier] = append(inv.mapPins[identifier], path)
		}
	}
	return nil
}

// suffixesLongestFirst sorts suffixes by descending length, so "cp_ingress_map"
// is matched before "ingress_map".
func suffixesLongestFirst(suffixes []string) []string {
	ordered := make([]string, len(suffixes))
	copy(ordered, suffixes)
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) > len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})
	return ordered
}

// identifierFromPinName strips a known suffix from a pin file name to recover the
// pod identifier. Unlike utils.GetPodIdentifierFromBPFPinPath it takes a base name,
// not an absolute bpffs path.
func identifierFromPinName(name string, suffixesLongestFirst []string) (string, bool) {
	for _, suffix := range suffixesLongestFirst {
		if identifier, ok := strings.CutSuffix(name, "_"+suffix); ok && identifier != "" {
			return identifier, true
		}
	}
	return "", false
}

// livePodIdentifiers returns the identifier of every checkpointed pod, in both the
// current and the legacy pin name format.
func livePodIdentifiers(pods []ipamPod) map[string]struct{} {
	live := make(map[string]struct{}, len(pods)*2)
	for _, pod := range pods {
		live[utils.GetPodIdentifier(pod.Name, pod.Namespace)] = struct{}{}
		live[utils.LegacyGetPodIdentifier(pod.Name, pod.Namespace)] = struct{}{}
	}
	return live
}

// identifierHasAttachedProgram reports whether any of the identifier's programs is
// attached to a TC filter. A pin that cannot be read counts as attached.
func identifierHasAttachedProgram(progPins []string, attached map[uint32]struct{}, inspector progPinInspector) bool {
	if inspector == nil {
		return true
	}
	for _, pin := range progPins {
		info, progFD, err := inspector.GetProgFromPinPath(pin)
		// Close the fd the SDK opened. It returns -1 on error paths.
		if progFD > 0 {
			if closeErr := unix.Close(progFD); closeErr != nil {
				log().Warnf("boot pin cleanup: closing fd %d for %s: %v", progFD, pin, closeErr)
			}
		}
		if err != nil {
			log().Warnf("boot pin cleanup: cannot read program at %s, treating it as attached: %v", pin, err)
			return true
		}
		if _, isAttached := attached[info.ID]; isAttached {
			return true
		}
	}
	return false
}

// removePinFamily unlinks the given program and map pins and reports how many of
// each were removed, plus the number that existed but could not be.
func removePinFamily(progPins, mapPins []string) (progsRemoved, mapsRemoved, failed int) {
	for _, pin := range progPins {
		switch removePinIfExists(pin) {
		case removeOK:
			progsRemoved++
		case removeFailed:
			failed++
		}
	}
	for _, pin := range mapPins {
		switch removePinIfExists(pin) {
		case removeOK:
			mapsRemoved++
		case removeFailed:
			failed++
		}
	}
	return progsRemoved, mapsRemoved, failed
}

type removeResult int

const (
	removeSkipped removeResult = iota // already gone
	removeOK                          // unlinked
	removeFailed                      // exists but could not be unlinked
)

func removePinIfExists(path string) removeResult {
	err := os.Remove(path)
	switch {
	case err == nil:
		return removeOK
	case errors.Is(err, os.ErrNotExist):
		return removeSkipped
	default:
		log().Errorf("boot pin cleanup: unlink %s: %v", path, err)
		return removeFailed
	}
}
