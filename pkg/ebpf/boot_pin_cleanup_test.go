package ebpf

import (
	"os"
	"sync"
	"testing"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	mock_bpfclient "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser/mocks"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfprogs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	mock_tc "github.com/aws/aws-ebpf-sdk-go/pkg/tc/mocks"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// fakeProgInspector is an in-memory progPinInspector.
type fakeProgInspector struct {
	// Program ID reported per pin path.
	progIDByPin map[string]uint32
	// Read failure to return per pin path.
	errByPin map[string]error
	// File descriptor to return per pin path.
	fdByPin map[string]int
	// Pin paths asked about, in order.
	inspected []string
}

func (f *fakeProgInspector) GetProgFromPinPath(pinPath string) (goebpfprogs.BpfProgInfo, int, error) {
	f.inspected = append(f.inspected, pinPath)
	if err, ok := f.errByPin[pinPath]; ok {
		return goebpfprogs.BpfProgInfo{}, -1, err
	}
	return goebpfprogs.BpfProgInfo{ID: f.progIDByPin[pinPath]}, f.fdByPin[pinPath], nil
}

func noAttachedProgs() (map[uint32]struct{}, error) {
	return map[uint32]struct{}{}, nil
}

// seedPinFamily writes all pin files of one pod identifier: 2 programs, 6 maps.
func seedPinFamily(t *testing.T, progsDir, mapsDir, identifier string) (progPins, mapPins []string) {
	t.Helper()
	for _, suffix := range progPinSuffixes() {
		path := progsDir + identifier + "_" + suffix
		assert.NoError(t, os.WriteFile(path, []byte("x"), 0644))
		progPins = append(progPins, path)
	}
	for _, suffix := range mapPinSuffixes() {
		path := mapsDir + identifier + "_" + suffix
		assert.NoError(t, os.WriteFile(path, []byte("x"), 0644))
		mapPins = append(mapPins, path)
	}
	return progPins, mapPins
}

// redirectPinDirsToTemp points the pin path vars at temp directories for the test,
// so it never reads or writes the host's /sys/fs/bpf. These are package vars, so
// the tests using it must not run in parallel.
func redirectPinDirsToTemp(t *testing.T) (progsDir, mapsDir string) {
	t.Helper()
	origProgs, origMaps := utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY, utils.BPF_MAPS_PIN_PATH_DIRECTORY
	progsDir, mapsDir = t.TempDir()+"/", t.TempDir()+"/"
	utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY, utils.BPF_MAPS_PIN_PATH_DIRECTORY = progsDir, mapsDir
	t.Cleanup(func() {
		utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY, utils.BPF_MAPS_PIN_PATH_DIRECTORY = origProgs, origMaps
	})
	return progsDir, mapsDir
}

// redirectIPAMCheckpointPath points the checkpoint path var at a test file.
func redirectIPAMCheckpointPath(t *testing.T, path string) {
	t.Helper()
	orig := ipamCheckpointPath
	ipamCheckpointPath = path
	t.Cleanup(func() { ipamCheckpointPath = orig })
}

func assertGone(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		_, err := os.Stat(path)
		assert.True(t, os.IsNotExist(err), "expected %s to be reclaimed", path)
	}
}

func assertPresent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		_, err := os.Stat(path)
		assert.NoError(t, err, "expected %s to be preserved", path)
	}
}

func TestCleanupOrphanPinsAtBoot_ReclaimsOrphanFamilyAndKeepsLive(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	// web-abc is live, ghost-xyz is not.
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	liveProgs, liveMaps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("web-abc", "default"))
	orphanProgs, orphanMaps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("ghost-xyz", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Empty(t, result.skippedReason)
	assert.Equal(t, 2, result.candidateIdentifiers)
	assert.Equal(t, 1, result.orphanIdentifiers)
	assert.Equal(t, 2, result.progPinsRemoved)
	assert.Equal(t, 6, result.mapPinsRemoved)
	assert.Empty(t, result.retained)

	assertGone(t, append(orphanProgs, orphanMaps...)...)
	assertPresent(t, append(liveProgs, liveMaps...)...)
}

// A legacy format pin of a live pod is kept.
func TestCleanupOrphanPinsAtBoot_LegacyFormatPinForLivePodRetained(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	legacyProgs, legacyMaps := seedPinFamily(t, progsDir, mapsDir, utils.LegacyGetPodIdentifier("web-abc", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, 0, result.orphanIdentifiers)
	assert.Equal(t, 0, result.progPinsRemoved+result.mapPinsRemoved)
	assertPresent(t, append(legacyProgs, legacyMaps...)...)
}

func TestCleanupOrphanPinsAtBoot_GlobalPinsNeverReclaimed(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	conntrack := mapsDir + "global_aws_conntrack_map"
	events := mapsDir + "global_policy_events"
	assert.NoError(t, os.WriteFile(conntrack, []byte("x"), 0644))
	assert.NoError(t, os.WriteFile(events, []byte("x"), 0644))
	orphanProgs, orphanMaps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("ghost-xyz", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	// Global pins are skipped before parsing, so they are neither candidates
	// nor unparsable.
	assert.Equal(t, 1, result.candidateIdentifiers)
	assert.Equal(t, 0, result.retained[retainUnparsablePin])
	assertPresent(t, conntrack, events)
	assertGone(t, append(orphanProgs, orphanMaps...)...)
}

// A workload named "global-*" is a normal candidate, not a node-wide pin.
func TestCleanupOrphanPinsAtBoot_WorkloadNamedGlobalIsStillACandidate(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	progs, maps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("global-cache-1", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, 1, result.orphanIdentifiers)
	assertGone(t, append(progs, maps...)...)
}

// A checkpoint listing no pods abandons the pass instead of reclaiming everything.
func TestCleanupOrphanPinsAtBoot_EmptyIpamStateAbandonsPass(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), nil)

	progs, maps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("web-abc", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, skipEmptyIpamState, result.skippedReason)
	assert.Equal(t, 0, result.progPinsRemoved+result.mapPinsRemoved)
	assertPresent(t, append(progs, maps...)...)
}

func TestCleanupOrphanPinsAtBoot_MissingIpamStateAbandonsPass(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"

	progs, maps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("web-abc", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        t.TempDir() + "/does-not-exist.json",
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, skipNoIpamState, result.skippedReason)
	assertPresent(t, append(progs, maps...)...)
}

func TestCleanupOrphanPinsAtBoot_UnreadableIpamStateAbandonsPass(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := t.TempDir() + "/ipam.json"
	assert.NoError(t, os.WriteFile(ipamPath, []byte("{not json"), 0644))

	progs, maps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("web-abc", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, skipUnreadableIpamState, result.skippedReason)
	assertPresent(t, append(progs, maps...)...)
}

// An unparsable pin name is counted and left in place.
func TestCleanupOrphanPinsAtBoot_UnparsablePinLeftAlone(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	mystery := progsDir + "something_unexpected"
	assert.NoError(t, os.WriteFile(mystery, []byte("x"), 0644))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, 0, result.candidateIdentifiers)
	assert.Equal(t, 1, result.retained[retainUnparsablePin])
	assertPresent(t, mystery)
}

// An attached program keeps its pins even when absent from the checkpoint.
func TestCleanupOrphanPinsAtBoot_AttachedProgramRetained(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	identifier := utils.GetPodIdentifier("ghost-xyz", "default")
	progs, maps := seedPinFamily(t, progsDir, mapsDir, identifier)

	inspector := &fakeProgInspector{progIDByPin: map[string]uint32{progs[1]: 42}}
	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir: progsDir,
		mapsDir:  mapsDir,
		ipamPath: ipamPath,
		attachedProgIDs: func() (map[uint32]struct{}, error) {
			return map[uint32]struct{}{42: {}}, nil
		},
		inspector: inspector,
	})

	assert.Equal(t, 0, result.orphanIdentifiers)
	assert.Equal(t, 1, result.retained[retainAttached])
	assertPresent(t, append(progs, maps...)...)
}

// With no inspector, attachment cannot be checked and every pin is kept.
func TestCleanupOrphanPinsAtBoot_NoInspectorRetainsEverything(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	progs, maps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("ghost-xyz", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       nil,
	})

	assert.Equal(t, 1, result.retained[retainAttached])
	assertPresent(t, append(progs, maps...)...)
}

func TestCleanupOrphanPinsAtBoot_TCQueryFailureAbandonsPass(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	progs, maps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("ghost-xyz", "default"))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir: progsDir,
		mapsDir:  mapsDir,
		ipamPath: ipamPath,
		attachedProgIDs: func() (map[uint32]struct{}, error) {
			return nil, assert.AnError
		},
		inspector: &fakeProgInspector{},
	})

	assert.Equal(t, skipTCQueryFailed, result.skippedReason)
	assertPresent(t, append(progs, maps...)...)
}

// One live pod keeps the pin family of an identifier shared by several pods.
func TestCleanupOrphanPinsAtBoot_OneLivePodKeepsSharedIdentifier(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	// Both pods collapse to identifier "web@default"; only web-live is still on
	// the node.
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-live", "default"}})

	shared := utils.GetPodIdentifier("web-gone", "default")
	assert.Equal(t, shared, utils.GetPodIdentifier("web-live", "default"))
	progs, maps := seedPinFamily(t, progsDir, mapsDir, shared)

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, 0, result.orphanIdentifiers)
	assertPresent(t, append(progs, maps...)...)
}

// Map pins with no program pin in the family are reclaimed.
func TestCleanupOrphanPinsAtBoot_MapOnlyOrphanReclaimed(t *testing.T) {
	progsDir := t.TempDir() + "/"
	mapsDir := t.TempDir() + "/"
	ipamPath := writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}})

	orphanMap := mapsDir + utils.GetPodIdentifier("ghost-xyz", "default") + "_" + utils.TC_INGRESS_MAP
	assert.NoError(t, os.WriteFile(orphanMap, []byte("x"), 0644))

	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        progsDir,
		mapsDir:         mapsDir,
		ipamPath:        ipamPath,
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Equal(t, 1, result.orphanIdentifiers)
	assert.Equal(t, 1, result.mapPinsRemoved)
	assertGone(t, orphanMap)
}

// Absent pin directories are not an error.
func TestCleanupOrphanPinsAtBoot_MissingPinDirsIsNoOp(t *testing.T) {
	root := t.TempDir()
	result := cleanupOrphanPinsAtBoot(bootPinCleanupInput{
		progsDir:        root + "/programs/",
		mapsDir:         root + "/maps/",
		ipamPath:        writeIpam(t, root, [][2]string{{"web-abc", "default"}}),
		attachedProgIDs: noAttachedProgs,
		inspector:       &fakeProgInspector{},
	})

	assert.Empty(t, result.skippedReason)
	assert.Equal(t, 0, result.candidateIdentifiers)
}

// recoverBPFState reaches the cleanup pass. The other tests call
// cleanupOrphanPinsAtBoot directly and would not catch an unwired call site.
func TestRecoverBPFState_ReclaimsOrphanPinsAtBoot(t *testing.T) {
	progsDir, mapsDir := redirectPinDirsToTemp(t)
	redirectIPAMCheckpointPath(t, writeIpam(t, t.TempDir(), [][2]string{{"web-abc", "default"}}))

	orphanProgs, orphanMaps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("ghost-xyz", "default"))
	liveProgs, liveMaps := seedPinFamily(t, progsDir, mapsDir, utils.GetPodIdentifier("web-abc", "default"))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sdkClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	tcClient := mock_tc.NewMockBpfTc(ctrl)
	sdkClient.EXPECT().RecoverGlobalMaps().Return(map[string]goebpfmaps.BpfMap{}, nil).AnyTimes()
	sdkClient.EXPECT().RecoverAllBpfProgramsAndMaps().Return(map[string]goelf.BpfData{}, nil).AnyTimes()
	tcClient.EXPECT().GetAllAttachedProgIds().Return(map[string]int{}, map[string]int{}, nil).AnyTimes()

	client := NewMockBpfClient()
	// The real SDK inspector cannot read a temp-dir pin, so nothing would ever
	// look unattached. Only the inspector is faked; the wiring under test is real.
	client.progInspector = &fakeProgInspector{}

	_, _, _, _, _, err := client.recoverBPFState(tcClient, sdkClient, new(sync.Map), new(sync.Map), false, false, false)
	assert.NoError(t, err)

	assertGone(t, append(orphanProgs, orphanMaps...)...)
	assertPresent(t, append(liveProgs, liveMaps...)...)
}

// Every fd opened by the attachment check is closed.
func TestIdentifierHasAttachedProgram_ClosesEveryFD(t *testing.T) {
	fd, err := unix.Dup(1)
	assert.NoError(t, err)

	pin := "/sys/fs/bpf/globals/aws/programs/ghost@default_" + utils.TC_INGRESS_PROG
	inspector := &fakeProgInspector{
		progIDByPin: map[string]uint32{pin: 7},
		fdByPin:     map[string]int{pin: fd},
	}

	attached := identifierHasAttachedProgram([]string{pin}, map[uint32]struct{}{}, inspector)
	assert.False(t, attached)

	// A second close proves the first one happened.
	assert.Equal(t, unix.EBADF, unix.Close(fd))
}

// An unreadable program pin counts as attached.
func TestIdentifierHasAttachedProgram_UnreadablePinTreatedAsAttached(t *testing.T) {
	pin := "/sys/fs/bpf/globals/aws/programs/ghost@default_" + utils.TC_INGRESS_PROG
	inspector := &fakeProgInspector{errByPin: map[string]error{pin: assert.AnError}}

	assert.True(t, identifierHasAttachedProgram([]string{pin}, map[uint32]struct{}{}, inspector))
}

func TestIdentifierFromPinName(t *testing.T) {
	progOrder := suffixesLongestFirst(progPinSuffixes())
	mapOrder := suffixesLongestFirst(mapPinSuffixes())

	cases := []struct {
		name           string
		order          []string
		wantIdentifier string
		wantOK         bool
	}{
		{"web@default_" + utils.TC_INGRESS_PROG, progOrder, "web@default", true},
		{"web@default_" + utils.TC_EGRESS_PROG, progOrder, "web@default", true},
		{"web@default_" + utils.TC_INGRESS_MAP, mapOrder, "web@default", true},
		// The cluster-policy and pod-state map names end with shorter map names.
		// Matching the shorter suffix would yield "web@default_cp", an
		// identifier no pod can own, and the live pod's map would look orphaned.
		{"web@default_" + utils.TC_CLUSTER_POLICY_INGRESS_MAP, mapOrder, "web@default", true},
		{"web@default_" + utils.TC_CLUSTER_POLICY_EGRESS_MAP, mapOrder, "web@default", true},
		{"web@default_" + utils.TC_INGRESS_POD_STATE_MAP, mapOrder, "web@default", true},
		{"web@default_" + utils.TC_EGRESS_POD_STATE_MAP, mapOrder, "web@default", true},
		// Legacy "-" format identifiers parse the same way.
		{"web-default_" + utils.TC_INGRESS_PROG, progOrder, "web-default", true},
		// Namespaces keep their hyphens.
		{"aws-node@kube-system_" + utils.TC_INGRESS_PROG, progOrder, "aws-node@kube-system", true},
		{"global_aws_conntrack_map", mapOrder, "", false},
		{"something_unexpected", progOrder, "", false},
		// A suffix with no identifier in front of it is not a pin.
		{"_" + utils.TC_INGRESS_PROG, progOrder, "", false},
	}

	for _, c := range cases {
		identifier, ok := identifierFromPinName(c.name, c.order)
		assert.Equal(t, c.wantOK, ok, "parse ok for %s", c.name)
		assert.Equal(t, c.wantIdentifier, identifier, "identifier for %s", c.name)
	}
}
