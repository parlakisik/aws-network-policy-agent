package restart

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
)

/*
Boot-time Orphan Pin Reclamation (GitHub #620)

A pin is orphaned when its pod leaves the node without the CNI DeletePodNp call
reaching the agent. On restart the agent adopts every pin it finds, so nothing
reclaims it.

The orphan is created by renaming a live pod's pin family to an identifier no pod
owns and then deleting that pod. After an agent restart:
  - the orphaned family is reclaimed
  - a live workload keeps its pins and its enforcement
*/

const (
	bpfProgramsDir = "/sys/fs/bpf/globals/aws/programs"
	bpfMapsDir     = "/sys/fs/bpf/globals/aws/maps"

	// Distinct prefixes: GetPodIdentifier strips only the last "-<segment>", so
	// these must not collapse into one identifier.
	livePodName  = "bootlive-1"
	ghostPodName = "bootghost-1"
	// Identifier the ghost's pins are renamed to. No pod on the node owns it.
	orphanedPrefix = "bootgone"
)

var _ = Describe("Boot-time Orphan Pin Reclamation", Ordered, func() {

	var (
		networkPolicy    *network.NetworkPolicy
		livePod          *v1.Pod
		ghostPod         *v1.Pod
		clientPod        *v1.Pod
		nodeName         string
		liveIdentifier   string
		ghostIdentifier  string
		orphanIdentifier string
	)

	It("should reclaim orphaned pins on restart, keeping live pins and enforcement", func() {
		By("Deploying two policy-selected workloads with distinct pod identifiers")
		var err error
		livePod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildPinWorkload(livePodName, ""), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())
		nodeName = livePod.Spec.NodeName

		ghostPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, buildPinWorkload(ghostPodName, nodeName), podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		clientPod = &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "bootpin-client", Namespace: namespace},
			Spec: v1.PodSpec{
				NodeName: nodeName,
				Containers: []v1.Container{{
					Name: "curl", Image: "public.ecr.aws/docker/library/python:3.11-slim",
					Command: []string{"sleep", "3600"},
				}},
			},
		}
		clientPod, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, clientPod, podReadyTimeout)
		Expect(err).ToNot(HaveOccurred())

		liveIdentifier = podIdentifier(livePodName)
		ghostIdentifier = podIdentifier(ghostPodName)
		orphanIdentifier = orphanedPrefix + "@" + namespace

		By("Applying a deny-all ingress policy so both workloads get pinned programs")
		networkPolicy = &network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "bootpin-deny", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "bootpin"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
			},
		}
		Expect(fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, networkPolicy)).To(Succeed())
		time.Sleep(bpfSettleInterval)

		serverIP := livePod.Status.PodIP
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"),
			"policy must be enforced before the restart, otherwise the post-restart check proves nothing")

		shell := startNodeShell(nodeName)

		By("Verifying both identifiers are pinned")
		Expect(countPins(shell, liveIdentifier)).To(BeNumerically(">", 0),
			"live workload must have pinned programs and maps")
		Expect(countPins(shell, ghostIdentifier)).To(BeNumerically(">", 0),
			"soon-to-be-orphaned workload must have pinned programs and maps")

		By("Renaming the ghost's pin family to an identifier no pod owns")
		renamePinPrefix(shell, ghostIdentifier, orphanIdentifier)
		orphanPinCount := countPins(shell, orphanIdentifier)
		Expect(orphanPinCount).To(BeNumerically(">", 0), "rename must produce the orphaned family")
		Expect(countPins(shell, ghostIdentifier)).To(Equal(0), "no pin may keep the old identifier")
		fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, shell)

		By("Deleting the ghost pod, so its programs are pinned but attached to nothing")
		Expect(fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, ghostPod)).To(Succeed())
		ghostPod = nil
		time.Sleep(bpfSettleInterval)

		shell = startNodeShell(nodeName)
		By("Confirming the orphan survives normal operation - this is the leak")
		Expect(countPins(shell, orphanIdentifier)).To(Equal(orphanPinCount),
			"a running agent has no path that reclaims an orphaned pin family")
		fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, shell)

		By("Restarting the agent on the target node")
		pods := &v1.PodList{}
		Expect(fw.K8sClient.List(ctx, pods, client.InNamespace(agentNamespace),
			client.MatchingLabels{"k8s-app": "aws-node"})).To(Succeed())
		for _, p := range pods.Items {
			if p.Spec.NodeName == nodeName {
				Expect(fw.K8sClient.Delete(ctx, &p)).To(Succeed())
			}
		}
		waitForDaemonSetRollout()
		time.Sleep(bpfSettleInterval)

		shell = startNodeShell(nodeName)
		defer fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, shell)

		By("Validating: the orphaned pin family was reclaimed")
		Expect(countPins(shell, orphanIdentifier)).To(Equal(0),
			"boot cleanup must reclaim every pin of an identifier no pod owns")

		By("Validating: the live workload's pins were preserved")
		Expect(countPins(shell, liveIdentifier)).To(BeNumerically(">", 0),
			"a pod still in the CNI checkpoint must keep its pins")

		By("Validating: the global maps were preserved")
		state := captureBPFState(nodeName)
		Expect(state.GlobalMaps["aws_conntrack_map"]).To(BeNumerically(">", 0),
			"the conntrack map is not per-pod state and must never be reclaimed")

		By("Validating: enforcement continues for the live workload")
		Expect(execConnect(namespace, clientPod.Name, serverIP, 80)).To(Equal("BLOCKED"))
	})

	AfterAll(func() {
		if networkPolicy != nil {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, networkPolicy)
		}
		for _, pod := range []*v1.Pod{livePod, ghostPod, clientPod} {
			if pod != nil {
				fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, pod)
			}
		}
		// A failed run would otherwise leave the seeded pins on the node.
		if nodeName != "" {
			shell := startNodeShell(nodeName)
			for _, prefix := range []string{orphanedPrefix + "@", podIdentifier(ghostPodName)} {
				runInNodeShell(shell, fmt.Sprintf("rm -f %s/%s* %s/%s* || true",
					bpfProgramsDir, prefix, bpfMapsDir, prefix))
			}
			fw.PodManager.DeleteAndWaitTillPodIsDeleted(ctx, shell)
		}
	})
})

func buildPinWorkload(name, nodeName string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace, Labels: map[string]string{"app": "bootpin"},
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{{
				Name: "nginx", Image: "public.ecr.aws/nginx/nginx:latest",
				Ports: []v1.ContainerPort{{ContainerPort: 80}},
			}},
		},
	}
}

// podIdentifier mirrors utils.GetPodIdentifier for the test's pod names.
func podIdentifier(podName string) string {
	prefix := podName
	if idx := strings.LastIndex(podName, "-"); idx > 0 {
		prefix = podName[:idx]
	}
	return prefix + "@" + namespace
}

// startNodeShell runs a privileged pod on nodeName with the host filesystem
// mounted. Callers must delete it.
func startNodeShell(nodeName string) *v1.Pod {
	shell, err := fw.PodManager.CreateAndWaitTillPodIsRunning(ctx,
		utils.BuildBPFCheckPod(namespace, nodeName), podReadyTimeout)
	Expect(err).ToNot(HaveOccurred())
	return shell
}

func runInNodeShell(shell *v1.Pod, script string) string {
	out, err := fw.PodManager.ExecInPod(namespace, shell.Name, []string{"chroot", "/host", "sh", "-c", script})
	Expect(err).ToNot(HaveOccurred(), "node shell script failed: %s", script)
	return out
}

// countPins returns how many program and map pins carry the given identifier.
func countPins(shell *v1.Pod, identifier string) int {
	out := runInNodeShell(shell, fmt.Sprintf("find %s %s -maxdepth 1 -name '%s_*' 2>/dev/null | wc -l",
		bpfProgramsDir, bpfMapsDir, identifier))
	count, err := strconv.Atoi(strings.TrimSpace(out))
	Expect(err).ToNot(HaveOccurred(), "unexpected pin count output %q", out)
	return count
}

// renamePinPrefix rewrites the identifier part of every matching pin file name.
func renamePinPrefix(shell *v1.Pod, from, to string) {
	script := fmt.Sprintf(`for dir in %s %s; do
  for f in "$dir"/%s_*; do
    [ -e "$f" ] || continue
    mv "$f" "$dir/$(basename "$f" | sed 's/^%s_/%s_/')"
  done
done`, bpfProgramsDir, bpfMapsDir, from, from, to)
	runInNodeShell(shell, script)
}
