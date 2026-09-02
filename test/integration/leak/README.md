# BPF probe leak suite

Regression gate for the eBPF program/map pin leak under high pod churn
(issues #620 / #621).

## What it asserts

| Assertion | Reads | Survives a dirty node? |
|---|---|---|
| **No new leaked pins** — churn podIdentifiers pinned after the run that were not pinned before | bpffs (`aws-eks-na-cli ebpf loaded-ebpfdata`) | yes, via a pre-churn baseline |
| **No ghost re-attaches** — no churn pod completes more than one attach | the agent log | yes, unconditionally |

A "ghost re-attach" is the leak's mechanism: a pod attached twice is
re-inserted into the shared `progFD -> pods` set after its own delete
already removed it. Nothing removes it again, so `isProgFdShared` stays
true for the last pod of that identifier and its programs and maps are
never unpinned.

Both assertions are needed. The pin check proves the outcome; the ghost
check localises the cause and keeps working on a node that arrived dirty
— leaked pins never self-reclaim, and the agent *adopts* them on restart
(`recoverBPFState` has no liveness check), so nodes stay dirty until
manually cleaned.

## Why the pin assertion is a delta

Earlier the suite failed if *any* pin path contained `churn-generator`.
Because leaked pins never self-reclaim, one leak from any earlier run
made the suite permanently red on that node regardless of how correct the
agent was — it could not validate a fix. It now snapshots before churn
and blames a run only for identifiers *it* leaked, reporting inherited
ones via `AddReportEntry` instead of failing on them.

## Running it

Takes ~26 min (20 min churn at 100 pods/min + 2 min drain + assertions).
It creates and owns namespace `leak-test`, which must not already exist.

```bash
# Pin the kubeconfig to the target cluster. framework.New() connects using the
# file's CURRENT-CONTEXT and ignores -cluster-name for that purpose, so a stray
# context silently tests the wrong cluster -- which surfaces only as
# "Expected <int>: 0 to be >= 1", because getWorkerNodes() filters on
# OSImage containing "Amazon Linux 2023".
kubectl config view --raw --minify --context <cluster> > /tmp/kubeconfig.yaml

# NOTE: `go test ... -- -flag` silently swallows the flags. -args is required.
go test -v -timeout 45m ./test/integration/leak/ -args \
  -cluster-kubeconfig=/tmp/kubeconfig.yaml \
  -cluster-name=<cluster> \
  -aws-region=<region>
```

The agent under test must run with `--log-level=debug`: the suppression
points the ghost assertion depends on log at Debug.

## Interpreting output

```
SUCCESS! -- 1 Passed          the run leaked nothing new
node X carried N pre-existing leaked churn identifier(s)   inherited, not counted
```

A ghost failure names the offending pods:

```
node X: 2 churn pod(s) completed more than one attach (ghost re-add): [pod-a pod-b]
```

## Clearing inherited leaks

For a clean baseline. Order matters — unpinning alone leaves the programs
resident because the agent still holds their fds, and restarting alone
re-adopts the pins.

```bash
# 1. verify the churn workload is gone, or you would unpin live pods
kubectl get ns leak-test                        # expect NotFound
kubectl get pods -A | grep -c churn-generator   # expect 0

# 2. unpin, on each node, scoped to the churn workload only
P=/sys/fs/bpf/globals/aws/programs; M=/sys/fs/bpf/globals/aws/maps
ls $P | grep '^churn-generator' | while read f; do rm -f "$P/$f"; done
ls $M | grep '^churn-generator' | while read f; do rm -f "$M/$f"; done

# 3. release the kernel programs and the agent's held fds
kubectl -n kube-system rollout restart ds/aws-node

# 4. verify (privileged pod, hostPID, dnf install -y bpftool)
ls $P | grep -c churn-generator      # 0
bpftool prog show | grep -c sched_cls # 0
bpftool net show | grep -c handle_    # 0
```

Never remove the global `aws_conntrack_map` or `policy_events` pins, or
pins belonging to other workloads.
