package ebpf

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Fix for V2377427643 / EKS-NW-CNI-Cust-491 (netfilter conntrack exhaustion from
// NetworkPolicy-denied traffic).
//
// A NetworkPolicy-denied packet is dropped at the TC hook (TC_ACT_SHOT) *after*
// Netfilter has already created and confirmed an nf_conntrack entry for the flow.
// The drop is silent (no RST), so the entry is orphaned in SYN_SENT for the full
// nf_conntrack_tcp_timeout_syn_sent (default 120s). Sustained denied traffic then
// fills the node conntrack table -> "nf_conntrack: table full" -> node isolation.
//
// This sweeper periodically reclaims those stuck entries. It targets only TCP
// conntrack entries in the SYN_SENT state (which by definition are unreplied —
// once a reply is seen the state advances) that have been idle at least
// netfilterSynSentIdleFloor. A real handshake gets a reply within ms, so an entry
// stuck unreplied for tens of seconds is a failed/denied attempt; established and
// recently-active flows are never in SYN_SENT and are never touched.
//
// Design choice vs. reacting to every deny event: a single ConntrackDeleteFilters
// call per interval dumps the table once and deletes all matches (O(table) per
// sweep), instead of O(table) per denied packet. It also needs no eBPF ring-buffer
// consumption (so no dropped events under load) and no kfuncs (works on any kernel).

const (
	// How often to sweep the netfilter conntrack table.
	netfilterSweepInterval = 10 * time.Second
	// Reclaim a SYN_SENT entry once it has been idle at least this long. Kept well
	// above normal handshake latency so only genuinely-stuck flows are reclaimed.
	netfilterSynSentIdleFloor = 30 * time.Second
	// Fallback if the sysctl cannot be read.
	defaultSynSentTimeoutSec = 120
	// Path to the kernel's SYN_SENT conntrack timeout.
	synSentTimeoutSysctl = "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_sent"
)

var conntrackSweptTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_policy_conntrack_swept_total",
		Help: "Total stale SYN_SENT netfilter conntrack entries reclaimed by the sweeper",
	},
	[]string{"family"},
)

func init() {
	metrics.Registry.MustRegister(conntrackSweptTotal)
}

// staleSynSentFilter matches TCP conntrack entries stuck in SYN_SENT that have
// been idle >= idleFloorSec. Idle time is derived from the entry's remaining
// timeout: a SYN_SENT entry starts at fullTimeoutSec and counts down, and any
// packet on the flow resets it, so idle = fullTimeoutSec - remaining. Returning
// true causes ConntrackDeleteFilters to delete the entry.
type staleSynSentFilter struct {
	fullTimeoutSec uint32
	idleFloorSec   uint32
}

func (f staleSynSentFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if flow == nil || flow.Forward.Protocol != syscall.IPPROTO_TCP {
		return false
	}
	tcp, ok := flow.ProtoInfo.(*netlink.ProtoInfoTCP)
	if !ok || tcp == nil || tcp.State != nl.TCP_CONNTRACK_SYN_SENT {
		return false
	}
	if flow.TimeOut > f.fullTimeoutSec { // guard against skew / non-default timeouts
		return false
	}
	idle := f.fullTimeoutSec - flow.TimeOut
	return idle >= f.idleFloorSec
}

// newStaleSynSentFilter builds the sweep filter, reading the kernel's SYN_SENT
// timeout so idle time is computed correctly even if the sysctl was tuned.
func newStaleSynSentFilter() staleSynSentFilter {
	return staleSynSentFilter{
		fullTimeoutSec: readSynSentTimeoutSec(),
		idleFloorSec:   uint32(netfilterSynSentIdleFloor / time.Second),
	}
}

// sweepStaleSynSentConntrack runs one sweep across IPv4 and IPv6: one table dump
// + delete-matches per family. Safe to call on a timer; errors are logged and
// swallowed so a transient netlink failure never crashes the agent.
func sweepStaleSynSentConntrack(filter staleSynSentFilter) {
	for _, fam := range []struct {
		name   string
		family netlink.InetFamily
	}{
		{"ipv4", netlink.InetFamily(syscall.AF_INET)},
		{"ipv6", netlink.InetFamily(syscall.AF_INET6)},
	} {
		n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, fam.family, filter)
		if err != nil {
			log().Debugf("conntrack sweep (%s) failed: %v", fam.name, err)
			continue
		}
		if n > 0 {
			conntrackSweptTotal.WithLabelValues(fam.name).Add(float64(n))
			log().Debugf("conntrack sweep (%s): reclaimed %d stale SYN_SENT entries", fam.name, n)
		}
	}
}

func readSynSentTimeoutSec() uint32 {
	b, err := os.ReadFile(synSentTimeoutSysctl)
	if err != nil {
		return defaultSynSentTimeoutSec
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v <= 0 {
		return defaultSynSentTimeoutSec
	}
	return uint32(v)
}
