#ifndef NPA_TCP_RST_H
#define NPA_TCP_RST_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Fix for V2377427643 / EKS-NW-CNI-Cust-491.
//
// A NetworkPolicy-denied packet is dropped at the TC hook (BPF_DROP) *after*
// Netfilter has already created and confirmed an nf_conntrack entry. Because the
// drop is silent (no RST), the entry is orphaned in SYN_SENT for the full
// nf_conntrack_tcp_timeout_syn_sent (default 120s), so sustained denied traffic
// exhausts the node conntrack table -> "nf_conntrack: table full" -> node
// isolation.
//
// reject_with_rst_v4 instead rewrites a denied IPv4 TCP packet in place into a
// RST+ACK reply and reflects it back to the sender. Netfilter sees the RST and
// moves the entry to CLOSE (reclaimed in ~10s instead of 120s), and the client
// stops retransmitting immediately. Non-TCP packets are dropped silently
// (BPF_DROP), as before.
//
// NOTE: this changes NetworkPolicy's silent-drop behavior to an active reject
// (a RST reveals the host/filter), so it is a deliberate posture change for this
// fix.

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1ULL << 0)
#endif

#define NPA_TCP_FLAG_SYN 0x02
#define NPA_TCP_FLAG_ACK 0x10
#define NPA_TCP_FLAG_RST 0x04

// Reflect a denied IPv4 TCP segment as a RST+ACK back to the sender.
// Verifier discipline: every direct packet write happens BEFORE any helper call
// (bpf_l4_csum_replace / bpf_redirect), since helper calls invalidate packet
// pointers. IP options are not handled (assumes a 20-byte IP header, matching
// the rest of this program); such packets fall through to a silent drop.
static __always_inline int reject_with_rst_v4(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return BPF_DROP;
	if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
		return BPF_DROP;

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return BPF_DROP;
	if (ip->protocol != IPPROTO_TCP)
		return BPF_DROP;

	struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
	if ((void *)(tcp + 1) > data_end)
		return BPF_DROP;

	// Only reject a bare connection attempt: SYN set, ACK/RST clear. This is the
	// packet that creates the leaked SYN_SENT entry, AND it guarantees we never
	// reflect our own RST+ACK if it re-enters this program (which would loop and
	// storm the CPU). Any other denied TCP packet falls through to a silent drop.
	__u8 tcp_flags = ((__u8 *)tcp)[13];
	if (!(tcp_flags & NPA_TCP_FLAG_SYN) || (tcp_flags & (NPA_TCP_FLAG_ACK | NPA_TCP_FLAG_RST)))
		return BPF_DROP;

	// Constant, data-relative offset of the TCP checksum field.
	__u32 tcp_csum_off = ((__u8 *)tcp - (__u8 *)data) + __builtin_offsetof(struct tcphdr, check);

	// ---- save originals (for checksum deltas) ----
	__be32 old_saddr = ip->saddr;
	__be32 old_daddr = ip->daddr;
	__be16 old_sport = tcp->source;
	__be16 old_dport = tcp->dest;
	__be32 old_seq = tcp->seq;
	__be32 old_ack = tcp->ack_seq;
	__be16 old_win = tcp->window;

	// TCP flags live in byte 13; byte 12 holds data-offset/reserved. The 16-bit
	// network-order word [byte12,byte13] is what the checksum sums.
	__u8 *fptr = (__u8 *)tcp + 12;
	__u8 doff_res = fptr[0];
	__u16 old_flags16 = ((__u16)doff_res << 8) | (__u16)fptr[1];
	__u16 new_flags16 = ((__u16)doff_res << 8) | (NPA_TCP_FLAG_RST | NPA_TCP_FLAG_ACK);

	// ---- new values ----
	__be32 new_seq = 0;                                          // RST seq (ACK set)
	__be32 new_ack = __builtin_bswap32(__builtin_bswap32(old_seq) + 1); // ack the SYN
	__be16 new_win = 0;

	// ==== direct packet writes (pointers valid; no helper calls yet) ====
	__u8 mac[ETH_ALEN];
	__builtin_memcpy(mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, mac, ETH_ALEN);

	ip->saddr = old_daddr;   // symmetric swap -> IP csum and TCP pseudo-hdr unchanged
	ip->daddr = old_saddr;
	tcp->source = old_dport;  // symmetric swap -> TCP csum unchanged
	tcp->dest = old_sport;
	tcp->seq = new_seq;
	tcp->ack_seq = new_ack;
	tcp->window = new_win;
	fptr[1] = (NPA_TCP_FLAG_RST | NPA_TCP_FLAG_ACK); // keep data-offset/reserved

	// ==== checksum fixups (helpers; no packet-pointer access after here) ====
	bpf_l4_csum_replace(skb, tcp_csum_off, old_seq, new_seq, 4);
	bpf_l4_csum_replace(skb, tcp_csum_off, old_ack, new_ack, 4);
	bpf_l4_csum_replace(skb, tcp_csum_off, old_win, new_win, 2);
	bpf_l4_csum_replace(skb, tcp_csum_off, old_flags16, new_flags16, 2);

	// Reflect toward the client: inject on the veth ingress path so the host
	// routes it out to the (now-swapped) destination = the original sender.
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

#endif /* NPA_TCP_RST_H */
