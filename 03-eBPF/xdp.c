//go:build ignore

// xdp.c - FastPath eBPF/XDP UDP Port Filter
//
// This program runs directly in the Linux kernel network driver at the eXpress Data Path (XDP)
// layer. It intercepts incoming packets before memory allocation (sk_buff) occurs, achieving
// bare-metal packet filtering throughput (millions of packets per second).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// License definition: required by the Linux kernel eBPF verifier to access GPL-only helpers.
char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * BPF Map: blocked_port
 * ---------------------
 * Type: BPF_MAP_TYPE_ARRAY
 * Key:  __u32 (Index 0 is used for configuration)
 * Value: __u16 (The UDP destination port number in host byte order to block)
 *
 * This map is written by the Go userspace program (objs.BlockedPort.Update)
 * and read by the eBPF kernel program on every packet.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, 1);
} blocked_port SEC(".maps");

/*
 * XDP Program: xdp_policy
 * -----------------------
 * SEC("xdp") indicates to the kernel loader and bpf2go that this function
 * attaches to the XDP hook of a network interface.
 *
 * Parameters:
 *   ctx: struct xdp_md pointer containing packet buffer metadata:
 *        - ctx->data:     start of packet data (Ethernet header)
 *        - ctx->data_end: end of valid packet data in memory
 *
 * Returns:
 *   XDP_DROP: Drop packet immediately at the driver level (no kernel stack overhead)
 *   XDP_PASS: Allow packet to continue up into the Linux networking stack
 */
SEC("xdp")
int xdp_policy(struct xdp_md *ctx) {
	// Pointers to the start and end of packet memory.
	// Cast through (long) / (unsigned long) to ensure safe 64-bit address conversion.
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// -------------------------------------------------------------------------
	// 1. ETHERNET HEADER PARSING & BOUNDS CHECK
	// -------------------------------------------------------------------------
	// The Linux kernel eBPF verifier statically analyzes all memory accesses.
	// We MUST prove that (data + sizeof(struct ethhdr)) <= data_end before
	// accessing any fields of ethhdr; otherwise, the verifier rejects the program.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	// Filter out non-IPv4 traffic.
	// eth->h_proto is in network byte order (big-endian), so compare with bpf_htons(ETH_P_IP).
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	// -------------------------------------------------------------------------
	// 2. IPv4 HEADER PARSING & BOUNDS CHECK
	// -------------------------------------------------------------------------
	// The IPv4 header immediately follows the Ethernet header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}

	// Filter out non-UDP traffic (IPPROTO_UDP == 17).
	if (ip->protocol != IPPROTO_UDP) {
		return XDP_PASS;
	}

	// -------------------------------------------------------------------------
	// 3. UDP HEADER PARSING (Accounting for variable IPv4 header length)
	// -------------------------------------------------------------------------
	// ip->ihl contains Internet Header Length in 32-bit (4-byte) words.
	// Minimum valid IPv4 header length is 5 (5 * 4 = 20 bytes).
	if (ip->ihl < 5) {
		return XDP_PASS;
	}

	// Calculate start address of UDP header: ip + (ihl * 4).
	void *udp_start = (void *)ip + (ip->ihl * 4);
	struct udphdr *udp = udp_start;

	// Verify that the full UDP header resides inside the packet buffer.
	if ((void *)(udp + 1) > data_end) {
		return XDP_PASS;
	}

	// -------------------------------------------------------------------------
	// 4. MAP LOOKUP & POLICY EVALUATION
	// -------------------------------------------------------------------------
	// Lookup the blocked port configuration from our BPF array map at key 0.
	__u32 key = 0;
	__u16 *blocked = bpf_map_lookup_elem(&blocked_port, &key);

	// If a port is configured (*blocked != 0):
	// Note: udp->dest is in network byte order (big-endian).
	// *blocked is stored in host byte order by userspace, so we convert with bpf_htons.
	if (blocked && *blocked != 0) {
		if (udp->dest == bpf_htons(*blocked)) {
			// FastPath packet drop: discarded directly in the NIC driver ring!
			return XDP_DROP;
		}
	}

	// Allow all non-matching or allowed traffic to pass through.
	return XDP_PASS;
}
