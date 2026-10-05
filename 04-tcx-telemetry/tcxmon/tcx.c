//go:build ignore

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#define DROP_UDP_PORT 9999
#define EVENT_SAMPLE_MASK 1023 /* emit about 1 / 1024 drops */

struct event {
  __u64 ts_ns;   // timestamp in nanoseconds
  __u32 ifindex; // interface index
  __u32 reason;  // reason for drop
};

enum drop_reason {          // the different reasons why the packets are dropped
  DROP_REASON_UDP_PORT = 1, //
};

struct counters {
  __u64 packets; // the total number of packets that have been processed by the
                 // BPF program
  __u64 dropped; // the total number of packets that have been dropped by the
                 // BPF program
  __u64 ringbuf_reserve_failures; // the total number of times the BPF program
                                  // failed to reserve space in the ring buffer
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // perCPU array means that each CPU
                                           // has its own copy of the array
  __uint(max_entries, 1);                  // only one entry in the array
  __type(key, __u32); // the key is a 32-bit unsigned integer which will be
                      // always 0 because we only have one entry in the array
  __type(value, struct counters); // the value is a struct counters
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF); // ring buffer is used to store the events
  __uint(max_entries, 1 << 20);
  /* 1 MiB */ // max_entries is the size of the ring buffer in bytes for
              // instance here it is 1 MiB
} events SEC(".maps");

static __always_inline void
maybe_emit_drop(struct __sk_buff *skb,
                __u32 reason, // this is an inline function that is used to emit
                              // a drop event only if the random number is 0
                struct counters *c) {
  if ((bpf_get_prandom_u32() & EVENT_SAMPLE_MASK) !=
      0) // here we are using the prandom_u32() to generate a random number
         // between 0 and 4294967295 but the mask we procide enhance the chance
         // of getting zero to 1 in 1024
    return;

  struct event *e = bpf_ringbuf_reserve(
      &events, sizeof(*e),
      0);   // here we are reserving space in the ring buffer to store the event
  if (!e) { // if the space is not reserved, we increment the
            // ringbuf_reserve_failures counter
    if (c)
      c->ringbuf_reserve_failures++;
    return;
  }

  e->ts_ns = bpf_ktime_get_ns(); // get the timestamp in nanoseconds
  e->ifindex = skb->ifindex;     // get the interface index
  e->reason = reason;            // get the reason for drop
  bpf_ringbuf_submit(e, 0); // submit the event to the ring buffer and this 0 is
}

SEC("tc") // this tells the ebpf loader to hook this into kernel (tc hook for
          // ingress)
int count_and_filter(struct __sk_buff *skb) // here skb is the packet that is
                                            // received by the kernel
{
  __u32 key = 0; // the key is a 32-bit unsigned integer which will be always 0
                 // because we only have one entry in the array
  struct counters *c = bpf_map_lookup_elem(
      &stats, &key); // here we are looking up the stats map to get the counters
  if (c)
    c->packets++;

  void *data =
      (void *)(long)
          skb->data; // skb->data is the pointer to the beginning of the packet
  void *data_end =
      (void *)(long)skb
          ->data_end; // skb->data_end is the pointer to the end of the packet

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  if (ip->protocol != IPPROTO_UDP)
    return TC_ACT_OK;

  __u32 ip_header_len = ip->ihl * 4;
  if (ip_header_len < sizeof(*ip))
    return TC_ACT_OK;

  struct udphdr *udp = (void *)ip + ip_header_len;
  if ((void *)(udp + 1) > data_end)
    return TC_ACT_OK;

  if (udp->dest != bpf_htons(DROP_UDP_PORT))
    return TC_ACT_OK;

  if (c)
    c->dropped++;

  maybe_emit_drop(skb, DROP_REASON_UDP_PORT, c);
  return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
