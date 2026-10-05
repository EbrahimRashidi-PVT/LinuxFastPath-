# TCX + ring-buffer telemetry lab

A compact Linux networking project showing:

- TCX ingress attachment using `link.AttachTCX`
- `BPF_MAP_TYPE_PERCPU_ARRAY` aggregate counters
- `BPF_MAP_TYPE_RINGBUF` exceptional telemetry
- sampled events only for dropped UDP/9999 traffic
- cancellation-safe Go ring-buffer consumption
- bounded downstream event processing
- exact 16-byte BPF/Go event-layout test

## Repository

```text
04-tcx-telemetry/
├── tcxmon/
│   ├── generate.go
│   ├── main.go
│   └── tcx.c
├── internal/
│   └── telemetry/
│       ├── consumer.go
│       └── consumer_test.go
├── .gitignore
├── go.mod
├── Makefile
└── README.md
```

`go generate ./...` creates the `tcx_bpf*.go` and object files used by `main.go`.

## Requirements

- Linux kernel with TCX support. Linux 6.6+ is a practical baseline for this lab.
- Go 1.24+
- clang/LLVM
- libbpf/Linux BPF headers (`bpf/bpf_helpers.h`, etc.)
- root or sufficient BPF/network capabilities to load and attach the program

## Build

```bash
go mod tidy
go generate ./...
go test ./...
go build -o bin/tcxmon ./tcxmon
```

## Run

```bash
sudo ./bin/tcxmon -iface eth0
```

The eBPF classifier:

1. Counts every skb in a per-CPU map.
2. Parses Ethernet + IPv4 + UDP safely.
3. Drops UDP destination port `9999` with `TC_ACT_SHOT`.
4. Counts each drop.
5. Emits roughly 1/1024 drops as a 16-byte ring-buffer event.
6. Counts BPF ring-buffer reservation failures.

The Go process:

1. Loads the generated BPF objects.
2. Attaches the program to TCX ingress.
3. Reads ring-buffer events without blocking shutdown.
4. Pushes them to a bounded Go channel.
5. Drops telemetry rather than blocking when the queue is full.
6. Periodically sums all per-CPU counters.

## Quick veth test

```bash
sudo ip netns add tcx-peer
sudo ip link add veth-host type veth peer name veth-peer
sudo ip link set veth-peer netns tcx-peer
sudo ip addr add 10.10.0.1/24 dev veth-host
sudo ip link set veth-host up
sudo ip netns exec tcx-peer ip addr add 10.10.0.2/24 dev veth-peer
sudo ip netns exec tcx-peer ip link set lo up
sudo ip netns exec tcx-peer ip link set veth-peer up

sudo ./bin/tcxmon -iface veth-host
```

In another terminal, generate traffic:

```bash
sudo ip netns exec tcx-peer bash -c 'echo test >/dev/udp/10.10.0.1/9999'
sudo ip netns exec tcx-peer bash -c 'echo pass >/dev/udp/10.10.0.1/9998'
```

Cleanup:

```bash
sudo ip netns del tcx-peer
sudo ip link del veth-host 2>/dev/null || true
```

## Production extensions

- Export aggregate counters and userspace queue drops to Prometheus.
- Replace the fixed UDP port with a configuration map.
- Add IPv6 and VLAN parsing.
- Separate ingress and egress BPF programs.
- Compare TCX counters against NIC hardware counters and account for GRO/GSO/redirect behavior.
- Convert monotonic `bpf_ktime_get_ns()` timestamps intentionally if wall-clock time is required.
