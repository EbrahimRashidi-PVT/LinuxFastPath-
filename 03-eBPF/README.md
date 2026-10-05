# 03-eBPF: FastPath XDP UDP Port Filter

This module implements a bare-metal packet filtering pipeline using **Linux eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)** managed from Go using `cilium/ebpf`.

---

## Architecture Overview

```
                      [ Physical / Virtual NIC ]
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │      XDP Hook (Driver)    │ ◄── xdp.c (xdp_policy)
                    └─────────────┬─────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
            [ XDP_DROP ]                    [ XDP_PASS ]
      (Discarded at NIC level;         (Passed to Kernel Stack:
       Zero sk_buff allocation)         Routing, TCP/IP, Sockets)
```

1. **Kernel Space (`xdp.c`)**:
   - Executes inside the NIC driver at the ingress hook point before Linux allocates a socket buffer (`sk_buff`).
   - Parses the Ethernet, IPv4, and UDP headers while satisfying all static bounds checks enforced by the eBPF verifier.
   - Queries a BPF array map (`blocked_port`) for the target UDP port.
   - Returns `XDP_DROP` if the packet matches, or `XDP_PASS` otherwise.

2. **User Space (`gen.go`)**:
   - Uses `github.com/cilium/ebpf` and `github.com/cilium/ebpf/link` to load the compiled eBPF bytecode into kernel memory.
   - Communicates dynamically with the eBPF program by writing the configured port to the `blocked_port` map at runtime.
   - Attaches `XdpPolicy` to the specified network interface index (`ifindex`) using netlink/bpf_link.
   - Traps termination signals (`SIGINT`, `SIGTERM`) for graceful detachment.

---

## Prerequisites (for running on Linux)

To compile the C eBPF bytecode and execute the program on Linux, ensure you have:
- Linux Kernel version **5.7+** (with XDP and `bpf_link` support enabled).
- `clang` & `llvm` (with BPF target support: `clang -target bpf`).
- Standard Linux header files or `libbpf-dev`:
  ```bash
  # Debian/Ubuntu
  sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

  # Fedora/RHEL
  sudo dnf install -y clang llvm libbpf-devel kernel-devel
  ```

---

## How to Build and Run (Later on Linux)

### 1. Generate Go Bindings from C
Run `go generate` inside this directory to invoke `bpf2go`:
```bash
go generate ./...
```
This compiles `xdp.c` and outputs `fastpath_bpfel.go` and `fastpath_bpfeb.go`.

### 2. Build the Go Binary
```bash
go build -o fastpath .
```

### 3. Run with Sudo (Root or CAP_BPF / CAP_NET_ADMIN required)
```bash
# Block UDP port 53 (DNS) on interface eth0:
sudo ./fastpath -iface eth0 -port 53

# Pass all traffic (policy inactive):
sudo ./fastpath -iface eth0 -port 0
```
