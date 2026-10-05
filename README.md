# LinuxFastPath

> **Disclaimer / Status**: This repository is a **Proof of Concept (POC)** and an **initial version of the code developed for evaluation**, prototyping, and experimentation with Linux FastPath networking paradigms.

---

## Overview

A hands-on collection of high-performance Linux networking prototypes exploring the Linux FastPath, eBPF, XDP, TCX, Netlink, and kernel network subsystem architectures.

---

## Modules Overview

| Module | Technologies | Key Concepts |
| :--- | :--- | :--- |
| **[01- Namespace aware interface inventory](./01-%20Namespace%20aware%20interface%20inventory%20)** | Go, Netlink, Netns | Multi-namespace discovery, `RTM_GETLINK`, interface inventory, hardware RX/TX queue counts for RSS/XPS. |
| **[02- Read-only queue inventory](./02-%20Read-only%20queue%20inventory)** | Go, Sysfs (`/sys/class/net`) | Kernel sysfs queue discovery (`queues/rx-*`, `queues/tx-*`), NUMA node locality for high-throughput packet processing. |
| **[03-eBPF](./03-eBPF)** | C, Go, eBPF, XDP, `cilium/ebpf` | Line-rate driver-level packet filtering at the XDP layer, `bpf2go`, BPF array map kernel-userspace IPC, zero-copy packet drop (`XDP_DROP`). |
| **[04-tcx-telemetry](./04-tcx-telemetry)** | C, Go, eBPF, TCX, Ringbuf, Per-CPU Maps | Modern TCX ingress hooking (Linux 6.6+), zero-contention per-CPU aggregate counters (`BPF_MAP_TYPE_PERCPU_ARRAY`), 1/1024 sampled ring-buffer events (`BPF_MAP_TYPE_RINGBUF`), bounded worker pool with backpressure. |

---

## Prerequisites (Linux Target)

- **Kernel**: Linux 5.7+ (Linux 6.6+ recommended for TCX).
- **Toolchain**: Go 1.24+, `clang`, `llvm`, and `libbpf-dev` / kernel headers.
  ```bash
  # Debian / Ubuntu
  sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

  # Fedora / RHEL
  sudo dnf install -y clang llvm libbpf-devel kernel-devel
  ```
- **Privileges**: Root or `CAP_BPF` / `CAP_NET_ADMIN` capabilities for loading and attaching eBPF programs.

---

## Repository Structure

```text
LinuxFastPath/
├── 01- Namespace aware interface inventory/   # Namespace-aware Netlink interface scanner
├── 02- Read-only queue inventory/             # Sysfs NIC queue & NUMA topology inspector
├── 03-eBPF/                                   # XDP bare-metal packet filtering module
├── 04-tcx-telemetry/                          # TCX ingress & ring-buffer telemetry pipeline
│   ├── tcxmon/                                # Userspace daemon & eBPF C program
│   └── internal/telemetry/                    # Telemetry consumer, event decoder & counter aggregator
└── README.md
```
