package main

import (
	"encosing/json"
	"fmt"
	"os"

	// netlink communicates with the Linux kernel network subsystem
	// via Netlink sockets (equivalent to running `ip link`, `ip addr`, etc.).
	"github.com/vishvanansa/netlink"
	// netns manages Linux network namespaces, typically backed by
	// namespace file descriptors in /var/run/netns/<name>.
	"github.com/vishvananda/netns"
)

// result represents the inventory metadata of a network interface within a namespace.
// Struct tags define how each field is formatted when serialized to JSON.
type result struct {
	Namespace string `json:"namespace"` // Name of the network namespace where the interface lives
	Name      string `json:"name"`      // Network interface name (e.g., "eth0", "veth0")
	Index     int    `json:"index"`     // Kernel interface index (ifindex), unique per namespace
	MTU       int    `json:"mtu"`       // Maximum Transmission Unit in bytes (e.g., 1500, or 9000 for jumbo frames)
	State     string `json:"state"`     // Operational state (e.g., "up", "down", "unknown")
	RXQueues  int    `json:"rx_queues"` // Number of hardware/software receive queues (crucial for RSS / XDP fast path)
	TXQueues  int    `json:"tx_queues"` // Number of hardware/software transmit queues (crucial for XPS multi-queue fast path)
}

// inspect queries the Linux kernel for attributes of a network interface
// residing inside a specific network namespace.
func inspect(nsName, ifName string) (result, error) {
	// 1. Locate and open the network namespace file descriptor by name (/var/run/netns/<nsName>).
	ns, err := netns.GetFromName(nsName)
	if err != nil {
		return result{}, fmt.Errorf("open netns %q: %w", nsName, err)
	}
	defer ns.Close() // Ensure the namespace file descriptor is released when done

	// 2. Open a Netlink socket handle specifically bound to the target namespace.
	// NewHandleAt targets the netns without switching the Go runtime's OS thread,
	// making it safe for concurrent Go execution.
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return result{}, fmt.Errorf("netlink handle: %w", err)
	}
	defer h.Close() // Close the Netlink socket handle

	// 3. Query the kernel (via RTM_GETLINK netlink request) for interface details.
	link, err := h.LinkByName(ifName)
	if err != nil {
		return result{}, fmt.Errorf("lookup %q: %w", ifName, err)
	}

	// 4. Retrieve generic attributes (Attrs) common to all link types.
	a := link.Attrs()

	// 5. Populate and return the inventory struct.
	return result{
		Namespace: nsName,
		Name:      a.Name,
		Index:     a.Index,
		MTU:       a.MTU,
		State:     a.OperState.String(),
		RXQueues:  a.NumRxQueues,
		TXQueues:  a.NumTxQueues,
	}, nil
}

func main() {
	// Expect exactly two command line arguments:
	// usage: nsinspect <NETNS_NAME> <INTERFACE_NAME>
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: nsinspect NETNS IFACE")
		os.Exit(2)
	}

	// Inspect the interface inside the given namespace
	x, err := inspect(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Encode the result struct into JSON and print to standard output
	if err := json.NewEncoder(os.Stdout).Encode(x); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

//So : you target a specific Linux network namespace,
// grab an interface inside it, and inspect properties like MTU, state, index, RX queues, and TX queues.
