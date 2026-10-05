package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type inventory struct {
	Device string   `json:"device"`
	RX     []string `json:"rx_queues"`
	TX     []string `json:"tx_queues"`
	NUMA   string   `json:"numa_node,omitempty"`
}

func queues(base, pattern string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(base, "queues", pattern))
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(paths))

	for _, p := range paths {
		out = append(out, filepath.Base(p))
	}

	return out, nil
}

func run(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return fmt.Errorf("invalid interface name %q", name)
	}

	base := filepath.Join("/sys/class/net", name)

	if _, err := os.Stat(base); err != nil {
		return fmt.Errorf("interface: %w", err)
	}

	rx, err := queues(base, "rx-*")
	if err != nil {
		return err
	}

	tx, err := queues(base, "tx-*")
	if err != nil {
		return err
	}

	numa, err := os.ReadFile(filepath.Join(base, "device/numa_node"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	x := inventory{
		Device: name,
		RX:     rx,
		TX:     tx,
		NUMA:   strings.TrimSpace(string(numa)),
	}

	return json.NewEncoder(os.Stdout).Encode(x)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: queues IFACE")
		os.Exit(2)
	}

	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
