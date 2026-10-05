package main

// Generate Go bindings and embedded BPF bytecode from tcx.c.
//
// Run from the repository root:
//   go generate ./...
//
// Requires clang/llvm and Linux BPF headers.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux tcx tcx.c -- -O2 -g -Wall
