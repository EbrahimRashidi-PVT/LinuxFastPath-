package telemetry

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// EventSize is the exact binary size (in bytes) of struct event defined in tcx.c.
//   - ts_ns:   __u64 (8 bytes, offset 0..7)
//   - ifindex: __u32 (4 bytes, offset 8..11)
//   - reason:  __u32 (4 bytes, offset 12..15)
// Total size = 16 bytes. Because the 8-byte member is at offset 0, the struct
// is naturally 8-byte aligned with 0 padding bytes.
const EventSize = 16

// Event represents a sampled packet-drop event emitted by the eBPF kernel program.
// It mirrors byte-for-byte `struct event` from tcx.c.
type Event struct {
	TimestampNS uint64 // Monotonic timestamp from bpf_ktime_get_ns()
	IfIndex     uint32 // Interface index (ifindex) where the packet arrived
	Reason      uint32 // Drop reason code (e.g., DROP_REASON_UDP_PORT = 1)
}

// EventJob encapsulates an Event for worker queue dispatch and asynchronous processing.
type EventJob struct {
	E Event
}

// Counters holds aggregate packet statistics accumulated in the BPF per-CPU array map.
// It mirrors `struct counters` from tcx.c:
//   - packets:                  total packets processed
//   - dropped:                  total packets dropped (TC_ACT_SHOT)
//   - ringbuf_reserve_failures: telemetry events lost due to full BPF ring buffer
type Counters struct {
	Packets                uint64 `json:"packets"`
	Dropped                uint64 `json:"dropped"`
	RingbufReserveFailures uint64 `json:"ringbuf_reserve_failures"`
}

// Decode unpacks a raw 16-byte little-endian byte slice from the BPF ring buffer
// into a typed Event struct.
//
// If the payload does not match EventSize exactly, Decode returns an error to
// prevent reading truncated or corrupted kernel memory.
func Decode(raw []byte) (Event, error) {
	if len(raw) != EventSize {
		return Event{}, fmt.Errorf("event size mismatch: got %d bytes, want %d bytes", len(raw), EventSize)
	}

	return Event{
		TimestampNS: binary.LittleEndian.Uint64(raw[0:8]),
		IfIndex:     binary.LittleEndian.Uint32(raw[8:12]),
		Reason:      binary.LittleEndian.Uint32(raw[12:16]),
	}, nil
}

// ReadCounters queries the BPF_MAP_TYPE_PERCPU_ARRAY stats map at index 0 and
// aggregates the per-core metrics into a single cumulative Counters struct.
//
// In Linux eBPF, per-CPU maps maintain separate memory per CPU core to prevent
// cross-core cache line bouncing. Looking up key 0 returns a slice of Counters
// (one element per CPU core). We iterate over the slice and sum each metric.
func ReadCounters(statsMap *ebpf.Map) (Counters, error) {
	if statsMap == nil {
		return Counters{}, errors.New("nil stats map")
	}

	key := uint32(0)
	var perCPU []Counters
	if err := statsMap.Lookup(&key, &perCPU); err != nil {
		return Counters{}, fmt.Errorf("lookup per-CPU stats: %w", err)
	}

	var total Counters
	for _, cpu := range perCPU {
		total.Packets += cpu.Packets
		total.Dropped += cpu.Dropped
		total.RingbufReserveFailures += cpu.RingbufReserveFailures
	}

	return total, nil
}

// Consume streams sampled telemetry events from the BPF ring-buffer map until
// ctx is cancelled.
//
// Cancellation Architecture:
//  1. ringbuf.Reader.Read() is a blocking call that waits for events from the kernel.
//  2. A dedicated helper goroutine monitors <-ctx.Done(). When the context is cancelled,
//     it calls rd.Close().
//  3. Closing the reader unblocks any pending Read() immediately with ringbuf.ErrClosed,
//     enabling instant, deadlock-free shutdown.
func Consume(ctx context.Context, events *ebpf.Map, handle func(Event) error) error {
	if events == nil {
		return errors.New("nil events map")
	}
	if handle == nil {
		return errors.New("nil event handler")
	}

	// Create the memory-mapped ring-buffer reader for the BPF ringbuf map
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Synchronizer channel ensuring the cancellation goroutine stops when Consume returns
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Force unblock rd.Read() by closing the reader
			_ = rd.Close()
		case <-done:
			// Consume finished normally; exit helper goroutine
		}
	}()
	defer close(done)

	for {
		rec, err := rd.Read()
		if err != nil {
			// If shutdown was requested and reader closed, exit cleanly with nil error
			if ctx.Err() != nil && errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		// Decode the 16-byte raw sample into an Event struct
		e, err := Decode(rec.RawSample)
		if err != nil {
			// Malformed telemetry events are dropped so they never crash or stall the pipeline
			continue
		}

		// Dispatch decoded event to the caller's handler callback
		if err := handle(e); err != nil {
			return fmt.Errorf("handle event: %w", err)
		}
	}
}
