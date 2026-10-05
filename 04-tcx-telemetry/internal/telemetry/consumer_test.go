package telemetry

import (
	"encoding/binary"
	"testing"
)

// TestDecodeExactLayout verifies byte-for-byte deserialization of the 16-byte C event struct.
func TestDecodeExactLayout(t *testing.T) {
	raw := make([]byte, EventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 0x0102030405060708)
	binary.LittleEndian.PutUint32(raw[8:12], 17)
	binary.LittleEndian.PutUint32(raw[12:16], 1)

	got, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if got.TimestampNS != 0x0102030405060708 {
		t.Fatalf("TimestampNS = %#x", got.TimestampNS)
	}
	if got.IfIndex != 17 {
		t.Fatalf("IfIndex = %d", got.IfIndex)
	}
	if got.Reason != 1 {
		t.Fatalf("Reason = %d", got.Reason)
	}
}

// TestDecodeRejectsWrongSize ensures packets of unexpected size are rejected.
func TestDecodeRejectsWrongSize(t *testing.T) {
	for _, size := range []int{0, 15, 17, 32} {
		if _, err := Decode(make([]byte, size)); err == nil {
			t.Fatalf("Decode(%d bytes) unexpectedly succeeded", size)
		}
	}
}

// TestCountersAggregation verifies that per-CPU counter slices sum correctly.
func TestCountersAggregation(t *testing.T) {
	perCPU := []Counters{
		{Packets: 100, Dropped: 10, RingbufReserveFailures: 1},
		{Packets: 250, Dropped: 25, RingbufReserveFailures: 0},
		{Packets: 50, Dropped: 5, RingbufReserveFailures: 2},
	}

	var total Counters
	for _, cpu := range perCPU {
		total.Packets += cpu.Packets
		total.Dropped += cpu.Dropped
		total.RingbufReserveFailures += cpu.RingbufReserveFailures
	}

	if total.Packets != 400 {
		t.Errorf("total Packets: got %d, want 400", total.Packets)
	}
	if total.Dropped != 40 {
		t.Errorf("total Dropped: got %d, want 40", total.Dropped)
	}
	if total.RingbufReserveFailures != 3 {
		t.Errorf("total RingbufReserveFailures: got %d, want 3", total.RingbufReserveFailures)
	}
}
