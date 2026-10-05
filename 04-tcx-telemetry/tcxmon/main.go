//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"example.com/tcx-telemetry/internal/telemetry"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type eventJob struct {
	e telemetry.Event
}

type counters struct {
	Packets                uint64
	Dropped                uint64
	RingbufReserveFailures uint64
}

func main() {
	// we use flag package to parse the command line arguments
	// ifaceName is the name of the interface to attach the TCX program to
	// workers is the number of workers to process the telemetry events
	// queueSize is the size of the bounded telemetry queue
	ifaceName := flag.String("iface", "", "network interface to attach TCX ingress program to")
	workers := flag.Int("workers", 2, "number of telemetry workers")
	queueSize := flag.Int("queue", 256, "bounded telemetry queue size")
	flag.Parse()

	if *ifaceName == "" {
		fmt.Fprintln(os.Stderr, "-iface is required")
		os.Exit(2)
	}
	if *workers < 1 || *queueSize < 1 {
		fmt.Fprintln(os.Stderr, "-workers and -queue must be positive")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(ctx, logger, *ifaceName, *workers, *queueSize); err != nil {
		logger.Error("tcx monitor failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, ifaceName string, workers, queueSize int) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	var objs tcxObjects // here we load the BPF objects from the tcx.c file
	if err := loadTcxObjects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer objs.Close()

	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.CountAndFilter,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach TCX ingress on %s: %w", iface.Name, err)
	}
	defer lnk.Close()

	logger.Info("TCX attached", "interface", iface.Name, "ifindex", iface.Index, "drop_udp_port", 9999)

	jobs := make(chan eventJob, queueSize)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				logger.Warn("sampled drop",
					"worker", workerID,
					"ifindex", job.E.IfIndex,
					"reason", job.E.Reason,
					"ktime_ns", job.E.TimestampNS,
				)
			}
		}(i)
	}

	consumeErr := make(chan error, 1)
	go func() {
		consumeErr <- telemetry.Consume(ctx, objs.Events, func(e telemetry.Event) error {
			select {
			case jobs <- eventJob{E: e}:
			default:
				// Deliberately drop telemetry under overload rather than blocking
				// the ring-buffer reader. Export this count as a metric in prod.
				logger.Warn("telemetry queue full; dropping sampled event")
			}
			return nil
		})
	}()

	statsErr := make(chan error, 1)
	go func() {
		statsErr <- reportStats(ctx, logger, objs.Stats)
	}()

	var runErr error
	select {
	case <-ctx.Done():
		runErr = nil
	case err := <-consumeErr:
		if err != nil {
			runErr = fmt.Errorf("consume telemetry: %w", err)
		}
	case err := <-statsErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			runErr = fmt.Errorf("report stats: %w", err)
		}
	}

	close(jobs)
	wg.Wait()
	return runErr
}

func reportStats(ctx context.Context, logger *slog.Logger, statsMap *ebpf.Map) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	key := uint32(0)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var perCPU []counters
			if err := statsMap.Lookup(&key, &perCPU); err != nil {
				return fmt.Errorf("lookup per-CPU stats: %w", err)
			}

			var total counters
			for _, cpu := range perCPU {
				total.Packets += cpu.Packets
				total.Dropped += cpu.Dropped
				total.RingbufReserveFailures += cpu.RingbufReserveFailures
			}

			logger.Info("aggregate counters",
				"packets", total.Packets,
				"dropped", total.Dropped,
				"ringbuf_reserve_failures", total.RingbufReserveFailures,
			)
		}
	}
}
