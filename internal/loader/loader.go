package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/kelvosd/kelvosd/internal/config"
	"github.com/kelvosd/kelvosd/internal/events"
	"github.com/kelvosd/kelvosd/internal/output"
	trafficTop "github.com/kelvosd/kelvosd/internal/top"
	"golang.org/x/sys/unix"
)

type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
	Top    bool
}

func (r Runner) Run(ctx context.Context, cfg config.Config, objectPath string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	ifaceName := cfg.TrafficMonitor.InterfaceName()
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", ifaceName, err)
	}
	objectPath, err = filepath.Abs(objectPath)
	if err != nil {
		return fmt.Errorf("resolve eBPF object path: %w", err)
	}
	log, err := output.Open(cfg.LogPath())
	if err != nil {
		return err
	}
	defer log.Close()
	var dashboard *trafficTop.Dashboard
	if r.Top {
		dashboard = trafficTop.New(r.Stdout, ifaceName, cfg.LogPath())
		dashboard.Render()
	}

	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("load eBPF object %q: %w", objectPath, err)
	}
	if trafficEvents, ok := spec.Maps["traffic_events"]; ok {
		trafficEvents.MaxEntries = uint32(runtime.NumCPU())
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load eBPF programs: %w", err)
	}
	defer collection.Close()
	program, ok := collection.Programs["xdp_monitor"]
	if !ok {
		return errors.New("eBPF program xdp_monitor not found")
	}
	trafficEvents, ok := collection.Maps["traffic_events"]
	if !ok {
		return errors.New("eBPF map traffic_events not found")
	}
	attached, err := link.AttachXDP(link.XDPOptions{Program: program, Interface: iface.Index})
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
	}
	defer attached.Close()

	reader, err := perf.NewReader(trafficEvents, 4096)
	if err != nil {
		return fmt.Errorf("create perf reader: %w", err)
	}
	defer reader.Close()
	var realtime, monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realtime); err != nil {
		return fmt.Errorf("read realtime clock: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		return fmt.Errorf("read monotonic clock: %w", err)
	}
	clockOffset := realtime.Nano() - monotonic.Nano()
	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()
	if dashboard != nil {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					dashboard.Render()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	if !r.Top {
		fmt.Fprintf(r.Stdout, "Monitoring %s, logging to %s. Press Ctrl+C to stop.\n", ifaceName, cfg.LogPath())
	}
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read traffic event: %w", err)
		}
		if record.LostSamples != 0 {
			fmt.Fprintf(r.Stderr, "warning: lost %d samples\n", record.LostSamples)
			continue
		}
		event, err := events.Decode(record.RawSample)
		if err != nil {
			fmt.Fprintf(r.Stderr, "warning: discard event: %v\n", err)
			continue
		}
		event.TimestampNS += uint64(clockOffset)
		if dashboard != nil {
			dashboard.Add(event)
		}
		if err := log.Write(event.Record(ifaceName)); err != nil {
			return err
		}
	}
}
