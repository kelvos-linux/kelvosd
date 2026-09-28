package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"

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

func loadTrafficPolicy(collection *ebpf.Collection, cfg config.Config) error {
	policy, ok := collection.Maps["traffic_policy"]
	if !ok {
		return errors.New("eBPF map traffic_policy not found")
	}
	defaultPolicy, ok := collection.Maps["traffic_default_policy"]
	if !ok {
		return errors.New("eBPF map traffic_default_policy not found")
	}
	defaultAction := uint8(1)
	if cfg.Firewall.DefaultIngress == "drop" {
		defaultAction = 2
	}
	if err := defaultPolicy.Put(uint32(0), defaultAction); err != nil {
		return fmt.Errorf("configure default ingress policy: %w", err)
	}
	ratePolicy := collection.Maps["traffic_rate_policy"]
	rateRules := collection.Maps["rate_limit_rules"]
	for _, rule := range cfg.Rules {
		if rule.Direction != "ingress" {
			continue
		}
		action := uint8(1)
		if rule.Action == "drop" {
			action = 2
		} else if rule.Action == "rate_limit" {
			action = 3
			if ratePolicy == nil || rateRules == nil {
				return errors.New("eBPF rate-limit maps not found")
			}
			ratePerSec, _ := config.ParseRate(rule.Rate)
			flagsMask, _ := config.TCPFlagMask(rule.Flags)
			rateConfig := struct {
				RatePerSec uint64
				Burst      uint32
				FlagsMask  uint8
				Padding    [3]byte
			}{RatePerSec: ratePerSec, Burst: rule.Burst, FlagsMask: flagsMask}
			if err := rateRules.Put(rule.ID, rateConfig); err != nil {
				return fmt.Errorf("configure rate limit %d: %w", rule.ID, err)
			}
		}
		protocols := rule.Protocols
		if rule.Protocol != "" {
			protocols = append(protocols, rule.Protocol)
		}
		if len(protocols) == 0 {
			protocols = []string{""}
		}
		ports := rule.DestinationPorts
		if len(ports) == 0 {
			ports = []uint16{0}
		}
		states := rule.State
		if len(states) == 0 {
			states = []string{"*"}
		}
		for _, protocolName := range protocols {
			var protocol uint8
			if protocolName != "" {
				protocol = cfg.Protocols[protocolName]
			}
			for _, number := range ports {
				for _, stateName := range states {
					state := config.PolicyStateWildcard
					if stateName != "*" {
						state, _ = config.StateCode(stateName)
					}
					key := uint64(protocol)<<40 | uint64(number)<<8 | uint64(state)
					if action == 3 {
						if err := ratePolicy.Put(key, rule.ID); err != nil {
							return fmt.Errorf("configure rate policy %d for %s port %d state %s: %w", rule.ID, protocolName, number, stateName, err)
						}
					} else if err := policy.Put(key, action); err != nil {
						return fmt.Errorf("configure rule %d for %s port %d state %s: %w", rule.ID, protocolName, number, stateName, err)
					}
				}
			}
		}
	}
	return nil
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
	if err := loadTrafficPolicy(collection, cfg); err != nil {
		return err
	}
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
	if r.Top {
		dashboard = trafficTop.New(
			r.Stdout,
			ifaceName,
			cfg.LogPath(),
			cfg,
		)

		go func() {
			if err := dashboard.Run(); err != nil {
				fmt.Fprintf(r.Stderr, "TUI error: %v\n", err)
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
		serviceName := cfg.ServiceFor(event.Transport, event.SourcePort, event.DestPort)
		if err := log.Write(event.Record(ifaceName, serviceName)); err != nil {
			return err
		}
	}
}
