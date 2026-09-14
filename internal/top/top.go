package top

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/kelvosd/kelvosd/internal/events"
)

type protocolStats struct {
	packets uint64
	bytes   uint64
}

type Dashboard struct {
	mu       sync.Mutex
	out      io.Writer
	iface    string
	logPath  string
	started  time.Time
	packets  uint64
	bytes    uint64
	protocol map[string]protocolStats
	last     time.Time
	lastPkts uint64
	lastByte uint64
}

func New(out io.Writer, iface, logPath string) *Dashboard {
	now := time.Now()
	return &Dashboard{out: out, iface: iface, logPath: logPath, started: now, last: now, protocol: make(map[string]protocolStats)}
}

func (d *Dashboard) Add(event events.TrafficEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.packets++
	d.bytes += uint64(event.IPTotalLen)
	protocol := event.Protocol()
	stats := d.protocol[protocol]
	stats.packets++
	stats.bytes += uint64(event.IPTotalLen)
	d.protocol[protocol] = stats
}

func (d *Dashboard) Render() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	interval := now.Sub(d.last).Seconds()
	if interval <= 0 {
		interval = 1
	}
	packetRate := float64(d.packets-d.lastPkts) / interval
	byteRate := float64(d.bytes-d.lastByte) / interval
	d.last = now
	d.lastPkts = d.packets
	d.lastByte = d.bytes

	protocols := make([]protocolRow, 0, len(d.protocol))
	for name, stats := range d.protocol {
		protocols = append(protocols, protocolRow{name: name, packets: stats.packets, bytes: stats.bytes})
	}
	sort.Slice(protocols, func(i, j int) bool {
		if protocols[i].packets == protocols[j].packets {
			return protocols[i].name < protocols[j].name
		}
		return protocols[i].packets > protocols[j].packets
	})
	topProtocol := "-"
	if len(protocols) > 0 {
		topProtocol = protocols[0].name
	}

	fmt.Fprint(d.out, "\033[H\033[2J")
	fmt.Fprintf(d.out, "KELVOSD TRAFFIC TOP   %s\n", now.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(d.out, "Interface: %-12s  Uptime: %-12s  Top protocol: %s\n", d.iface, formatDuration(now.Sub(d.started)), topProtocol)
	fmt.Fprintf(d.out, "Packets: %-12d  Traffic: %-12s  Rate: %.1f pkt/s  %s/s\n\n", d.packets, formatBytes(d.bytes), packetRate, formatBytes(uint64(byteRate)))
	fmt.Fprintln(d.out, "PROTOCOL          PACKETS          BYTES")
	fmt.Fprintln(d.out, "-----------------------------------------")
	for _, protocol := range protocols {
		fmt.Fprintf(d.out, "%-16s  %-15d  %s\n", protocol.name, protocol.packets, formatBytes(protocol.bytes))
	}
	fmt.Fprintf(d.out, "\nLogging JSONL to %s\nPress Ctrl+C to stop.\n", d.logPath)
}

type protocolRow struct {
	name    string
	packets uint64
	bytes   uint64
}

func formatBytes(value uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	amount := float64(value)
	unit := 0
	for amount >= 1024 && unit < len(units)-1 {
		amount /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", amount, units[unit])
}

func formatDuration(value time.Duration) string {
	seconds := int64(value.Seconds())
	return fmt.Sprintf("%02dh %02dm %02ds", seconds/3600, (seconds/60)%60, seconds%60)
}
