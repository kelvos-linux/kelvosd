
package top

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kelvosd/kelvosd/internal/config"
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
	services []serviceDefinition
	service  map[string]protocolStats

	last     time.Time
	lastPkts uint64
	lastByte uint64
	pktRate  float64
	byteRate float64

	width  int
	height int
	page   int
	paused bool
	quitting bool
}

type protocolRow struct {
	name    string
	packets uint64
	bytes   uint64
}

type serviceDefinition struct {
	name         string
	protocol     uint8
	protocolName string
	ports        map[uint16]bool
}

type tickMsg time.Time

var (
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#67e8f9"))

	panelStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#374151")).
		Padding(0, 1)

	mutedStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#9ca3af"))

	headingStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#67e8f9"))

	selectedStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#67e8f9"))
)

func New(out io.Writer, iface, logPath string, cfg config.Config) *Dashboard {
	now := time.Now()

	d := &Dashboard{
		out:      out,
		iface:    iface,
		logPath:  logPath,
		started:  now,
		last:     now,
		protocol: make(map[string]protocolStats),
		service:  make(map[string]protocolStats),
	}

	// Build unique service definitions.
	seen := make(map[string]bool)

	for _, port := range cfg.Ports {
		for _, protocolName := range port.Protocols {
			protocol, ok := cfg.Protocols[protocolName]
			if !ok {
				continue
			}

			definition := serviceDefinition{
				name:         port.Service,
				protocol:     protocol,
				protocolName: strings.ToUpper(protocolName),
				ports:        make(map[uint16]bool),
			}

			for _, number := range port.Numbers {
				definition.ports[number] = true
			}

			if !seen[definition.key()] {
				d.services = append(d.services, definition)
				seen[definition.key()] = true
			}
		}
	}

	return d
}

// Add is safe to call from the event collection goroutine.
func (d *Dashboard) Add(event events.TrafficEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	size := uint64(event.IPTotalLen)

	d.packets++
	d.bytes += size

	protocol := event.Protocol()
	stats := d.protocol[protocol]
	stats.packets++
	stats.bytes += size
	d.protocol[protocol] = stats

	for _, service := range d.services {
		if !service.matches(event) {
			continue
		}

		key := service.key()
		stats := d.service[key]
		stats.packets++
		stats.bytes += size
		d.service[key] = stats
	}
}

func (d *Dashboard) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (d *Dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		d.width = msg.Width
		d.height = msg.Height

	case tickMsg:
		d.mu.Lock()

		if !d.paused {
			seconds := time.Since(d.last).Seconds()
			if seconds <= 0 {
				seconds = 1
			}

			d.pktRate = float64(d.packets-d.lastPkts) / seconds
			d.byteRate = float64(d.bytes-d.lastByte) / seconds

			d.lastPkts = d.packets
			d.lastByte = d.bytes
			d.last = time.Now()
		}

		d.mu.Unlock()
		return d, tick()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			d.quitting = true
			return d, tea.Quit

		case "1":
			d.page = 0
		case "2":
			d.page = 1
		case "3":
			d.page = 2
		case " ":
			d.paused = !d.paused
		}
	}

	return d, nil
}

func (d *Dashboard) View() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	var b strings.Builder

	b.WriteString(titleStyle.Render(" KELVOSD "))
	b.WriteString(" ")
	b.WriteString(mutedStyle.Render("XDP TRAFFIC MONITOR"))
	b.WriteString("  ")

	if d.paused {
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#fbbf24")).
			Render("● PAUSED"))
	} else {
		b.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("#34d399")).
			Render("● LIVE"))
	}

	b.WriteString("\n")
	b.WriteString(mutedStyle.Render(fmt.Sprintf(
		"Interface: %s   Uptime: %s   Refresh: 1s",
		d.iface,
		formatDuration(now.Sub(d.started)),
	)))
	b.WriteString("\n\n")

	switch d.page {
	case 1:
		b.WriteString(d.protocolView())
	case 2:
		b.WriteString(d.serviceView())
	default:
		b.WriteString(d.overviewView())
	}

	b.WriteString("\n")
	b.WriteString(mutedStyle.Render(
		"[1] Overview  [2] Protocols  [3] Services  [Space] Pause  [q] Quit",
	))

	if d.logPath != "" {
		b.WriteString("\n")
		b.WriteString(mutedStyle.Render("JSONL: " + d.logPath))
	}

	return b.String()
}

func (d *Dashboard) overviewView() string {
	var b strings.Builder

	cards := []string{
		metricCard("TOTAL PACKETS", fmt.Sprintf("%d", d.packets)),
		metricCard("TOTAL TRAFFIC", formatBytes(d.bytes)),
		metricCard("PACKETS / SEC", fmt.Sprintf("%.1f", d.pktRate)),
		metricCard("BANDWIDTH", formatBytes(uint64(d.byteRate))+"/s"),
	}

	b.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Top, cards...,
	))
	b.WriteString("\n\n")

	b.WriteString(headingStyle.Render("PROTOCOL DISTRIBUTION"))
	b.WriteString("\n")

	protocols := d.sortedProtocols()
	total := uint64(0)

	for _, p := range protocols {
		total += p.packets
	}

	if total == 0 {
		b.WriteString(mutedStyle.Render("Waiting for traffic..."))
	} else {
		for _, p := range protocols {
			percent := float64(p.packets) * 100 / float64(total)
			b.WriteString(fmt.Sprintf(
				"%-12s %8.2f%%  %s\n",
				p.name, percent,
				bar(percent, 24),
			))
		}
	}

	b.WriteString("\n")
	b.WriteString(headingStyle.Render("TOP SERVICES"))
	b.WriteString("\n")
	b.WriteString(d.serviceTable(5))

	return b.String()
}

func (d *Dashboard) protocolView() string {
	var b strings.Builder

	b.WriteString(headingStyle.Render("PROTOCOL STATISTICS"))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("%-16s %15s %15s\n", "PROTOCOL", "PACKETS", "BYTES"))
	b.WriteString(strings.Repeat("-", 50) + "\n")

	for _, p := range d.sortedProtocols() {
		b.WriteString(fmt.Sprintf(
			"%-16s %15d %15s\n",
			p.name, p.packets, formatBytes(p.bytes),
		))
	}

	return b.String()
}

func (d *Dashboard) serviceView() string {
	var b strings.Builder

	b.WriteString(headingStyle.Render("SERVICE MONITOR"))
	b.WriteString("\n\n")
	b.WriteString(d.serviceTable(0))

	return b.String()
}

func (d *Dashboard) serviceTable(limit int) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf(
		"%-16s %-12s %12s %12s\n",
		"SERVICE", "PROTOCOL", "PACKETS", "BYTES",
	))
	b.WriteString(strings.Repeat("-", 58) + "\n")

	type row struct {
		name     string
		protocol string
		stats    protocolStats
	}

	rows := make([]row, 0, len(d.services))

	for _, s := range d.services {
		rows = append(rows, row{
			name:     s.name,
			protocol: s.protocolName,
			stats:    d.service[s.key()],
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].stats.packets == rows[j].stats.packets {
			return rows[i].name < rows[j].name
		}
		return rows[i].stats.packets > rows[j].stats.packets
	})

	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	for _, r := range rows {
		b.WriteString(fmt.Sprintf(
			"%-16s %-12s %12d %12s\n",
			r.name, r.protocol,
			r.stats.packets, formatBytes(r.stats.bytes),
		))
	}

	return b.String()
}

func (d *Dashboard) sortedProtocols() []protocolRow {
	rows := make([]protocolRow, 0, len(d.protocol))

	for name, stats := range d.protocol {
		rows = append(rows, protocolRow{
			name: name, packets: stats.packets, bytes: stats.bytes,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].packets == rows[j].packets {
			return rows[i].name < rows[j].name
		}
		return rows[i].packets > rows[j].packets
	})

	return rows
}

func metricCard(label, value string) string {
	content := mutedStyle.Render(label) + "\n" +
		lipgloss.NewStyle().Bold(true).Render(value)

	return panelStyle.Render(content)
}

func bar(percent float64, width int) string {
	filled := int(percent * float64(width) / 100)
	if filled > width {
		filled = width
	}

	return strings.Repeat("█", filled) +
		strings.Repeat("░", width-filled)
}

func (s serviceDefinition) matches(event events.TrafficEvent) bool {
	return s.protocol == event.Transport &&
		(s.ports[event.SourcePort] || s.ports[event.DestPort])
}

func (s serviceDefinition) key() string {
	return s.name + "\x00" + s.protocolName
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
	return fmt.Sprintf(
		"%02dh %02dm %02ds",
		seconds/3600, (seconds/60)%60, seconds%60,
	)
}

// Run starts the interactive terminal UI.
func (d *Dashboard) Run() error {
	program := tea.NewProgram(
		d,
		tea.WithOutput(d.out),
		tea.WithAltScreen(),
	)
	_, err := program.Run()
	return err
}