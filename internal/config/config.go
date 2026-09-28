package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const DefaultLogFile = "/var/log/kelvos_traffic_monitor.jsonl"

type Config struct {
	TrafficMonitor TrafficMonitor   `toml:"traffic_monitor"`
	Protocols      map[string]uint8 `toml:"protocols"`
	Ports          []Port           `toml:"ports"`
	Firewall       Firewall         `toml:"firewall"`
	Rules          []Rule           `toml:"rules"`
}

type Port struct {
	Service     string   `toml:"service"`
	Numbers     []uint16 `toml:"numbers"`
	Protocols   []string `toml:"protocols"`
	Description string   `toml:"description"`
}

type TrafficMonitor struct {
	Enabled           bool   `toml:"enabled"`
	EthernetInterface string `toml:"ethernet_interface"`
	Interface         string `toml:"interface"`
	TrafficLogFile    string `toml:"traffic_log_file"`
	LogFile           string `toml:"log_file"`
}

type Firewall struct {
	DefaultIngress string `toml:"default_ingress"`
	DefaultEgress  string `toml:"default_egress"`
}

type Rule struct {
	ID               uint32   `toml:"id"`
	Action           string   `toml:"action"`
	Direction        string   `toml:"direction"`
	Protocol         string   `toml:"protocol"`
	Protocols        []string `toml:"protocols"`
	DestinationPorts []uint16 `toml:"destination_ports"`
	State            []string `toml:"state"`
	Flags            []string `toml:"flags"`
	Rate             string   `toml:"rate"`
	Burst            uint32   `toml:"burst"`
}

const PolicyStateWildcard uint8 = 255

func StateCode(state string) (uint8, bool) {
	switch strings.ToLower(state) {
	case "new":
		return 0, true
	case "established":
		return 1, true
	case "related":
		return 2, true
	case "invalid":
		return 3, true
	default:
		return 0, false
	}
}

func ParseRate(rate string) (uint64, bool) {
	parts := strings.Split(rate, "/")
	if len(parts) != 2 || parts[1] != "s" {
		return 0, false
	}
	value, err := strconv.ParseUint(parts[0], 10, 64)
	return value, err == nil && value > 0
}

func TCPFlagMask(flags []string) (uint8, bool) {
	var mask uint8
	for _, flag := range flags {
		switch strings.ToLower(flag) {
		case "syn":
			mask |= 1
		case "ack":
			mask |= 2
		case "fin":
			mask |= 4
		case "rst":
			mask |= 8
		case "psh":
			mask |= 16
		case "urg":
			mask |= 32
		default:
			return 0, false
		}
	}
	return mask, true
}

func Load(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if !c.TrafficMonitor.Enabled {
		return nil
	}
	if c.TrafficMonitor.InterfaceName() == "" {
		return errors.New("traffic_monitor.ethernet_interface is required")
	}
	for name, number := range c.Protocols {
		if number == 0 {
			return fmt.Errorf("protocols.%s must be greater than zero", name)
		}
	}
	for index, port := range c.Ports {
		if port.Service == "" {
			return fmt.Errorf("ports[%d].service is required", index)
		}
		if len(port.Numbers) == 0 {
			return fmt.Errorf("ports[%d].numbers must not be empty", index)
		}
		if len(port.Protocols) == 0 {
			return fmt.Errorf("ports[%d].protocols must not be empty", index)
		}
		for _, protocol := range port.Protocols {
			if _, ok := c.Protocols[protocol]; !ok {
				return fmt.Errorf("ports[%d] references undefined protocol %q", index, protocol)
			}
		}
	}
	if err := validateDefaultAction("firewall.default_ingress", c.Firewall.DefaultIngress); err != nil {
		return err
	}
	if err := validateDefaultAction("firewall.default_egress", c.Firewall.DefaultEgress); err != nil {
		return err
	}
	seenRuleIDs := make(map[uint32]struct{}, len(c.Rules))
	for index, rule := range c.Rules {
		if rule.ID == 0 {
			return fmt.Errorf("rules[%d].id must be greater than zero", index)
		}
		if _, seen := seenRuleIDs[rule.ID]; seen {
			return fmt.Errorf("rules[%d].id %d is duplicated", index, rule.ID)
		}
		seenRuleIDs[rule.ID] = struct{}{}
		if rule.Action == "rate_limit" {
			if rule.Direction != "ingress" {
				return fmt.Errorf("rules[%d].action rate_limit requires ingress direction", index)
			}
			if _, ok := ParseRate(rule.Rate); !ok {
				return fmt.Errorf("rules[%d].rate must be a positive count per second such as 100/s", index)
			}
			if rule.Burst == 0 {
				return fmt.Errorf("rules[%d].burst must be greater than zero", index)
			}
			if rule.Protocol == "" && len(rule.Protocols) == 0 {
				return fmt.Errorf("rules[%d].protocol is required for rate_limit", index)
			}
			if rule.Protocol != "" && len(rule.Protocols) != 0 {
				return fmt.Errorf("rules[%d] must use either protocol or protocols, not both", index)
			}
		} else {
			if err := validateDefaultAction(fmt.Sprintf("rules[%d].action", index), rule.Action); err != nil {
				return err
			}
			if rule.Rate != "" || rule.Burst != 0 || len(rule.Flags) != 0 {
				return fmt.Errorf("rules[%d] rate, burst, and flags require action rate_limit", index)
			}
		}
		if rule.Direction != "ingress" && rule.Direction != "egress" {
			return fmt.Errorf("rules[%d].direction must be ingress or egress", index)
		}
		protocols := rule.Protocols
		if rule.Protocol != "" {
			protocols = append(protocols, rule.Protocol)
		}
		for _, protocol := range protocols {
			if _, ok := c.Protocols[protocol]; !ok {
				return fmt.Errorf("rules[%d] references undefined protocol %q", index, protocol)
			}
		}
		if len(rule.Flags) != 0 {
			if _, ok := TCPFlagMask(rule.Flags); !ok {
				return fmt.Errorf("rules[%d] contains an unknown TCP flag", index)
			}
			if rule.Action != "rate_limit" || rule.Protocol != "tcp" {
				return fmt.Errorf("rules[%d].flags requires a TCP rate_limit rule", index)
			}
		}
		for _, state := range rule.State {
			if _, ok := StateCode(state); !ok {
				return fmt.Errorf("rules[%d] has unknown state %q", index, state)
			}
		}
	}
	return nil
}

func validateDefaultAction(field, action string) error {
	if action == "" {
		return nil
	}
	if action != "allow" && action != "drop" {
		return fmt.Errorf("%s must be allow or drop", field)
	}
	return nil
}

func (c Config) LogPath() string {
	if c.TrafficMonitor.TrafficLogFile != "" {
		return c.TrafficMonitor.TrafficLogFile
	}
	if c.TrafficMonitor.LogFile != "" {
		return c.TrafficMonitor.LogFile
	}
	return DefaultLogFile
}

func (c Config) ServiceFor(protocol uint8, sourcePort, destinationPort uint16) string {
	for _, port := range c.Ports {
		matchesPort := false
		for _, number := range port.Numbers {
			if number == sourcePort || number == destinationPort {
				matchesPort = true
				break
			}
		}
		if !matchesPort {
			continue
		}
		for _, protocolName := range port.Protocols {
			if c.Protocols[protocolName] == protocol {
				return port.Service
			}
		}
	}
	return "Unknown"
}

func (m TrafficMonitor) InterfaceName() string {
	if m.EthernetInterface != "" {
		return m.EthernetInterface
	}
	return m.Interface
}
