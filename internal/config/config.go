package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

const DefaultLogFile = "/var/log/kelvos_traffic_monitor.jsonl"

type Config struct {
	TrafficMonitor TrafficMonitor   `toml:"traffic_monitor"`
	Protocols      map[string]uint8 `toml:"protocols"`
	Ports          []Port           `toml:"ports"`
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

func (m TrafficMonitor) InterfaceName() string {
	if m.EthernetInterface != "" {
		return m.EthernetInterface
	}
	return m.Interface
}
