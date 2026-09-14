package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/kelvosd/kelvosd/internal/config"
	"github.com/kelvosd/kelvosd/internal/loader"
	"github.com/spf13/cobra"
)

type Options struct {
	ConfigPath string
	ObjectPath string
	Interface  string
	LogPath    string
}

func New(version string, stdout, stderr io.Writer) *cobra.Command {
	var opts Options
	root := &cobra.Command{Use: "kelvosd", Short: "XDP traffic monitor", SilenceUsage: true}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.Version = version
	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	root.AddCommand(runCommand(&opts, stdout, stderr, false), runCommand(&opts, stdout, stderr, true), validateCommand(&opts, stdout))
	return root
}

func runCommand(opts *Options, stdout, stderr io.Writer, topMode bool) *cobra.Command {
	use := "run"
	short := "Attach the XDP program and write traffic events"
	if topMode {
		use = "top"
		short = "Attach the XDP program and show live traffic statistics"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Example: "  sudo kelvosd run --config config/kelvos_config.toml --object build/xdp_prog.o\n" +
			"  sudo kelvosd run --interface eth0 --log /tmp/traffic.jsonl",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(opts.ConfigPath)
			if err != nil {
				return err
			}
			if opts.Interface != "" {
				cfg.TrafficMonitor.EthernetInterface = opts.Interface
			}
			if opts.LogPath != "" {
				cfg.TrafficMonitor.TrafficLogFile = opts.LogPath
			}
			if !cfg.TrafficMonitor.Enabled {
				fmt.Fprintln(stdout, "Traffic monitor is disabled.")
				return nil
			}
			return loader.Runner{Stdout: stdout, Stderr: stderr, Top: topMode}.Run(cmd.Context(), cfg, opts.ObjectPath)
		},
	}
	cmd.Flags().StringVarP(&opts.ConfigPath, "config", "c", "config/kelvos_config.toml", "path to TOML configuration")
	cmd.Flags().StringVarP(&opts.ObjectPath, "object", "o", "build/xdp_prog.o", "path to compiled eBPF object")
	cmd.Flags().StringVarP(&opts.Interface, "interface", "i", "", "network interface (overrides config)")
	cmd.Flags().StringVarP(&opts.LogPath, "log", "l", "", "JSONL output path (overrides config)")
	return cmd
}

func validateCommand(opts *Options, stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a TOML configuration without loading eBPF",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(opts.ConfigPath)
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "valid: interface=%s log=%s\n", cfg.TrafficMonitor.InterfaceName(), cfg.LogPath())
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.ConfigPath, "config", "c", "config/kelvos_config.toml", "path to TOML configuration")
	return cmd
}

func Execute(version string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	root := New(version, os.Stdout, os.Stderr)
	root.SetContext(ctx)
	if err := root.Execute(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return nil
}
