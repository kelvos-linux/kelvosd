# kelvosd

 A lightweight eBPF/XDP-based traffic manager and loader for Linux.

 This repository contains an XDP/eBPF program and a Go userspace loader to build, load, and test the packet processing program.

 Contents
- `bpf/xdp_prog.c` — XDP program source written in C.
- `cmd/kelvosd/main.go` — Go userspace loader and Cobra CLI.
- `internal/config` — TOML loading and validation.
- `internal/events` — eBPF perf-event ABI decoding and JSON event shaping.
- `internal/loader` — XDP attachment and perf-buffer lifecycle.
- `internal/output` — buffered JSONL event output.
- `config/kelvos_config.toml` and `build/kelvos_config.toml` — example configuration files.
- `build/` — CMake build artifacts and helper build scripts.

 Requirements
- Linux kernel with eBPF and XDP support (recent kernel recommended).
- `clang` and `llc` (or `clang` with `-target bpf`) for compiling BPF programs.
- `cmake` and `make` for compiling the eBPF object.
- Go 1.23 or newer for the userspace CLI.
 - Linux kernel headers and the Go dependencies declared in `go.mod`.

 Quick start

 1. Build the project (out-of-tree recommended):

 ```bash
 mkdir -p build && cd build
 cmake ..
 make -j
 ```

2. Configure the loader

 Create or edit `config/kelvos_config.toml` with a `[traffic_monitor]` table and
 dynamic protocol/port policy. Example:

```toml
[traffic_monitor]
enabled = true
ethernet_interface = "enp1s0"
log_file = "/var/log/kelvos_traffic_monitor.jsonl"

[protocols]
tcp = 6
udp = 17

[[ports]]
service = "http"
numbers = [80, 8080]
protocols = ["tcp"]
description = "Web traffic"
```

Only packets matching a configured protocol and source or destination port are
sent from XDP to userspace. Add more `[[ports]]` entries without recompiling
the BPF object.

 3. Build and validate the Go CLI

 From the repository root:

 ```bash
 go mod tidy
 go build -o kelvosd ./cmd/kelvosd
 ./kelvosd validate --config config/kelvos_config.toml
 ```

 4. Load the BPF program

 Run the loader (example):

 ```bash
 sudo ./kelvosd run --config config/kelvos_config.toml --object build/xdp_prog.o
 ```

 The Cobra CLI also supports direct overrides:

 ```bash
 sudo ./kelvosd run --interface eth0 --object build/xdp_prog.o --log /tmp/traffic.jsonl
 ./kelvosd --help
 ./kelvosd run --help
 ```

 For a live terminal dashboard with total packets, traffic volume, packet/byte rates, and protocol breakdown:

 ```bash
 sudo ./kelvosd top --interface eth0 --object build/xdp_prog.o --log /tmp/traffic.jsonl
 ```

 The dashboard refreshes every second and keeps writing the same JSONL event stream. Press Ctrl+C to stop.

 The `run` command opens the perf event map, attaches `xdp_monitor` to the selected interface, and appends JSONL events to the configured log file. Use Ctrl+C to detach cleanly.

 Development notes
- BPF program sources are located under `bpf/`. Keep BPF C code minimal and avoid heavy C standard library usage.
- Use `clang` with `-O2 -target bpf` or the project CMake rules to compile the program into an object file.
- When iterating on BPF code, use `bpftool` and `ip` to inspect and manage loaded programs and maps.

 Testing and debugging
- Use `dmesg` to check kernel logs when loading fails.
- Use `bpftool prog` and `bpftool map` to list programs and maps.
- Consider enabling verbose logging in the loader to troubleshoot attach failures.

 License

 Check the repository `Packet.json` and project headers for licensing information.

 Contributing

 Feel free to open issues or submit pull requests with bug fixes or enhancements. Provide a minimal reproduction and test steps.

 Contact

 For questions, add an issue in the repository.
