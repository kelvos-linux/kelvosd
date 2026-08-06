# kelvos_tm

 A lightweight eBPF/XDP-based traffic manager and loader for Linux.

 This repository contains an XDP/eBPF program and a simple userspace loader to build, load, and test the packet processing program.

 Contents
- `bpf/xdp_prog.c` — XDP program source written in C.
- `src/loader.c` — userspace loader that attaches the compiled BPF object to a network interface.
- `config/kelvos_tm.conf` and `build/kelvos_tm.conf` — example configuration files.
- `build/` — CMake build artifacts and helper build scripts.

 Requirements
- Linux kernel with eBPF and XDP support (recent kernel recommended).
- `clang` and `llc` (or `clang` with `-target bpf`) for compiling BPF programs.
- `cmake` and `make` for building the userspace loader.
- `libbpf` or the appropriate BPF userspace libraries installed (system package or bundled headers), and kernel headers.

 Quick start

 1. Build the project (out-of-tree recommended):

 ```bash
 mkdir -p build && cd build
 cmake ..
 make -j
 ```

 2. Configure the loader

 Copy or edit `config/kelvos_tm.conf` to point to the desired interface and options.

 3. Load the BPF program

 Run the loader (example):

 ```bash
 sudo ./loader <interface> [options]
 ```

 Replace `<interface>` with your network device (e.g. `eth0`). The loader will open and attach the BPF program built under `build/`.

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