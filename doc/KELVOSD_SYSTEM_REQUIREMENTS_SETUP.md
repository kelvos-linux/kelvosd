# KelvoSD System Requirements and Setup

## 1. Overview

KelvoSD is a Linux userspace application with an eBPF/XDP packet-processing
program. The project includes:

- A Go userspace loader with a Cobra CLI
- An eBPF/XDP program in `bpf/xdp_prog.c`
- Go eBPF libraries for loading and managing eBPF programs
- Go JSON and TOML libraries for event output and configuration
- Clang and LLVM for compiling the eBPF program
- CMake and Make for the build process

This guide targets Ubuntu 24.04 LTS or later on an x86-64 system.

## 2. System Requirements

### Hardware

- CPU: 2 cores minimum; 4 or more recommended
- Memory: 2 GB minimum; 4 GB or more recommended
- Free disk space: at least 1 GB

### Software

- Ubuntu x86-64/amd64
- CMake and Make
- Clang and LLVM
- Go 1.23 or newer
- Linux userspace headers
- A network interface for XDP attachment and testing

The current BPF build configuration uses the x86 architecture and the
following include directory:

```text
/usr/include/x86_64-linux-gnu
```

## 3. Install Dependencies

Update the package index and install the required packages:

```bash
sudo apt update
sudo apt install \
    cmake \
    clang \
    llvm \
    linux-libc-dev
```

Install `bpftool` for optional kernel and eBPF diagnostics:

```bash
sudo apt install bpftool
```

## 4. Verify the Environment

Verify the compiler and build tools:

```bash
go version
clang --version
cmake --version
make --version
```

Verify the required headers and architecture:

```bash
uname -m
uname -r
ls /usr/include/linux/bpf.h
find /usr/include -path '*/asm/types.h' -print
```

The expected architecture is `x86_64`. The architecture-specific header
should normally be available at:

```text
/usr/include/x86_64-linux-gnu/asm/types.h
```

## 5. Kernel and Network Requirements

The running kernel must support eBPF and XDP. Recent Ubuntu kernels normally
provide the required functionality.

Check whether the BPF filesystem is mounted:

```bash
mount | grep bpf
ls /sys/fs/bpf
```

If necessary, mount it with:

```bash
sudo mount -t bpf bpf /sys/fs/bpf
```

If `bpftool` is installed, inspect kernel support with:

```bash
sudo bpftool feature probe
```

List available network interfaces and select the interface to monitor:

```bash
ip link
```

The XDP program is defined in `bpf/xdp_prog.c` and uses the `xdp` section.
Loading and attaching the program normally requires root privileges or the
appropriate Linux capabilities.

## 6. Build and Run

From the project root, configure and build the project:

```bash
mkdir -p build
cd build
cmake ..
make -j"$(nproc)"
```

The build should produce the loader and copy the configuration file to:

```text
build/kelvos_config.toml
```

The example configuration is located at:

```text
config/kelvos_config.toml
```

Build and run the Go userspace loader from the repository root:

```bash
go build -o kelvosd ./cmd/kelvosd
./kelvosd validate --config config/kelvos_config.toml
sudo ./kelvosd run --config config/kelvos_config.toml --object build/xdp_prog.o
```

The `run` command requires the privileges needed to attach XDP and accepts
`--interface`, `--object`, and `--log` overrides.

### Clean rebuild

Perform a clean rebuild after changing CMake settings, compiler flags,
include paths, or library dependencies:

```bash
cd /path/to/kelvosd
rm -rf build
mkdir build
cd build
cmake ..
make -j"$(nproc)"
```

## 7. Troubleshooting

### `libbpf` or Jansson is not found

Install the corresponding development packages and verify them with
`pkg-config`:

```bash
sudo apt install libbpf-dev libjansson-dev
pkg-config --modversion libbpf
pkg-config --modversion jansson
```

### `asm/types.h` is not found

Confirm that the architecture-specific header exists:

```bash
find /usr/include -path '*/asm/types.h' -print
```

For x86-64, the BPF compiler must include:

```text
-I/usr/include/x86_64-linux-gnu
```

### BPF or XDP loading fails

Check kernel messages, loaded programs, and maps:

```bash
dmesg | tail
sudo bpftool prog show
sudo bpftool map show
```

Also confirm that the selected network interface exists and that the loader
is run with sufficient privileges.

### Build diagnostics

Reconfigure the project and run a verbose build:

```bash
cd build
cmake ..
make VERBOSE=1
```

## 8. Setup Checklist

- [ ] Ubuntu x86-64 is installed.
- [ ] Required packages are installed.
- [ ] `libbpf` and Jansson are available through `pkg-config`.
- [ ] Linux BPF headers are present.
- [ ] The kernel supports eBPF and XDP.
- [ ] A suitable network interface is available.
- [ ] The project builds successfully.
- [ ] The loader is run with the required privileges.