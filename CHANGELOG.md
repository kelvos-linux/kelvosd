# Changelog

## [1.0.0] - 2026-09-28

### Added

- Initial release of `kelvosd`.
- Linux XDP/eBPF traffic monitoring.
- XDP-based ingress firewall.
- TOML configuration.
- Protocol configuration.
- Service port configuration.
- Ingress firewall rules.
- TCP connection state tracking.
- Per-source ingress rate limiting.
- JSONL packet/event logging.
- Configuration validation.
- CLI monitoring.
- Live traffic dashboard.
- systemd service deployment.

### Known limitations

- Egress rules are accepted in configuration but are not currently enforced.
- Configured service ports label events but do not independently filter emitted packets.
- IPv6 extension headers are not currently parsed.
- Under a drop-by-default policy, rate-limited packets may be dropped while tokens remain available.
