#!/usr/bin/env bash

set -euo pipefail

PREFIX="/usr"
SYSCONFDIR="/etc/kelvosd"
LIBDIR="/usr/lib/kelvosd"
LOGDIR="/var/log/kelvosd"

echo "Installing kelvosd..."

install -d "$SYSCONFDIR"
install -d "$LIBDIR"
install -d "$LOGDIR"

install -m 0755 build/kelvosd "$PREFIX/bin/kelvosd"

if [ -f build/kelvosd.bpf.o ]; then
    install -m 0644 build/kelvosd.bpf.o "$LIBDIR/kelvosd.bpf.o"
fi

if [ ! -f "$SYSCONFDIR/kelvosd.toml" ]; then
    install -m 0644 config/kelvos_config.toml \
        "$SYSCONFDIR/kelvosd.toml"
else
    echo "Existing configuration preserved."
fi

install -m 0644 packaging/systemd/kelvosd.service \
    /usr/lib/systemd/system/kelvosd.service

systemctl daemon-reload

echo
echo "Installation complete."
echo
echo "Validate:"
echo "  sudo kelvosd config validate"
echo
echo "Start:"
echo "  sudo systemctl enable --now kelvosd"
echo
echo "Status:"
echo "  sudo systemctl status kelvosd"
