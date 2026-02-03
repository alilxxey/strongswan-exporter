#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now strongswan-exporter.service || true
fi
