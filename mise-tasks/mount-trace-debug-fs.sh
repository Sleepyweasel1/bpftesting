#!/usr/bin/env bash
#MISE description="mount tracefs and debugfs for BPF tracing"
sudo mkdir -p /sys/kernel/tracing /sys/kernel/debug
sudo mount -t tracefs tracefs /sys/kernel/tracing
sudo mount -t debugfs debugfs /sys/kernel/debug
grep -E "tracefs|debugfs" /proc/mounts