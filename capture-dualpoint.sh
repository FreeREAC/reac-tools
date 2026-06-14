#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

# Dual-point REAC capture for loss/reorder/cross-mix analysis.
# Run from the operator host (laptop) on the 192.168.10.x rig network.
#
# Captures the SAME stream simultaneously at console-side (router1) and
# box-side (router2) so reac.cli / a seq-diff can measure real loss.
#
# busybox tcpdump on OpenWrt 25.12 has NO standalone `timeout` -> background
# the capture and kill it after N seconds.
#
# Usage: ./capture-dualpoint.sh [SECONDS] [IFACE]   (defaults: 15 lan1)
set -e
SECS="${1:-15}"
IFACE="${2:-lan1}"
R1=192.168.10.1   # console side
R2=192.168.10.2   # stagebox side
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="capture-$STAMP"
mkdir -p "$OUT"

echo "Capturing ${SECS}s on $IFACE at both routers -> $OUT/"
# -e keeps the ethernet header so the VLAN tag is visible (needed for cross-mix)
CMD='tcpdump -i '"$IFACE"' -nn -e -xx "ether proto 0x8819" > /tmp/cap.txt 2>/dev/null & P=$!; sleep '"$SECS"'; kill $P 2>/dev/null; cat /tmp/cap.txt'
ssh -o BatchMode=yes "root@$R1" "$CMD" > "$OUT/console-r1-$IFACE.txt" &
ssh -o BatchMode=yes "root@$R2" "$CMD" > "$OUT/box-r2-$IFACE.txt" &
wait
echo "Done. Analyze with:"
echo "  python3 -m reac.cli $OUT/console-r1-$IFACE.txt"
echo "  python3 -m reac.cli $OUT/box-r2-$IFACE.txt"
echo "  python3 -m reac.diff $OUT/console-r1-$IFACE.txt $OUT/box-r2-$IFACE.txt   # (loss between the two points)"
