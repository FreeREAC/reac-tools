#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# REAC capture playbook — run ON an OpenWrt router. busybox tcpdump has no
# `timeout`, so we background + kill. Captures FULL REAC (0x8819) frames to a
# classic pcap for offline analysis with `python3 -m reac.characterize`.
#
# Capture on a WIRED LAN port (not over the WDS link you are measuring), full
# frames (-s 0). Set the console/project sample rate BEFORE each run.
#
# Usage:  capture-campaign.sh <iface> <seconds> <out.pcap> [label]
#
# The session (per the capture campaign):
#   capture-campaign.sh lan1 20 /tmp/48k.pcap  48k    # baseline: expect ~4000 pps
#   capture-campaign.sh lan1 20 /tmp/96k.pcap  96k    # DECISIVE: ~8000 pps => double-rate,
#                                                     #           ~4000 pps + 20 active ch => halving
#   capture-campaign.sh lan1 20 /tmp/44k1.pcap 44k1   # 44.1: frames @ ~3675 pps => our missing mode;
#                                                     #       no frames / box won't lock => mixer clock
# Then pull each .pcap to the analysis host and run:
#   python3 -m reac.characterize /tmp/96k.pcap
set -u
IFACE="${1:?usage: capture-campaign.sh <iface> <seconds> <out.pcap> [label]}"
SECS="${2:?seconds}"
OUT="${3:?out.pcap}"
LABEL="${4:-reac}"

command -v tcpdump >/dev/null 2>&1 || { echo "tcpdump not found (apk add tcpdump-mini)"; exit 1; }

echo "[$LABEL] capturing 0x8819 on $IFACE for ${SECS}s -> $OUT (full frames, -s0)"
tcpdump -i "$IFACE" -s 0 -w "$OUT" 'ether proto 0x8819' >/dev/null 2>&1 &
P=$!
sleep "$SECS"
kill "$P" 2>/dev/null
wait "$P" 2>/dev/null
SZ=$(ls -l "$OUT" 2>/dev/null | awk '{print $5}')
echo "[$LABEL] done: ${SZ:-0} bytes -> $OUT"
echo "[$LABEL] analyse with: python3 -m reac.characterize $OUT"
