#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# reac-measure.sh -- regression harness for the REAC recovered-clock wobble.
# Captures the stagebox upstream off the rig, decodes the test sine, prints the
# ±ppm metric, and appends a row to measure-log.csv. Run before AND after every
# rig/config change; compare the ppm column to catch regressions.
#
# Usage: REAC_HOST=<router-address> reac-measure.sh LABEL [HOST] [IFACE]
#   LABEL   free text tag for this run (e.g. baseline, etf-on, wired-hwbridge)
#   HOST    router to capture on            (or $REAC_HOST; e.g. 192.168.10.1)
#   IFACE   interface carrying the upstream (default reactap.12 = gretap REAC B)
#
# Authentication is by ssh key. Where the router only accepts a password, export
# SSHPASS and this uses `sshpass -e`, which keeps the secret out of both the file
# and the local process table:
#
#   read -rs SSHPASS && export SSHPASS
#   REAC_HOST=<router> ./reac-measure.sh baseline
#
# No credential and no rig address lives in this file. The repository publishes.
#
# NOTE: read-only on the rig (tcpdump only). The capture point depends on the
# topology: gretap path -> reactap.12; pure-L2 wired bridge -> the box-side lanN.

set -e
LABEL="${1:-run}"
HOST="${2:-${REAC_HOST:?set REAC_HOST, or pass the router address as argument 2}}"
IFACE="${3:-reactap.12}"
DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="$DIR/measure-log.csv"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=12"
if [ -n "${SSHPASS:-}" ]; then
  SSH="sshpass -e ssh $SSH_OPTS root@$HOST"
else
  SSH="ssh $SSH_OPTS root@$HOST"
fi

[ -f "$LOG" ] || echo "label,frames,f0_hz,purity,ppm_1sigma,wobble_hz,beeps,utc" > "$LOG"

echo "[measure] $LABEL: capturing 28000 upstream frames on $HOST:$IFACE ..."
$SSH "rm -f /tmp/m.pcap; tcpdump -i $IFACE -nn -s 700 'ether proto 0x8819 and less 900' -c 28000 -w /tmp/m.pcap 2>/dev/null; gzip -f /tmp/m.pcap"

# pull via ssh-cat with a size check (scp drops on the flaky WiFi mgmt link)
RSZ="$($SSH 'wc -c </tmp/m.pcap.gz' | tr -d ' ')"
i=1
while [ "$i" -le 6 ]; do
  $SSH 'cat /tmp/m.pcap.gz' > /tmp/m.pcap.gz 2>/dev/null || true
  [ "$(wc -c </tmp/m.pcap.gz | tr -d ' ')" = "$RSZ" ] && [ -n "$RSZ" ] && break
  echo "[measure] pull retry $i"; i=$((i + 1))
done
gunzip -f /tmp/m.pcap.gz

OUT="$(python3 "$DIR/reac_clock_measure.py" /tmp/m.pcap "$LABEL")"
echo "$OUT" | grep -v '^CSV,'
CSV="$(echo "$OUT" | sed -n 's/^CSV,//p')"
echo "$CSV,$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
echo "[measure] logged -> $LOG"
