#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# reac-hwbridge.sh -- pure-L2 hardware REAC bridge over the lan3 wire, NO re-pacer,
# NO gretap. The mt7531 floods the REAC broadcast in silicon, so the stagebox
# recovers the mixer's real cadence (no software reconstruction -> no ±400 ppm wobble).
#
# REAC A = vid11 (lan1 access), REAC B = vid12 (lan2 access), trunk vid11+12 tagged on lan3.
# Management (vid1 on br-lan.1 over the WiFi phy1) is left UNTOUCHED -> ssh survives.
# Reversible: run reacN-restore.sh to bring back the gretap + re-pacer.

kill $(pgrep -f '[r]eac-repacer') 2>/dev/null; sleep 1
ip link del reactap 2>/dev/null
for v in 11 12 13; do ip link del reactap.$v 2>/dev/null; done
nft delete table bridge reac 2>/dev/null

# lan3 := tagged trunk vid11+12 (was PVID13); lan1/lan2 keep their PVID11/12 access role.
bridge vlan del dev lan3 vid 13 2>/dev/null
bridge vlan del dev lan3 vid 1 2>/dev/null
bridge vlan add dev lan3 vid 11 tagged
bridge vlan add dev lan3 vid 12 tagged

# Assert hardware flood on the three REAC ports -- this is the bit the gretap worked around.
for p in lan1 lan2 lan3; do
	bridge link set dev $p learning on flood on mcast_flood on bcast_flood on
	ip link set dev $p up
done

echo "hwbridge: repacer=$(pgrep -f '[r]eac-repacer' | wc -l) gretap=$(ip -o link show reactap 2>/dev/null | wc -l) lan3vids=$(bridge vlan show dev lan3 | grep -oE '1[12]' | tr '\n' ' ')"
