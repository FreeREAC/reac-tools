#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# reac-untagged-test.sh -- test whether a CLEAN UNTAGGED L2 bridge (no 802.1Q tags,
# NO re-pacer) links the REAC desk. Hypothesis: the VLAN tag on the trunk wire was
# breaking the link handshake, not a missing re-pacer.
#
# Single-stream test: REAC B (lan2) + the lan3 wire on a flat bridge br-reac.
# REAC A (lan1) is parked (one wire can't carry two untagged streams).
# Management bridge (br-lan: WDS + lan4 + br-lan.1/vid1) is left UNTOUCHED.
# Reversible: rc.local + reacN-restore.sh brings back the gretap + re-pacer.

kill $(pgrep -f '[r]eac-repacer') 2>/dev/null; sleep 1
ip link del reactap 2>/dev/null
for v in 11 12 13; do ip link del reactap.$v 2>/dev/null; done
nft delete table bridge reac 2>/dev/null

# pull the REAC ports out of the management bridge
for p in lan1 lan2 lan3; do ip link set $p nomaster 2>/dev/null; done

# flat, untagged, no-STP bridge carrying ONLY REAC B + the wire
ip link del br-reac 2>/dev/null
ip link add name br-reac type bridge
ip link set br-reac type bridge stp_state 0 vlan_filtering 0
for p in lan2 lan3; do
	ip link set $p master br-reac
	bridge link set dev $p flood on bcast_flood on mcast_flood on learning on
	ip link set $p up
done
ip link set br-reac up

echo "br-reac: $(ip -o link show 2>/dev/null | grep -oE 'lan[0-9]+' | while read p; do m=$(ip -o link show $p|grep -oE 'master [a-z0-9-]+'); echo "$p:$m"; done | grep br-reac | tr '\n' ' ') | repacer=$(pgrep -f '[r]eac-repacer'|wc -l) gretap=$(ip -o link show reactap 2>/dev/null|wc -l) tags=NONE"
