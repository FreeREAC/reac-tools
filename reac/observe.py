# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Live multi-segment REAC observer: who is on each wire, saying what, how fast.

Usage (root, CAP_NET_RAW):
    python3 -m reac.observe IFACE [IFACE ...] [--seconds N] [--interval S]
                                              [--no-promisc]

Opens receive-only AF_PACKET sockets on each interface and aggregates every
EtherType 0x8819 frame into per-(iface, vlan, source-MAC) streams, printing a
table per interval: the role the source is playing (master / box), the sample
rate measured from its own cadence, its channel width, and the control kinds
it is emitting. Nothing is ever transmitted — the tool cannot join, grant or
disturb a segment, only watch it.

Where it is meant to sit: a switch port carrying several REAC VLANs at once —
a mirror of the trunk between the console and the boxes, or a tagged member
port. Two sockets per interface cover both ways a kernel hands over a tagged
frame: bound to 0x8819 for untagged frames and for frames whose NIC stripped
the 802.1Q tag on receive (the tag is recovered from PACKET_AUXDATA), and
bound to 0x8100 for frames delivered with the tag still inline. VLAN
sub-interfaces are therefore NOT needed — point the tool at the trunk parent.

One visibility rule to hold while reading the table: a socket bound to an
EtherType receives only frames the HOST receives, never the host's own
transmissions. On a mirror port that is everything (every frame there is a
copy delivered to us); on a host that is itself a REAC master, the table
shows the boxes answering and not the master's own flood — absence of the
master row on such a host is this rule, not a fault.

Reading the exit status is part of using the tool. A live REAC segment never
idles: an established master floods FILLER at the audio frame rate and a probing
master cycles cdea 01 0x at ~250/s, so a capture point that yields ZERO frames
is a broken tap (wrong mirror source, wrong port, missing promiscuous mode),
not a quiet wire. Exit 0 means REAC was seen; exit 1 means the tap needs fixing.
"""
import argparse
import collections
import selectors
import socket
import struct
import sys
import time

from .model import rate_from_pps
from . import ctrl

REAC_ETHERTYPE = 0x8819
DOT1Q_ETHERTYPE = 0x8100

# AF_PACKET ancillary plumbing (linux/if_packet.h). PACKET_AUXDATA delivers a
# tpacket_auxdata per frame; when the NIC stripped the VLAN tag on receive the
# tag survives only here, so without it a trunk capture collapses every VLAN
# into one indistinguishable stream.
SOL_PACKET = 263
PACKET_AUXDATA = 8
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
_AUXDATA_FMT = "=IIIHHHH"  # tp_status tp_len tp_snaplen tp_mac tp_net tp_vlan_tci tp_vlan_tpid
_AUXDATA_LEN = struct.calcsize(_AUXDATA_FMT)
TP_STATUS_VLAN_VALID = 1 << 4

BROADCAST = b"\xff\xff\xff\xff\xff\xff"

# Frame length -> channel width. The whole REAC family is one formula,
# 14 (ethernet) + 38 (REAC header/trailer) + nch*36 audio bytes; the 40-ch
# solution (1492 B) is the downstream program broadcast and everything even
# below it is a box return. An OHRCA console's +2 FCS residue is tolerated the
# same way libreac tolerates it: by trying the length with and without it.
_AUDIO_BASE = 52


def audio_width(eth_len):
    """Channel width carried by a frame of `eth_len` untagged-equivalent bytes,
    or None if the length is not an audio-frame solution."""
    for residue in (0, 2):
        body = eth_len - _AUDIO_BASE - residue
        if body >= 0 and body % 36 == 0:
            nch = body // 36
            if 2 <= nch <= 40 and nch % 2 == 0:
                return nch
    return None


class Sight:
    """One received REAC frame, already stripped to what aggregation needs."""

    __slots__ = ("vlan", "src", "dst", "bcast", "width", "kind")

    def __init__(self, vlan, src, dst, bcast, width, kind):
        self.vlan = vlan
        self.src = src
        self.dst = dst
        self.bcast = bcast
        self.width = width
        self.kind = kind


def _mac(b):
    return ":".join("%02x" % x for x in b)


def sight(data, aux_vlan=None):
    """Classify one raw ethernet frame; return a Sight or None if not REAC.

    `aux_vlan` is the VLAN id recovered from PACKET_AUXDATA when the NIC
    stripped the tag; an inline 802.1Q tag in `data` is parsed here and wins
    over aux (a frame carries at most one of the two forms).
    """
    if len(data) < 18:
        return None
    ethertype = (data[12] << 8) | data[13]
    vlan = aux_vlan
    off = 12
    if ethertype == DOT1Q_ETHERTYPE:
        vlan = ((data[14] << 8) | data[15]) & 0x0FFF
        ethertype = (data[16] << 8) | data[17]
        off = 16
    if ethertype != REAC_ETHERTYPE:
        return None
    payload = data[off + 2:]
    # Untagged-equivalent length: the width formula is stated over the frame
    # as a REAC device sends it, which never carries a tag.
    eth_len = 14 + len(payload)
    parsed = ctrl.parse(payload)
    return Sight(
        vlan=vlan,
        src=_mac(data[6:12]),
        dst=_mac(data[0:6]),
        bcast=data[0:6] == BROADCAST,
        width=audio_width(eth_len),
        kind=parsed.kind,
    )


class Stream:
    """Everything observed from one (iface, vlan, src) so far."""

    def __init__(self):
        self.frames = 0
        self.frames_at_mark = 0
        self.mark_ts = None
        self.first_ts = None
        self.pps = 0.0
        self.kinds = collections.Counter()
        self.widths = set()
        self.dsts = set()
        self.master_score = 0
        self.box_score = 0

    def feed(self, s, ts=None):
        if self.first_ts is None:
            self.first_ts = time.monotonic() if ts is None else ts
        self.frames += 1
        self.kinds[s.kind] += 1
        if s.width is not None:
            self.widths.add(s.width)
        self.dsts.add("bcast" if s.bcast else s.dst)
        # Role evidence. A master is the one broadcasting: the program (40 ch),
        # the presence-flood FILLER, cfea announces, cdea probes and the 25-byte
        # heartbeat. A box returns unicast: its audio width, unicast FILLER and
        # the 1-byte heartbeat. GRANT deliberately scores nothing — the master's
        # grant echo and the box's cold-connect share the cdea 04 03 layout, so
        # it identifies the exchange, not the speaker.
        if s.bcast or s.kind in (ctrl.MASTER_ANNOUNCE, ctrl.PROBE, ctrl.MASTER_HB):
            self.master_score += 1
        elif s.kind == ctrl.BOX_HB or (s.width is not None and s.width < 40):
            self.box_score += 1
        elif s.kind == ctrl.FILLER:
            self.box_score += 1  # unicast filler: a linked box holding cadence

    def role(self):
        if self.master_score > self.box_score:
            return "master"
        if self.box_score > self.master_score:
            return "box"
        return "?"

    def tick(self, now):
        """Refresh the windowed packets/s figure.

        The first tick a stream ever gets measures from its first frame, so a
        run whose only table is the final one (--seconds shorter than
        --interval) still reports the cadence instead of a dash.
        """
        since = self.mark_ts if self.mark_ts is not None else self.first_ts
        if since is not None and now > since:
            self.pps = (self.frames - self.frames_at_mark) / (now - since)
        self.frames_at_mark = self.frames
        self.mark_ts = now


class Segments:
    """The aggregation: streams keyed by (iface, vlan, src)."""

    def __init__(self):
        self.streams = {}
        self.total = 0

    def feed(self, iface, s, ts=None):
        self.total += 1
        key = (iface, s.vlan, s.src)
        stream = self.streams.get(key)
        if stream is None:
            stream = self.streams[key] = Stream()
        stream.feed(s, ts)

    def table(self, now):
        """Render the current picture, one line per stream, masters first."""
        lines = ["%-14s %-5s %-17s %-6s %-5s %8s %-6s %-28s %s" % (
            "iface", "vlan", "src", "role", "rate", "pps", "width", "kinds", "dst")]
        def order(item):
            (iface, vlan, src), st = item
            return (iface, vlan if vlan is not None else -1, st.role() != "master", src)
        for (iface, vlan, src), st in sorted(self.streams.items(), key=order):
            st.tick(now)
            rate = rate_from_pps(st.pps)
            kinds = " ".join("%s:%d" % (k, n) for k, n in st.kinds.most_common(3))
            lines.append("%-14s %-5s %-17s %-6s %-5s %8.0f %-6s %-28s %s" % (
                iface,
                "-" if vlan is None else vlan,
                src,
                st.role(),
                "%dk" % (rate // 1000) if rate else "?",
                st.pps,
                "/".join(str(w) for w in sorted(st.widths)) or "-",
                kinds,
                ",".join(sorted(st.dsts))))
        return "\n".join(lines)


def open_sockets(iface, promisc):
    """Two receive-only sockets for one interface, 0x8819 + 0x8100 bound.

    Promiscuity is joined per-socket via PACKET_ADD_MEMBERSHIP so it dies with
    the socket — the interface's own flag is never touched, which matters when
    the interface also carries a live REAC daemon.
    """
    socks = []
    for proto in (REAC_ETHERTYPE, DOT1Q_ETHERTYPE):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
        s.bind((iface, 0))
        s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        if promisc:
            mreq = struct.pack("iHH8s", socket.if_nametoindex(iface),
                               PACKET_MR_PROMISC, 0, b"")
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        s.setblocking(False)
        socks.append(s)
    return socks


def recv_sight(sock):
    """One frame off a socket -> Sight or None (not REAC / would block)."""
    try:
        data, ancdata, _flags, _addr = sock.recvmsg(
            2048, socket.CMSG_SPACE(_AUXDATA_LEN))
    except BlockingIOError:
        return None
    vlan = None
    for level, ctype, cdata in ancdata:
        if level == SOL_PACKET and ctype == PACKET_AUXDATA and len(cdata) >= _AUXDATA_LEN:
            status, _l, _sl, _m, _n, tci, _tpid = struct.unpack_from(_AUXDATA_FMT, cdata)
            if status & TP_STATUS_VLAN_VALID:
                vlan = tci & 0x0FFF
    return sight(data, aux_vlan=vlan)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Observe REAC segments live on one or more interfaces")
    ap.add_argument("ifaces", nargs="+", metavar="IFACE",
                    help="interface(s) to watch — a trunk parent is fine, "
                         "VLAN sub-interfaces are not required")
    ap.add_argument("--seconds", type=float, default=None,
                    help="observe this long, print the final table, exit")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="seconds between table refreshes (default 2)")
    ap.add_argument("--no-promisc", action="store_true",
                    help="skip promiscuous membership — enough on a host that "
                         "is itself a REAC endpoint, never on a mirror port")
    args = ap.parse_args(argv)

    seg = Segments()
    sel = selectors.DefaultSelector()
    try:
        for iface in args.ifaces:
            for s in open_sockets(iface, promisc=not args.no_promisc):
                sel.register(s, selectors.EVENT_READ, iface)
    except PermissionError:
        print("raw sockets need CAP_NET_RAW — run as root", file=sys.stderr)
        return 2
    except OSError as e:
        print("cannot open capture: %s" % e, file=sys.stderr)
        return 2

    start = time.monotonic()
    next_print = start + args.interval
    deadline = None if args.seconds is None else start + args.seconds
    try:
        while True:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                break
            timeout = next_print - now
            if deadline is not None:
                timeout = min(timeout, deadline - now)
            for key, _ev in sel.select(max(timeout, 0)):
                while True:
                    got = recv_sight(key.fileobj)
                    if got is None:
                        break
                    seg.feed(key.data, got, time.monotonic())
            now = time.monotonic()
            if now >= next_print:
                if deadline is None or now < deadline:
                    print("\n%s" % seg.table(now))
                next_print = now + args.interval
    except KeyboardInterrupt:
        pass
    finally:
        for key in list(sel.get_map().values()):
            sel.unregister(key.fileobj)
            key.fileobj.close()
        sel.close()

    print("\n%s" % seg.table(time.monotonic()))
    if seg.total == 0:
        print("\nzero REAC frames: a live segment never idles (FILLER floods "
              "continuously), so this is a broken tap — wrong mirror source, "
              "wrong port or missing promiscuous mode — not a quiet wire.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
