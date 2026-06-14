# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Dual-point loss diff: compare a stream captured at two points on the path.

Frames present at the sender (console side) but absent at the receiver
(stagebox side) were lost in transit across the Wi-Fi/gretap link. Frames at
the receiver that the sender never sent are foreign (cross-mix / wrong tap).
"""
import sys
from dataclasses import dataclass, field

from .parser import parse_tcpdump_text


@dataclass
class DiffReport:
    """Dual-point comparison result: frames lost in transit vs. foreign at the receiver."""

    lost_in_transit: list = field(default_factory=list)
    unexpected_at_receiver: list = field(default_factory=list)
    sent: int = 0
    received: int = 0

    @property
    def loss_count(self):
        """Number of frames the sender sent but the receiver never saw."""
        return len(self.lost_in_transit)

    @property
    def loss_rate(self):
        """Fraction of sent frames lost in transit (0.0 if nothing was sent)."""
        return self.loss_count / self.sent if self.sent else 0.0


def diff_streams(sender, receiver):
    """Compare two frame lists of the SAME stream captured at two points."""
    sent_seqs = {f.seq for f in sender}
    recv_seqs = {f.seq for f in receiver}
    return DiffReport(
        lost_in_transit=sorted(sent_seqs - recv_seqs),
        unexpected_at_receiver=sorted(recv_seqs - sent_seqs),
        sent=len(sent_seqs),
        received=len(recv_seqs),
    )


def main(argv=None):
    """CLI: diff two tcpdump-text captures of the same stream; report link loss / foreign frames."""
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 2:
        print("usage: python3 -m reac.diff SENDER.txt RECEIVER.txt", file=sys.stderr)
        return 2
    sender = parse_tcpdump_text(open(argv[0], errors="replace").read())
    receiver = parse_tcpdump_text(open(argv[1], errors="replace").read())
    r = diff_streams(sender, receiver)
    print(f"sent={r.sent}  received={r.received}")
    print(f"lost in transit: {r.loss_count}  ({r.loss_rate*100:.3f}%)")
    if r.lost_in_transit:
        sample = r.lost_in_transit[:20]
        print(f"  lost seqs (first 20): {[hex(s) for s in sample]}")
        print("  -> DATAGRAM LOSS across the link (this causes REAC clicking)")
    if r.unexpected_at_receiver:
        print(f"foreign frames at receiver: {len(r.unexpected_at_receiver)}")
        print("  -> CROSS-MIX or wrong capture point")
    if not r.lost_in_transit and not r.unexpected_at_receiver:
        print("  -> link clean: every sent frame arrived, none foreign")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
