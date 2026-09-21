#!/usr/bin/env python3
"""Counterexample hunt for the TAG-0500 identity-handshake model.

The model under test, from the M-200 enrol and establish decodes:

  - a master's 0500 record is an RQ1 poll (command 0x11) and its data is one of
    six constants: 000004 060008 100011 101109 110011 111109;
  - a box's 0500 record is a DT1 answer (command 0x12) carrying identity, and is
    consistent per box model;
  - the exchange is a ONE-TIME identity handshake, not a per-input escalation.

This is a gate, not a report: it scans a corpus and exits non-zero on the first
capture holding a counterexample -- an RQ1 poll outside the six, a command that
is neither, or a record whose checksum does not hold. Run it over the corpus
after any change to the model.

Records are found by the Roland SysEx signature (f0 41 0a 00 00), so every op
that can carry one is seen rather than only op 0403; the whole file is scanned,
so a late establishment is not missed; master and box are told apart by Ethernet
source MAC rather than by the command byte alone; and the inner DT1 checksum
(TAG..CKSUM summing to 0x80) must hold, so a byte pattern that merely looks like
a record is rejected. 0500 records are clustered in time so a one-time handshake
is visibly distinguishable from a per-input escalation.

A stagebox channel is silent until a State-4 COMMIT promotes staged head-amp
values into the active table, so the identity exchange this verifies is upstream
of anything audible: conforming here does NOT mean a channel will carry audio.

Usage: verify_tag_0500.py <capture.pcap> [more.pcap ...]
"""
import struct, sys, glob, os, json
from collections import Counter, defaultdict

SIG = b'\xf0\x41\x0a\x00\x00\x12'   # F0 mfr(41) dev(0a) model(00 00 12) — the 6-byte Roland prefix
SIX = {"000004", "060008", "100011", "101109", "110011", "111109"}


def frames(path):
    with open(path, 'rb') as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        e = '<' if gh[:4] == b'\xd4\xc3\xb2\xa1' else '>'
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_s, ts_u, incl, orig = struct.unpack(e + 'IIII', ph)
            data = f.read(incl)
            if len(data) < incl:
                break
            yield ts_s + ts_u / 1e6, data


def sysex_records(fr):
    """Every Roland SysEx record in a frame: (op, cmd, tag_hex, data_hex, ok_cksum)."""
    i = 0
    while True:
        q = fr.find(SIG, i)
        if q < 0:
            break
        i = q + 1
        p = q + 6                    # after the 6-byte SysEx prefix -> the command byte
        if p + 3 > len(fr):
            continue
        cmd = fr[p]
        tag = fr[p + 1:p + 3].hex()
        f7 = fr.find(b'\xf7', p + 3)
        if f7 < 0 or f7 - p > 96:
            continue
        rec = fr[p + 1:f7]           # TAG .. CKSUM
        if len(rec) < 3:
            continue
        ok = (sum(rec) & 0xff) == 0x80
        data = fr[p + 3:f7 - 1].hex()   # between TAG and CKSUM
        # op sits just before the SysEx: cd ea | op | oplen | wrapper(4) | len(1) | f0...
        op = fr[q - 9:q - 7].hex() if q >= 9 and fr[q - 11:q - 9] == b'\xcd\xea' else '??'
        yield op, cmd, tag, data, ok


def ascii_of(hexd):
    b = bytes.fromhex(hexd)
    s = ''.join(chr(c) if 0x20 <= c < 0x7f else '.' for c in b)
    return s if any(ch.isalpha() for ch in s) else ''


def scan(path):
    polls = defaultdict(Counter)     # src -> {data:n}  cmd 0x11 tag 0500
    answers = defaultdict(Counter)   # src -> {data:n}  cmd 0x12 tag 0500
    ops_seen = Counter()             # which op carries the 0500
    ascii_names = set()
    anomalies = []
    times = []                       # (ts, src, cmd)
    n0500 = badck = 0
    for ts, fr in frames(path):
        if SIG not in fr:
            continue
        src = fr[6:12].hex(':')
        for op, cmd, tag, data, ok in sysex_records(fr):
            if tag != '0500':
                continue
            if not ok:
                badck += 1
                continue
            n0500 += 1
            ops_seen[op] += 1
            times.append((ts, src, cmd))
            if cmd == 0x11:
                polls[src][data] += 1
                if data not in SIX:
                    anomalies.append(f"rq1-not-in-six op={op} src={src} data={data}")
            elif cmd == 0x12:
                answers[src][data] += 1
                a = ascii_of(data)
                if a:
                    ascii_names.add(a)
            else:
                anomalies.append(f"unexpected-cmd={cmd:02x} op={op} src={src} data={data}")
    times.sort()
    bursts, last = 0, None
    for ts, _, _ in times:
        if last is None or ts - last > 1.0:
            bursts += 1
        last = ts
    all_polls = set().union(*[set(c) for c in polls.values()]) if polls else set()
    return {
        "capture": os.path.basename(path),
        "size_mb": round(os.path.getsize(path) / 1e6, 1),
        "n_0500": n0500, "bad_cksum": badck,
        "ops_carrying_0500": dict(ops_seen),
        "poll_macs": {m: dict(c) for m, c in polls.items()},
        "answer_macs": {m: dict(c) for m, c in answers.items()},
        "ascii_model_names": sorted(ascii_names),
        "all_polls_in_six": bool(all_polls) and all_polls <= SIX,
        "polls_out_of_six": sorted(all_polls - SIX),
        "bursts_0500": bursts,
        "anomalies": anomalies,
    }


def main():
    # Captures are named on the command line. An absolute default path to one
    # machine's private corpus is a gate that silently scans nothing anywhere
    # else, and reports the empty scan as a pass.
    args = []
    for a in sys.argv[1:]:
        args += sorted(glob.glob(a)) if any(c in a for c in "*?[") else [a]
    if not args:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    missing = [a for a in args if not os.path.isfile(a)]
    if missing:
        print("no such capture: " + ", ".join(missing), file=sys.stderr)
        return 2
    ok = True
    seen_any = False
    for f in sorted(args, key=os.path.getsize):
        r = scan(f)
        if r["anomalies"] or r["bad_cksum"]:
            ok = False
        if r["n_0500"] or r["bad_cksum"]:
            seen_any = True
        print(json.dumps(r))
    if not seen_any:
        # An empty scan is not a pass. A corpus with no 0500 record in it says
        # nothing about the model, and reporting that as conformance is how a
        # broken search reads exactly like a clean one.
        print("NO VERDICT: no TAG-0500 record in any capture scanned "
              "(%d file(s)) -- the model was not exercised" % len(args),
              file=sys.stderr)
        return 2
    print("VERDICT: " + ("no 0500 poll outside the six, no unexpected cmd, no bad checksum"
                         if ok else "ANOMALY/COUNTEREXAMPLE FOUND"), file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
