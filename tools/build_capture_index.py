# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

"""Build a queryable INDEX of the REAC capture corpus.

Streams every classic pcap in a directory ONCE, record-by-record with bounded
memory (never materialises a whole file), and emits one manifest record per
capture:

  * filename, bytes, mtime (ISO), on-wire duration, frame count;
  * distinct src MACs mapped to Roland desk / stagebox names, with per-endpoint
    frame counts;
  * frame-SIZE histogram (1492 V-Mixer down / 1494 OHRCA down / 628 S-1608 up /
    340 S-0808 up, and the +2 mirror/FCS variants);
  * frame-TYPE split: audio (FILLER, type 0x0000) vs control, plus the control
    sub-type breakdown (master-announce cfea, probe / grant / enroll / chanmap /
    box-heartbeat cdea) that reac-tools can classify;
  * establishment landmarks with offsets from capture start (first master
    announce, first probe, first box frame / cold-connect, first grant, first
    box heartbeat, first audio);
  * an inferred sample rate from the streaming FILLER cadence.

Everything here is DETERMINISTIC — computed from the bytes, never from an LLM.
The one-line human "what this capture demonstrates" summary is added out of band
(see --summaries) so the deterministic fields and the prose stay separable.

Usage:
  python3 tools/build_capture_index.py CAPTURE_DIR \
      [--summaries demonstrates.json] [--json OUT.json] [--md OUT.md] \
      [--max-records N]

`--summaries` is a JSON object {filename: "one-line summary"} merged into each
record's `demonstrates` field. `--max-records` caps the per-file scan (sets
`sampled: true` on any capture that hits the cap — there is never a silent
truncation).

The REAC framing facts (EtherType 0x8819, LE16 counter at payload[0:2], type
word at payload[2:4], cdea/cfea control blocks) match reac/pcap.py and
reac/characterize.py.
"""
import argparse
import glob
import json
import os
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

_GLOBAL_HDR = 24
_REAC = b"\x88\x19"

# --- Roland endpoint map, keyed on the last 3 MAC bytes (OUI is 00:40:ab). ----
# Discovered by streaming the whole corpus; the last-3 suffix identifies the
# unit, the leading 00:40:ab is Roland's OUI.  Consoles (V-Mixer M-series and
# the OHRCA M-5000) act as REAC master; S-series are stageboxes; S-4000M is a
# merge unit; 00:00:01 is the reac-pw software master.
_MAC_MAP = {
    "c9:cc:03": ("M-200", "desk"),        # V-Mixer console (master)
    "c9:d8:5b": ("M-300", "desk"),        # V-Mixer console (master)
    "ca:15:4c": ("M-5000", "desk"),       # OHRCA console (master)
    "ca:15:4d": ("M-5000", "desk"),       # OHRCA console, port B
    "c9:91:9c": ("V-Mixer", "desk"),      # V-Mixer console, June rig (master)
    "c9:91:9d": ("V-Mixer", "desk"),      # V-Mixer console, June rig, port B
    "00:00:01": ("reac-pw", "sw-master"),  # reac-pw software master
    "c4:80:3b": ("S-1608", "box"),        # stagebox
    "c4:80:41": ("S-1608", "box"),        # stagebox, second unit
    "c4:dc:9c": ("S-0808", "box"),        # stagebox
    "c4:06:80": ("S-4000M", "merge"),     # merge unit
    "c4:08:bc": ("S-4000M", "merge"),     # merge unit, second unit
}

# --- frame-size legend ------------------------------------------------------
_SIZE_LABELS = {
    1492: "V-Mixer downstream (audio)",
    1494: "OHRCA/M-5000 downstream (audio, +2)",
    628: "S-1608 upstream (audio)",
    630: "S-1608 upstream mirror (+FCS)",
    340: "S-0808 upstream (audio)",
    342: "S-0808 upstream mirror (+FCS)",
}


def _mac(b):
    return ":".join("%02x" % x for x in b)


def endpoint(mac):
    """Map a full MAC to (name, role); unknown Roland units keep their suffix."""
    suffix = mac[-8:]
    if suffix in _MAC_MAP:
        return _MAC_MAP[suffix]
    if mac.startswith("00:40:ab"):
        return ("Roland?%s" % suffix, "unknown")
    return (mac, "foreign")


def classify(raw):
    """Classify one raw ethernet frame.

    Returns (kind, src_mac, orig_hint) or None for non-REAC frames.
    kind is one of: FILLER (audio, type 0x0000), MASTER_ANNOUNCE (cfea),
    PROBE / GRANT / ENROLL / CHANMAP / BOX_HB / SUB01 / SUB02 /
    UNKNOWN_CDEA_* (cdea control), or UNKNOWN_TYPE_*.
    """
    if len(raw) < 14:
        return None
    if raw[12] == 0x88 and raw[13] == 0x19:
        e = 12
    elif (len(raw) > 17 and raw[12] == 0x81 and raw[13] == 0x00
          and raw[16] == 0x88 and raw[17] == 0x19):
        e = 16
    else:
        return None
    if len(raw) < e + 10:
        return ("SHORT", _mac(raw[6:12]))
    t0, t1 = raw[e + 4], raw[e + 5]
    op0, op1 = raw[e + 6], raw[e + 7]
    op_len = (raw[e + 8] << 8) | raw[e + 9]
    if t0 == 0 and t1 == 0:
        kind = "FILLER"
    elif t0 == 0xcf and t1 == 0xea:
        kind = "MASTER_ANNOUNCE"
    elif t0 == 0xcd and t1 == 0xea:
        if op0 == 0x04 and op1 == 0x03:
            kind = "GRANT"
        elif op0 == 0x01 and op1 == 0x03 and op_len == 0x000d:
            kind = "ENROLL"
        elif op0 == 0x01 and op1 == 0x03 and op_len == 0x0019:
            kind = "CHANMAP"
        elif op0 == 0x01 and op1 == 0x03 and op_len == 0x0001:
            kind = "BOX_HB"
        elif op0 == 0x01 and op1 == 0x00:
            kind = "PROBE"
        elif op0 == 0x01 and op1 == 0x01:
            kind = "SUB01"
        elif op0 == 0x01 and op1 == 0x02:
            kind = "SUB02"
        else:
            kind = "UNKNOWN_CDEA_%02x%02x_len%04x" % (op0, op1, op_len)
    else:
        kind = "UNKNOWN_TYPE_%02x%02x" % (t0, t1)
    return (kind, _mac(raw[6:12]))


_CONTROL_SUBTYPES = ("MASTER_ANNOUNCE", "PROBE", "GRANT", "ENROLL",
                     "CHANMAP", "BOX_HB", "SUB01", "SUB02")
_RATES = {44100: 3675.0, 48000: 4000.0, 96000: 8000.0}  # pps @ 12 samp/pkt


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return None
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def scan(path, max_records=None):
    """Stream one pcap once; return a deterministic manifest record."""
    st = os.stat(path)
    rec = {
        "filename": os.path.basename(path),
        "bytes": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc)
                         .astimezone().isoformat(timespec="seconds"),
        "capture_date": _date_from_name(os.path.basename(path)),
        "sampled": False,
    }
    total = 0
    reac = 0
    first_ts = last_ts = None
    src_counts = Counter()
    size_hist = Counter()
    kind_counts = Counter()
    landmark_ts = {}
    filler_gaps = []          # inter-arrival for rate inference
    filler_last = {}          # per-src last FILLER ts
    audio_frames = 0

    with open(path, "rb", buffering=1 << 20) as f:
        ghdr = f.read(_GLOBAL_HDR)
        if len(ghdr) < _GLOBAL_HDR:
            rec.update(_finalize_empty())
            return rec
        magic = struct.unpack("<I", ghdr[:4])[0]
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        pkt = struct.Struct(endian + "IIII")
        nano = magic in (0xA1B23C4D, 0x4DC3B2A1)
        while True:
            ph = f.read(pkt.size)
            if len(ph) < pkt.size:
                break
            ts_s, ts_u, incl, orig = pkt.unpack(ph)
            raw = f.read(incl)
            if len(raw) < incl:
                break
            total += 1
            if max_records is not None and total > max_records:
                rec["sampled"] = True
                break
            ts = ts_s + (ts_u / 1e9 if nano else ts_u / 1e6)
            c = classify(raw)
            if c is None:
                continue
            kind, src = c
            reac += 1
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            src_counts[src] += 1
            size_hist[orig] += 1
            kind_counts[kind] += 1

            name, role = endpoint(src)
            if kind == "FILLER":
                audio_frames += 1
                prev = filler_last.get(src)
                if prev is not None:
                    g = ts - prev
                    if 0 < g < 0.01 and len(filler_gaps) < 20000:
                        filler_gaps.append(g)
                filler_last[src] = ts
                _mark(landmark_ts, "first_audio", ts)
            elif kind == "MASTER_ANNOUNCE":
                _mark(landmark_ts, "first_master_announce", ts)
            elif kind == "PROBE":
                _mark(landmark_ts, "first_probe", ts)
            elif kind == "GRANT":
                _mark(landmark_ts, "first_grant", ts)
            elif kind == "ENROLL":
                _mark(landmark_ts, "first_enroll", ts)
            elif kind == "BOX_HB":
                _mark(landmark_ts, "first_box_heartbeat", ts)
            if role in ("box", "merge"):
                _mark(landmark_ts, "first_box_frame", ts)

    rec["frame_count"] = total
    rec["reac_frames"] = reac
    rec["duration_s"] = round(last_ts - first_ts, 3) if first_ts is not None else 0.0
    rec["endpoints"] = _endpoints(src_counts, reac)
    rec["size_histogram"] = {str(k): v for k, v in size_hist.most_common()}
    rec["size_labels"] = {str(k): _SIZE_LABELS[k]
                          for k in size_hist if k in _SIZE_LABELS}
    audio = sum(v for k, v in kind_counts.items() if k == "FILLER")
    control = sum(v for k, v in kind_counts.items()
                  if k in _CONTROL_SUBTYPES or k.startswith("UNKNOWN_CDEA"))
    rec["type_counts"] = {
        "audio": audio,
        "control": control,
        "other": reac - audio - control,
    }
    rec["control_subtypes"] = {
        k: kind_counts[k] for k in _CONTROL_SUBTYPES if kind_counts[k]
    }
    unknown = {k: v for k, v in kind_counts.items()
               if k.startswith("UNKNOWN") or k == "SHORT"}
    if unknown:
        rec["control_subtypes"].update(unknown)
    rec["landmarks_s"] = ({} if first_ts is None else
                          {k: round(v - first_ts, 4)
                           for k, v in sorted(landmark_ts.items(),
                                              key=lambda kv: kv[1])})
    rec["inferred_rate_khz"] = _infer_rate(filler_gaps)
    rec["stats_line"] = _stats_line(rec)
    rec["demonstrates"] = None
    return rec


def _mark(d, key, ts):
    if key not in d:
        d[key] = ts


def _date_from_name(name):
    import re
    m = re.search(r"(\d{4}-\d{2}-\d{2})", name)
    return m.group(1) if m else None


def _endpoints(src_counts, reac):
    out = {}
    for mac, n in src_counts.most_common():
        name, role = endpoint(mac)
        out[mac] = {
            "name": name,
            "role": role,
            "frames": n,
            "pct": round(100.0 * n / reac, 1) if reac else 0.0,
        }
    return out


def _infer_rate(gaps):
    med = _median(gaps)
    if not med or med <= 0:
        return None
    pps = 1.0 / med
    rate = min(_RATES, key=lambda r: abs(pps - _RATES[r]))
    # only trust it if within 15% of a known nominal cadence
    if abs(pps - _RATES[rate]) / _RATES[rate] > 0.15:
        return None
    return rate // 1000


def _finalize_empty():
    return {
        "frame_count": 0, "reac_frames": 0, "duration_s": 0.0,
        "endpoints": {}, "size_histogram": {}, "size_labels": {},
        "type_counts": {"audio": 0, "control": 0, "other": 0},
        "control_subtypes": {}, "landmarks_s": {}, "inferred_rate_khz": None,
        "stats_line": "empty / unreadable pcap", "demonstrates": None,
    }


def _stats_line(rec):
    names = "+".join(dict.fromkeys(
        v["name"] for v in rec["endpoints"].values()))
    rate = ("%d kHz" % rec["inferred_rate_khz"]
            if rec["inferred_rate_khz"] else "no-audio")
    tc = rec["type_counts"]
    lm = ",".join("%s@%.1fs" % (k.replace("first_", ""), v)
                  for k, v in rec["landmarks_s"].items())
    return ("%s; %.0fs; %d frames; %s; audio %d / control %d; sizes %s; %s" % (
        names or "?", rec["duration_s"], rec["reac_frames"], rate,
        tc["audio"], tc["control"],
        "/".join(rec["size_histogram"].keys()) or "-",
        ("landmarks " + lm) if lm else "no landmarks"))


# --- markdown rendering -----------------------------------------------------

_MODEL_TOKENS = {
    "m5000": "M-5000", "m200": "M-200", "m300": "M-300",
    "s1608": "S-1608", "s0808": "S-0808", "s4000": "S-4000M",
}


def _name_wire_mismatch(r):
    """True if a desk/box model named in the filename is absent from the wire."""
    fn = r["filename"].lower()
    present = {v["name"] for v in r["endpoints"].values()}
    for tok, model in _MODEL_TOKENS.items():
        if tok in fn and model not in present:
            return True
    return False


_QUESTION_MAP = [
    ("real M-200 establishment (with a real stagebox)",
     lambda r: "M-200" in _names(r) and _has_box(r) and _establishes(r)
     and "reac-pw" not in _names(r)),
    ("real M-300 establishment",
     lambda r: "M-300" in _names(r) and _has_box(r) and _establishes(r)),
    ("M-5000 / OHRCA downstream (1494-byte frames)",
     lambda r: "M-5000" in _names(r) or "1494" in r["size_histogram"]),
    ("96 kHz audio stream (OHRCA double-rate)",
     lambda r: r["inferred_rate_khz"] == 96),
    ("48 kHz audio stream",
     lambda r: r["inferred_rate_khz"] == 48),
    ("S-0808 upstream (340-byte frames)",
     lambda r: any(s in ("340", "342") for s in r["size_histogram"])),
    ("S-1608 upstream (628-byte frames)",
     lambda r: any(s in ("628", "630") for s in r["size_histogram"])),
    ("S-4000M merge unit",
     lambda r: any(v["name"] == "S-4000M" for v in r["endpoints"].values())),
    ("reac-pw software master / slave",
     lambda r: "reac-pw" in _names(r) or "reacpw" in r["filename"]),
    ("cold-boot / cold-connect establishment sequence",
     lambda r: ("coldboot" in r["filename"] or "coldconnect" in r["filename"]
                or "cold" in r["filename"])),
    ("control-plane only (matrix / handshake, no PCM)",
     lambda r: r["type_counts"]["audio"] == 0 and r["type_counts"]["control"] > 0),
    ("full handshake reaches establishment (grant + heartbeat)",
     lambda r: "first_grant" in r["landmarks_s"]
     and "first_box_heartbeat" in r["landmarks_s"]),
    ("pure audio streaming (little/no establishment control)",
     lambda r: r["type_counts"]["audio"] > 0
     and r["type_counts"]["control"] < 50),
    ("mirror / +FCS trailer frames (+2 sizes)",
     lambda r: any(s in ("342", "630") for s in r["size_histogram"])),
    ("filename mislabels the desk/box vs the wire",
     _name_wire_mismatch),
]


def _names(r):
    return {v["name"] for v in r["endpoints"].values()}


def _has_box(r):
    return any(v["role"] in ("box", "merge") for v in r["endpoints"].values())


def _establishes(r):
    return "first_box_heartbeat" in r["landmarks_s"] or "first_grant" in r["landmarks_s"]


def render_md(records):
    recs = sorted(records, key=lambda r: (r["capture_date"] or "", r["filename"]))
    out = []
    out.append("# REAC capture corpus index\n")
    out.append("Auto-generated by `tools/build_capture_index.py` — do not edit "
               "by hand; re-run the builder. Deterministic fields come from "
               "streaming each pcap once; the *demonstrates* column is a "
               "reviewed one-line human summary.\n")
    out.append("Total: **%d captures**, **%s** on disk.\n" % (
        len(recs), _human_bytes(sum(r["bytes"] for r in recs))))

    out.append("\n## Question -> which capture\n")
    for label, pred in _QUESTION_MAP:
        hits = [r["filename"] for r in recs if pred(r)]
        out.append("- **%s** -> %s" % (
            label, ", ".join("`%s`" % h for h in hits) if hits else "_(none)_"))

    out.append("\n## Captures (by date)\n")
    out.append("| date | file | size | dur | frames | endpoints | rate | "
               "audio/ctrl | demonstrates |")
    out.append("|---|---|---:|---:|---:|---|---|---|---|")
    for r in recs:
        eps = ", ".join("%s(%s)" % (v["name"], v["role"][0])
                        for v in r["endpoints"].values())
        rate = ("%dk" % r["inferred_rate_khz"]
                if r["inferred_rate_khz"] else "-")
        tc = r["type_counts"]
        dem = r.get("demonstrates") or r["stats_line"]
        out.append("| %s | `%s`%s | %s | %.0fs | %d | %s | %s | %d/%d | %s |" % (
            r["capture_date"] or "?", r["filename"],
            " ⚠sampled" if r["sampled"] else "",
            _human_bytes(r["bytes"]), r["duration_s"], r["reac_frames"],
            eps, rate, tc["audio"], tc["control"],
            dem.replace("|", "\\|")))

    out.append("\n## Per-capture landmarks\n")
    for r in recs:
        if not r["landmarks_s"]:
            continue
        lm = ", ".join("%s @ %.3fs" % (k.replace("first_", ""), v)
                       for k, v in r["landmarks_s"].items())
        out.append("- `%s`: %s" % (r["filename"], lm))

    out.append("\n## Endpoint MAC legend\n")
    out.append("Roland OUI `00:40:ab`; the last 3 bytes identify the unit.\n")
    out.append("| suffix | unit | role |")
    out.append("|---|---|---|")
    for suf, (name, role) in _MAC_MAP.items():
        out.append("| `%s` | %s | %s |" % (suf, name, role))
    return "\n".join(out) + "\n"


def _names_str(r):
    return "+".join(dict.fromkeys(v["name"] for v in r["endpoints"].values()))


def _human_bytes(n):
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return "%.0f%s" % (n, unit) if unit == "B" else "%.1f%s" % (n, unit)
        n /= 1024.0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("capture_dir")
    ap.add_argument("--summaries", default=None,
                    help="JSON {filename: one-line summary} to merge")
    ap.add_argument("--json", default=None)
    ap.add_argument("--md", default=None)
    ap.add_argument("--max-records", type=int, default=None)
    args = ap.parse_args(argv)

    summaries = {}
    if args.summaries and os.path.exists(args.summaries):
        with open(args.summaries) as f:
            summaries = json.load(f)

    paths = sorted(glob.glob(os.path.join(args.capture_dir, "*.pcap")))
    records = []
    for p in paths:
        r = scan(p, max_records=args.max_records)
        if r["filename"] in summaries:
            r["demonstrates"] = summaries[r["filename"]]
        records.append(r)
        print("scanned %-52s %d frames %.0fs %s" % (
            r["filename"], r["reac_frames"], r["duration_s"],
            "SAMPLED" if r["sampled"] else ""), file=sys.stderr)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(records, f, indent=1)
        print("wrote %s (%d records)" % (args.json, len(records)), file=sys.stderr)
    if args.md:
        with open(args.md, "w") as f:
            f.write(render_md(records))
        print("wrote %s" % args.md, file=sys.stderr)
    if not args.json and not args.md:
        json.dump(records, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
