# reac-tools

Analysis tooling for **Roland REAC** (audio-over-Ethernet, EtherType `0x8819`)
traffic: does the network deliver the frames, cleanly and in order? Loss,
reorder, duplication, A/B cross-mix and jitter, from `tcpdump` text or a
`.pcap` capture.

Pure Python **standard library only** — no dependencies, so it runs on a
laptop or directly on an OpenWrt router (busybox Python, or scp'd over).

## This is half the toolkit

reac-tools answers "did the network deliver the frames?". It does not analyse
the audio inside them — pitch and clock-wobble meters, spectrum
classification, per-channel decode health and glitch/PLC detection live in
[`FreeREAC/reac-analysis`](https://github.com/FreeREAC/reac-analysis), which
needs numpy and scipy. Keeping those out is what lets this package be scp'd
onto a busybox router mid-session.

## Install

```sh
git clone https://github.com/FreeREAC/reac-tools
cd reac-tools
```

No build step and no dependencies beyond Python 3's standard library.

## Modules

| Module | Purpose |
|---|---|
| `reac.model` | `Frame` dataclass, 16-bit seq modulus, the rate table (`pps = rate / 12`) |
| `reac.parser` | parse `tcpdump -xx [-e]` text → `Frame` list (full-eth or payload-only) |
| `reac.pcap` | classic libpcap `.pcap` reader/writer (no pcapng), link-type 1 |
| `reac.analyzer` | per-stream loss / reorder / duplicate, cross-mix, jitter, mirror-twin dedup |
| `reac.characterize` | pcap → rate fingerprint, frame-size histogram, seq health, per-channel peak / active-channel count |
| `reac.diff` | dual-point loss diff: sender-side vs receiver-side captures |
| `reac.simulator` | synthetic streams with injectable faults (drives the test suite) |
| `reac.cli` | analyze one capture file (`--rate` / `--fps` set the jitter nominal) |

`reac.cli` and `reac.diff` read tcpdump text; `reac.characterize` reads a
`.pcap` directly. Three modules are runnable as `python3 -m`: `reac.cli`,
`reac.diff`, `reac.characterize`.

There is also a Wireshark dissector for interactive work —
[`wireshark/reac.lua`](wireshark/README.md).

## Run

Two capture scripts, run **on** an OpenWrt router (or any host on the REAC
segment):

- `capture-dualpoint.sh [SECONDS] [IFACE]` — tcpdump *text* at both ends of a
  link at once, for the `reac.diff` loss comparison.
- `capture-campaign.sh <iface> <seconds> <out.pcap> [label]` — full frames to
  a classic `.pcap`, for `reac.characterize`.

```sh
# capture the same stream at both ends of a link simultaneously
./capture-dualpoint.sh 15 lan1        # 15 s on lan1 (REAC A) at both ends

# analyze one capture point (the nominal frame rate is inferred per stream)
python3 -m reac.cli capture-*/console-r1-lan1.txt

# or state the rate explicitly, when the stream is too degraded to infer from
# (exit 3 = at least one stream's rate could not be resolved)
python3 -m reac.cli capture-*/box-r2-lan1.txt --rate 48000

# what got lost crossing a link, between a sender-side and receiver-side capture
python3 -m reac.diff capture-*/console-r1-lan1.txt capture-*/box-r2-lan1.txt

# rate + channel fingerprint of a .pcap (this one takes pcap, not text)
python3 -m reac.characterize /tmp/96k.pcap

# cross-mix check on a box's port (should only carry one VLAN from one console)
python3 -m reac.cli capture-*/box-r2-lan1.txt \
    --expect-vlan 11 --expect-src 00:40:ab:c9:91:9c
```

## REAC facts these tools depend on

- A clean frame is `52 + width × 36` bytes. Playback (console→box) is
  broadcast; return (box→console) is smaller unicast. Two extra bytes after
  the `C2 EA` end marker (1494, 1206, 630, …) are not a REAC field — they are
  the low 16 bits of the frame's own Ethernet FCS, left behind by a capture
  rig mirroring both RX and TX of a port. Such a capture carries every frame
  twice, so half its inter-arrivals read near-zero and a naive median reads a
  rate that was never on the wire; every tool here drops the twin before
  measuring anything (`clean_payload_len`, `dedupe_mirror_twins`).
- The frame rate is the sample rate: a frame carries 12 time-samples per
  channel slot at every rate, so `pps = rate / 12` — 3675 pps at 44.1 kHz,
  4000 at 48 kHz, 8000 at 96 kHz (`reac.model.RATE_PPS` / `pps_for_rate`).
  `rate_from_pps` snaps a measured pps to the nearest of the three and returns
  `None` when none is within 10%. No tool here assumes a rate from the frame
  itself — each reads it off the capture.
- The channel count is 40 slots at every rate. 96 kHz doubles the packet rate
  and keeps all 40 slots; an active-channel count is a count of slots
  carrying signal, not a rate clue.
- The 16-bit sequence counter is the first 2 bytes of the payload,
  little-endian, +1 per frame, wraps at `0xffff`.
- 24-bit PCM payload: digital silence is >90% zero bytes / few distinct
  values; real audio has high byte variance.
- tcpdump on a `vlan_filtering` bridge can show a phantom 802.1Q tag on
  egress (skb metadata before hardware strip) when the wire is actually
  untagged — check raw hex bytes 12–13: `8819` is untagged, `8100…8819` is
  really tagged.
- busybox tcpdump on OpenWrt has no standalone `timeout` — background the
  capture and `kill` it.

## Tests

```sh
make test               # or: python3 -m unittest discover tests -v
```

The suite is round-trip: `reac.simulator` injects a known fault (N losses, a
reorder, a dup, a cross-mix, a jitter burst) and asserts the analyzer reports
exactly it, so the analyzer is trustworthy before it ever sees a real capture.

## API reference

The public API carries docstrings; generate browsable HTML with `make docs`
(needs [pdoc](https://pdoc.dev), output in `site/`). CI publishes it to GitHub
Pages on each `v*` tag.

## Related

- [`FreeREAC/reac-analysis`](https://github.com/FreeREAC/reac-analysis) — the
  numpy/scipy half of this toolkit: pitch and clock-wobble meters, spectrum
  classification, per-channel decode health, glitch and PLC detection.
- [norihiro/obs-h8819-source](https://github.com/norihiro/obs-h8819-source) —
  OBS REAC plugin; reference for 0x8819 framing (`src/source.c`,
  `src/capdev-proc.c`).

### REAC protocol references

- https://github.com/per-gron/reacdriver — the original REAC reverse-engineering
  (macOS driver, master/slave modes). Source of the packet format.
- https://github.com/norihiro/obs-h8819-source — OBS source plugin; framing taken
  from reacdriver. Confirms the 16-bit LE `l2_counter` + per-frame +1 loss check.
- https://github.com/norihiro/reaccapture — Linux REAC pcap→WAV decoder
  (GPL-3.0); has the MASTER_ANNOUNCE/handshake decode and both s24be/s24le
  justifications.

## Acknowledgements

reac-tools is original work, but the REAC wire protocol it analyses was made
intelligible by prior reverse-engineering efforts. The 0x8819 framing, the
16-bit little-endian sequence counter and the frame layout it relies on were
documented by the projects below; reac-tools re-implements those documented
facts in pure Python and copies no upstream code. VLAN handling follows IEEE
802.1Q and the capture reader follows the public libpcap classic savefile
format.

- [per-gron/reacdriver](https://github.com/per-gron/reacdriver) (GPL-3.0) — the
  original REAC reverse-engineering and the source of the wire-framing facts.
- [norihiro/obs-h8819-source](https://github.com/norihiro/obs-h8819-source)
  (GPL-3.0-or-later) — OBS REAC source plugin; confirms the 16-bit
  little-endian sequence counter and per-frame sequencing.
- Standards: IEEE 802.1Q (VLAN tagging) and the libpcap classic savefile
  format.

## Licence

GPL-3.0-or-later. Copyright (C) 2026 Pau Aliagas. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
