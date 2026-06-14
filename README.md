# reac-tools

Analysis tooling for **Roland REAC** (audio-over-Ethernet, EtherType `0x8819`)
traffic, built to diagnose the REAC-over-Wi-Fi rig at the venue — two GL-MT6000
(Flint 2) routers carrying REAC across a 30 m 5 GHz WDS link via OpenWrt 25.12
gretap tunnels.

Pure Python **standard library only** — no dependencies, so it runs on the
laptop *or* directly on an OpenWrt router (busybox Python or scp'd).

## What problem this solves

Symptom: console (M-300) recognises both stageboxes, output is patched, but the
audio is **clicking instead of sound** and both boxes' REAC LEDs burst/solid/burst
(repeated clock-lock loss). Two hypotheses to test from packet captures:

1. **Datagram loss** in transit across the Wi-Fi/gretap link.
2. **A/B cross-mixing** — REAC A and B both broadcast the same EtherType to
   `ff:ff:ff:ff:ff:ff`; only the bridge VLAN tag (11 vs 12) separates them. Any
   isolation leak makes a box decode the other stream → clicking.

The single-point snapshots we had were too small/wrong-shaped to decide. This
toolkit does the proper **dual-point** analysis.

## REAC framing facts (verified on the rig 2026-05-30)

- EtherType `0x8819`. Playback (console→box) is **broadcast**, ~1492–1496 B,
  ~3000 fps; return (box→console) is smaller unicast.
- The **16-bit sequence counter** is the **first 2 bytes of the payload,
  little-endian**, increments +1/frame, wraps at `0xffff`. (`0xfd7e→7f→80→81`.)
- 24-bit PCM payload: digital silence ≈ >90 % zero bytes / few distinct values;
  real audio = high byte variance.
- tcpdump on a `vlan_filtering` bridge shows a **phantom 802.1Q tag** on egress
  (skb metadata before HW strip) — the wire is actually untagged. Check raw hex
  byte 12–13: `8819` = untagged, `8100…8819` = really tagged.
- busybox tcpdump on OpenWrt 25.12 has **no standalone `timeout`** — background
  the capture and `kill` it.

## Modules

| Module | Purpose |
|---|---|
| `reac.model` | `Frame` dataclass + 16-bit seq modulus |
| `reac.parser` | parse `tcpdump -xx [-e]` text → `Frame` list (full-eth or payload-only) |
| `reac.analyzer` | per-stream loss / reorder / duplicate, cross-mix, jitter |
| `reac.diff` | **dual-point** loss diff: sender-side vs receiver-side captures |
| `reac.simulator` | synthetic streams with injectable faults (drives the test suite) |
| `reac.cli` | analyze one capture file |

## Usage

```sh
# On-site: capture the same stream at both ends simultaneously
./capture-dualpoint.sh 15 lan1        # 15s on lan1 (REAC A) at r1 + r2

# Analyze each capture point
python3 -m reac.cli capture-*/console-r1-lan1.txt --fps 3000
python3 -m reac.cli capture-*/box-r2-lan1.txt --fps 3000

# THE decisive test: what got lost crossing the link?
python3 -m reac.diff capture-*/console-r1-lan1.txt capture-*/box-r2-lan1.txt

# Cross-mix check on box1's port (should only carry VLAN 11 from console A)
python3 -m reac.cli capture-*/box-r2-lan1.txt \
    --expect-vlan 11 --expect-src 00:40:ab:c9:91:9c
```

## Dual-point capture plan (next on-site session)

1. Get on the `192.168.10.x` rig LAN (wired into a router LAN4/5 is best for
   high-rate capture; don't capture over the WDS you're testing).
2. `./capture-dualpoint.sh 15 lan1` then again for `lan2` (REAC B).
3. `reac.diff` console-vs-box → exact lost-in-transit seq count + rate.
4. `reac.cli --expect-*` on each box port → cross-mix leak.
5. Jitter ratio in `reac.cli` → bursts that break clock lock.
6. Correlate with the both-boxes-flashing LED.

## Tests

```sh
python3 -m unittest discover tests -v
```

The suite is **round-trip**: `reac.simulator` injects a *known* fault (N losses,
a reorder, a dup, a cross-mix, a jitter burst) and asserts the analyzer reports
exactly it — so the analyzer is trustworthy before it ever sees real captures.

## Related

- [norihiro/obs-h8819-source](https://github.com/norihiro/obs-h8819-source) —
  OBS REAC plugin; reference for 0x8819 framing (`src/source.c`,
  `src/capdev-proc.c`).
- `FreeREAC/reac-docs` — build notes for the REAC-over-Wi-Fi rig.

### REAC protocol references

- https://github.com/per-gron/reacdriver — the original REAC reverse-engineering
  (macOS driver, master/slave modes). Source of the packet format.
- https://github.com/norihiro/obs-h8819-source — OBS source plugin; framing taken
  from reacdriver. Confirms 16-bit LE `l2_counter` + per-frame +1 loss check.
- https://github.com/norihiro/reaccapture — Linux REAC pcap→WAV decoder (GPL-3.0);
  has the MASTER_ANNOUNCE/handshake decode and both s24be/s24le justifications.
- https://obsproject.com/forum/resources/reac-audio-source.1471/ — the OBS plugin
  resource page.

## Acknowledgements

reac-tools is original work, but the REAC wire protocol it analyses was made
intelligible by prior reverse-engineering efforts. The 0x8819 framing,
the 16-bit little-endian sequence counter and the frame layout it relies on
were documented by the projects below; reac-tools re-implements those
documented *facts* in pure Python and copies no upstream code. VLAN handling
follows IEEE 802.1Q and the capture reader follows the public libpcap classic
savefile format.

- [per-gron/reacdriver](https://github.com/per-gron/reacdriver) (GPL-3.0) — the
  original REAC reverse-engineering and the source of the wire-framing facts.
- [norihiro/obs-h8819-source](https://github.com/norihiro/obs-h8819-source)
  (GPL-3.0-or-later) — OBS REAC source plugin; confirms the 16-bit
  little-endian sequence counter and per-frame sequencing.
- Standards: IEEE 802.1Q (VLAN tagging) and the libpcap classic savefile
  format.

## API reference

The public API carries docstrings; generate browsable HTML with `make docs`
(needs [pdoc](https://pdoc.dev), output in `site/`). CI publishes it to GitHub
Pages on each `v*` tag.

## License

GPL-3.0-or-later. Copyright (C) 2026 Pau Aliagas. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
