# REAC Wireshark dissector

`reac.lua` — a Wireshark / tshark dissector for Roland **REAC** (audio-over-
Ethernet, EtherType `0x8819`). Generated from the REAC protocol schema in
[`reac-aes67` `docs/REAC-PROTOCOL.md`](https://github.com/FreeREAC/reac-aes67)
§3.1 (reverse-engineered from reacdriver / obs-h8819 / reaccapture). It decodes
the frame header, the type registry, the `data[32]` control block + checksum, the
MASTER_ANNOUNCE overlay, the audio region, and the end marker.

## Use
```sh
# live (needs CAP_NET_RAW or sudo) or on a saved capture:
wireshark -X lua_script:reac.lua
tshark -X lua_script:reac.lua -r capture.pcap -V        # full dissection
tshark -X lua_script:reac.lua -r capture.pcap -T fields \
       -e frame.number -e reac.type_name -e reac.counter -e reac.checksum_ok
```

## Fields
- `reac.counter` — 16-bit LE sequence (per-frame +1).
- `reac.type` / `reac.type_name` — `FILLER 0x0000` · `CONTROL 0xCDEA` ·
  `MASTER_ANNOUNCE 0xCFEA` · `SPLIT_ANNOUNCE 0xCEEA`.
- `reac.control.subtype` — for CONTROL frames, the `data[0..4]` sub-type signature.
- `reac.checksum` / `reac.checksum_ok` — `sum(data[0..31]) & 0xff == 0` (FILLER
  frames are exempt; flagged via expert info when a non-FILLER frame fails).
- `reac.master.{disc,mac,in_channels,out_channels}` — MASTER_ANNOUNCE overlay
  (`data[6]`=0x0d primary, MAC `data[9..14]`, in `data[15]`, out `data[16]`).
- `reac.audio` — the 1440 B audio region (40 ch × 12 samp × 3 B).
- `reac.end` — the `0xC2EA` end marker (expert warning if absent).

Works on untagged and 802.1Q-tagged frames (Wireshark strips the tag before the
`0x8819` ethertype dispatch).

## Verification
Field offsets validated against the project's real capture fixture
(`tests/fixtures/real_reac_stream.pcap`): counters `0xfd7e..0xfd81`, type
`0x0000`, end `0xC2EA`, 1478-byte payload. (No tshark on the build host — offsets
were checked in Python with identical field math; run the `tshark` lines above to
confirm rendering.)

Complements `python3 -m reac.characterize <pcap>` (pps→rate, per-channel levels,
loss): the dissector is for **per-frame** inspection; `characterize` is for
**whole-capture** statistics.
