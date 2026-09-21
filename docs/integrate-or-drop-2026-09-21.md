# Integrate-or-drop: local `main` onto the clean `origin/main` lineage (2026-09-21)

Operator ruling 2026-09-21: "Go ahead with the branches and do the drop or integrate depending
on its current correctness." Local `main` (root `6b543a0`) and `origin/main` (`FreeREAC/reac-tools`,
root `9a967a9`) share no ancestor; local `main` held a root password and the rig LAN addresses in
its history. This branch (`lane/integrate-scrubbed-line`, off `origin/main`) is the resolution:
every patch below was either integrated (scrubbed, on top of the current tree) or dropped. Local
`main` is left untouched; the unscrubbed bundle
(`/home/pau/Devel/audio/_bundles-2026-09-21/reac-tools.bundle`, local-only) is the recovery surface
for anything dropped here.

Patches were read from a scrubbed clone (password -> `REDACTED`; the working tree at that clone's
`main` tip is independently verified clean of both the password and the rig LAN subnet — see Verification
below) — never from local `main` directly.

## Table

| # | subject | patch-id (scrubbed clone) | verdict | evidence |
|---|---|---|---|---|
| 1 | Add REAC traffic analysis toolkit | `2e8378b...` | SUPERSEDED | `origin/main` root commit `9a967a9` carries the whole package (`reac/*.py`) already, since refined by 8 further PRs. |
| 2 | Add pcap reader/writer + synthetic-from-real test fixture | `4a5f2be...` | SUPERSEDED | `reac/pcap.py` + `tests/fixtures/real_reac_stream.pcap` present in `origin/main` since `9a967a9`. |
| 3 | Commit the pcap fixture (gitignore fix) | `4ae6637...` | SUPERSEDED | fixture is tracked in `origin/main`; no `*.pcap` gitignore gap there. |
| 4 | Add GPL-3.0-or-later license, NOTICE, per-file headers, acknowledgements | `b6a8188...` | SUPERSEDED | `diff LICENSE`/`diff NOTICE` between the scrubbed clone's tip and `origin/main` = empty. |
| 5 | Add docstrings to public API + pdoc reference generation | `cfc22d3...` | SUPERSEDED | `origin/main`'s `Makefile` already carries the `docs: python3 -m pdoc -o site reac` target; modules already carry the same docstrings (folded into `9a967a9`). |
| 6 | docs: genericize obs-h8819 reference to its upstream GitHub URL | `9cd3a88...` | SUPERSEDED | `origin/main` README already links `github.com/norihiro/obs-h8819-source`. |
| 7 | Add on-rig capture + analysis playbooks (capture-campaign.sh + reac.characterize) | `8fbddf2...` | SUPERSEDED | `capture-campaign.sh` + `reac/characterize.py` present in `origin/main`; its 96 kHz comment is *more* current there (settled, not "DECISIVE" pending) — `origin/main` moved past this patch. |
| 8 | docs: reference norihiro/reaccapture in REAC protocol references | `830bf36...` | SUPERSEDED | `origin/main` README already cites `github.com/norihiro/reaccapture`. |
| 9 | Add Wireshark dissector for REAC (0x8819) | `1ae6cd0...` | SUPERSEDED | `origin/main` already carries `wireshark/reac.lua` from `9a967a9` (an earlier, pre-firmware-decode revision — see #31, INTEGRATED as a fix on top). |
| 10 | feat: shared REAC upstream codec + re-pacer transform model, with unit tests | `e25c5ff...` | OUTDATED | `reac_codec.py`/`test_reac_repacer.py`/`test_reac_tools.py` import `numpy`; `origin/main`'s README states audio-domain analysis (needs numpy/scipy) deliberately lives in `FreeREAC/reac-analysis`, not here (keeps the scp-to-a-router, stdlib-only property). `reac_repacer_model.py` claims to mirror `reac_repacer_v3.c`/`emit_ctr`, neither of which was found anywhere under `~/Devel/audio/reac-pw` — the thing it models is gone or renamed. |
| 11 | feat: REAC capture analysis suite (pitch, spectrum, glitch, frame anatomy, output health, I/O diff, defect + clock meters) | `99c8d8a...` | SPLIT | 9 of 11 files (`reac_pitch/spectrum/glitch/out_health/ab_defect/clock_measure/deep.py`, `decode_probe.py`, `measure_b7.py`) import `numpy`/`scipy` — OUTDATED, same reac-analysis-scope reasoning as #10, DROP. `reac_frame_anatomy.py` and `reac_io_diff.py` are stdlib-only and squarely "did the network deliver the frames" — VALUABLE, INTEGRATED as their own commit. |
| 12 | feat: rig measurement harness + L2 bridge / untagged-link test scripts | `c73be34...` | VALUABLE | `reac-hwbridge.sh`, `reac-untagged-test.sh`, `reac-measure.sh` absent from `origin/main`. INTEGRATED — but NOT via literal cherry-pick: this commit's original diff hardcoded the rig's router IP as the default `HOST` argument and embedded the (rotated) root password inline via `sshpass -p`; the scrubbed clone's current tip has the address made overridable via `$REAC_HOST` and the credential moved to `$SSHPASS` (`sshpass -e`), added in a later commit on that line. Took the clone's TIP content, not this commit's diff, to avoid replaying a since-fixed leak through lane history. |
| 13 | docs: re-pacer overnight investigation report; gitignore regenerated measure-log.csv | `99fe8db...` | OUTDATED | `REAC-REPACER-NIGHT.md` is a dated investigation of the same now-absent `reac_repacer_v3.c` (see #10) — historical narrative, not a living doc (CONTRIBUTING: no migration narrative). DROP the doc; the `.gitignore` line (`measure-log.csv`) was salvaged into the rig-harness integration commit instead, since `reac-measure.sh` (#12) writes it. |
| 14 | feat: REAC capture-corpus index builder | `a302975...` | VALUABLE | `tools/build_capture_index.py` absent from `origin/main`, stdlib-only, in-scope (frame-delivery facts, not audio analysis). INTEGRATED. |
| 15 | data: generated REAC capture-corpus index (42 captures) | `a68a892...` | DROP | Not a "big file" (json+md = 84 KB total; the actual 18 GB of pcaps were never in this repo) but a *stored derivation* of a corpus that lives in `reac-captures` — goes stale the moment that corpus changes, and this house's own rule is "derive, never store derivations" / no generated ledger committed. Regenerate with the tool from #14 instead. |
| 16 | docs: document the capture-corpus index in the README | `6a05965...` | PARTIAL | Its prose described the now-dropped committed `data/capture-index.{json,md}` as shipped artifacts. Not cherry-picked verbatim; a trimmed README section (documents the tool, says the index is regenerated on demand, not committed) was written fresh as part of the #14 integration commit. |
| 17 | pcap: read nanosecond-precision captures (0xa1b23c4d) | `5b7ce43...` | VALUABLE | `origin/main`'s `reac/pcap.py` had no `_MAGIC_NANO` handling. INTEGRATED, hand-merged onto the current file (which has diverged: it also carries a `payload=payload` field from `origin/main`'s own `4cc4a87` that this patch's base did not have) rather than a raw cherry-pick; added the round-trip test the original patch lacked. |
| 18 | reac.ctrl: control-plane parser + head-amp table decode | `9852705...` | SUPERSEDED | `diff` against `origin/main`'s `reac/ctrl.py` (landed via today's `caa85f4`, "carried by content copy") = byte-identical. |
| 19 | reac.headamp: head-amp control-block byte-diff analyzer | `14e1abb...` | SUPERSEDED | `diff` against `origin/main`'s `reac/headamp.py` (same `caa85f4`) = byte-identical. |
| 20 | capture-headamp.py: interactive head-amp capture harness | `f015d1b...` | VALUABLE | Companion capture-side script for #18/#19; absent from `origin/main`. INTEGRATED (clone tip content; the introducing commit itself carried no address/credential). |
| 21 | docs: README — head-amp mapping workflow + new modules | `1ee0828...` | SUPERSEDED / folded | `origin/main`'s README already documents `reac.ctrl`/`reac.headamp` (from `caa85f4`); `capture-headamp.py`'s own docstring (#20) covers its usage, so no separate doc commit was needed. |
| 22 | sanitize: a root password and the rig addresses were committed here | `cbb592d...` | DROP | Superseded by this branch's own direct-from-tip integration method (see #12, #17, #20): nothing on this branch ever carries the leak this commit remediated, so there is nothing to re-apply. Verified by scanning this branch's full commit history for the rig subnet and the rotated password token — see Verification below. |
| 23 | codec: a capture longer than 8.2 s was silently truncated and spliced | `ad2aa85...` | OUTDATED | Touches only `reac_clock_measure.py`/`reac_codec.py`/`test_reac_tools.py` — all numpy-scope, same reasoning as #10/#11. DROP. (`origin/main`'s own package solved the analogous counter-wrap problem for `reac/model.py` independently, via `4cc4a87`.) |
| 24 | instruments: read the rate and the width, stop assuming them | `9fa03d8...` | OUTDATED | Touches `reac_codec.py`, `reac_deep.py`, `reac_glitch.py`, `reac_pitch.py`, `reac_spectrum.py` — all numpy-scope, same reasoning as #10/#11. `reac_frame_anatomy.py`/`reac_io_diff.py` (integrated, #11 split) were never in this fix's file list and carry no rate assumption to begin with (`grep -n '96000\|48000\|SR '` = empty). DROP. |
| 25 | verify: one TAG-0500 gate, and an empty scan is no longer a pass | `8482c2c...` | VALUABLE | `verify_tag_0500.py` absent from `origin/main`; stdlib-only; consistent with (not contradicted by) `reac-protocol/spec/protocol-facts.yaml`'s TAG-0500 (DT1 tag 0x0500) documentation — a corpus gate is a distinct capability from a protocol-facts document. INTEGRATED. |
| 26 | reac.cli: measure the frame rate instead of defaulting to 3000 | `5c68208...` | SUPERSEDED | `origin/main`'s `reac/cli.py` already derives the rate from the stream's own cadence and reports `UNRESOLVED` rather than defaulting (landed via `98ea3aa`/`f1d56c2`). |
| 27 | docs: name the two halves, the divergence, and the facts they rest on | `9003448...` | DROP | Documents the disjoint-lineage situation this whole branch exists to end; moot once merged. |
| 28 | verify: untrack the superseded 0500 scanner, one gate stands | `5d3f3cd...` | N/A | Removes a duplicate (`verify_0500_corpus.py`) from local `main`'s own history. Not applicable here: this branch never introduced that duplicate (only `verify_tag_0500.py`, #25, was integrated), so there is nothing to untrack. |
| 29 | docs: this lineage carries a credential in its history and must not be pushed | `b96335e...` | DROP | Warning doc about the tainted local `main` line; moot once this branch replaces it. |
| 30 | readme: name the leak without reproducing it | `059f987...` | DROP | Same as #29 — moot once the lineage split ends. |
| 31 | wireshark: the control header has four fields, not one signature string | `165901a...` | VALUABLE | `origin/main`'s dissector still carries the pre-fix five-byte "signature" table this patch replaced with the firmware-derived class/fragment/rec_len/subtype decode (dated, verified against corpus bytes and the box's own I/O inventory). INTEGRATED on top of `origin/main`'s dissector (identical diffstat, 190+/16-, to the original patch — `origin/main`'s base file matched the pre-fix state exactly). |
| 32 | observe: live multi-VLAN segment observer, rx-only by construction | `f59d64c...` | SUPERSEDED | `diff` against `origin/main`'s `reac/observe.py` (`caa85f4`, "carried by content copy") = byte-identical. |

## Verification

- The rig's LAN subnet and the (rotated) root password, grepped across every commit this branch
  adds on top of `origin/main` (`git log -p origin/main..lane/integrate-scrubbed-line`): **0 hits**
  for both tokens.
- `.github/workflows/sanitize-guard.yml`'s own forbidden-token pattern (site/venue/client names
  plus the rig subnet — see that file for the exact list, not repeated here to avoid this note
  itself tripping the guard) run over the full working tree: **0 matches** (the guard's own grep
  exits 1, meaning nothing matched).
- `python3 -m pytest tests/ -q` on this branch: **113 passed, 2 skipped, 30 subtests passed**
- No file over 5 MB was integrated; the only "generated data" candidate (#15, the 42-capture index
  snapshot) was dropped as a stored derivation, not excluded for size.

## Not carried forward (recovery)

Everything marked DROP or OUTDATED above is fully recoverable from the durable bundle at
`/home/pau/Devel/audio/_bundles-2026-09-21/reac-tools.bundle` (local-only, not referenced by this
branch). Most durable candidate for a *future* home, if wanted: the numpy/scipy audio-analysis
suite (#10, #11 numpy half, #23, #24) belongs in `FreeREAC/reac-analysis`, not here — that repo does
not yet exist locally to receive it.
