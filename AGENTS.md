# AGENTS.md

## Policy: decoder changes must be validated against sample data

Every change to `pd.py` must be followed by running the decoder against
the example traces and comparing the output against the ground-truth
reader logs.

### Complete auto-test trace list

| Trace | Channels | CLK | DATA | RST | VCC | Mode |
|-------|----------|-----|------|-----|-----|------|
| `test_8_raw16.sr` | 8ch | D1 | D6 | D0 | D4 | ATR + mid-session |
| `test_7_raw16.sr` | 8ch | D1 | D6 | D0 | D4 | ATR |
| `phone_reference_live_16M.sr` | 8ch | D1 | D6 | D0 | D4 | mid-session, gated CLK |
| `samsung_phone_sample.sr` | 8ch | D1 | D6 | D0 | D4 | mid-session, gated CLK, F=512/D=32 |
| `samsung_phone2_sample.sr` | 8ch | D1 | D6 | D0 | D4 | mid-session, gated CLK |
| `sunrise_phone_sample.sr` | **2ch** | **D0** | **D1** | — | — | mid-session, gated CLK |
| `sim_turnon_2_clicking_around_ds.sr` | **6ch** | **1** | **0** | — | — | SIM power-on, gated CLK |

**Note:** `sunrise_phone_sample.sr` only has 2 channels recorded (D0=CLK,
D1=DATA). `sim_turnon_2_clicking_around_ds.sr` has 6 channels (1=CLK,
0=DATA). All other traces use 8 channels (D1=CLK, D6=DATA).

```bash
# --- test_8 (ATR-included, starts_with_atr=true) ---
sigrok-cli -i examples/test_8_raw16.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_8_reader.log /tmp/out.pcap

# --- test_8 (mid-session, starts_with_atr=false) ---
sigrok-cli -i examples/test_8_raw16.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_8_reader.log /tmp/out.pcap

# --- test_7 (ATR-included) ---
sigrok-cli -i examples/test_7_raw16.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_7_reader.log /tmp/out.pcap

# --- test_7 (mid-session) ---
sigrok-cli -i examples/test_7_raw16.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_7_reader.log /tmp/out.pcap

# --- phone reference (ATR-included, gated CLK) ---
sigrok-cli -i examples/phone_reference_live_16M.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- phone reference (mid-session, gated CLK) ---
sigrok-cli -i examples/phone_reference_live_16M.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- samsung phone 1 (ATR-included, gated CLK, non-default F/D) ---
sigrok-cli -i examples/samsung_phone_sample.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- samsung phone 1 (mid-session, gated CLK, non-default F/D) ---
sigrok-cli -i examples/samsung_phone_sample.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- samsung phone 2 (ATR-included, gated CLK, non-default F/D) ---
sigrok-cli -i examples/samsung_phone2_sample.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- samsung phone 2 (mid-session, gated CLK, non-default F/D) ---
sigrok-cli -i examples/samsung_phone2_sample.sr \
  -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- sunrise phone (ATR-included, gated CLK, 2-channel capture) ---
sigrok-cli -i examples/sunrise_phone_sample.sr \
  -P iso7816:clk=D0:data=D1:clock_option=native:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- sunrise phone (mid-session, gated CLK, 2-channel capture) ---
sigrok-cli -i examples/sunrise_phone_sample.sr \
  -P iso7816:clk=D0:data=D1:clock_option=native:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- sim power-on (ATR-included, gated CLK, 6-channel capture) ---
sigrok-cli -i examples/sim_turnon_2_clicking_around_ds.sr \
  -P iso7816:clk=1:data=0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- sim power-on (mid-session, gated CLK, 6-channel capture) ---
sigrok-cli -i examples/sim_turnon_2_clicking_around_ds.sr \
  -P iso7816:clk=1:data=0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- unit tests ---
python3 tests/test_gsmtap.py -v
```

**Always clear the Python bytecode cache before testing** — stale `.pyc`
files can cause the decoder to use old code, producing false results:
```bash
find . -name "__pycache__" -type d -exec rm -rf {} +
```

The acceptance criterion is **0 garbage** (`GARBAGE (mis-framed/desync): 0`,
`RESULT: OK`) for `test_8` in both modes. `test_7` may have some garbage
from the synthetic-ATR fallback (expected when no real ATR is found in the
trace). All traces must be tested in **both modes** (ATR-included and
mid-session) to verify the decoder works correctly regardless of user
setting. Phone/samsung/sunrise/sim_turnon traces are smoke tests (no
ground-truth reader log).

### Versioning

The decoder version is defined in `pd.py` as `VERSION = '1.0.0'`.
The version is printed to the log on decoder startup.

### Testing after decoder changes

After any change to `pd.py`:

1. Clear bytecode cache:
   ```bash
   find . -name "__pycache__" -type d -exec rm -rf {} +
   ```

2. Run all tests against all traces:
   ```bash
   ./tools/capture_baseline.sh > tests/baseline.txt
   ```

3. Compare against saved baseline:
   ```bash
   ./tools/compare_baseline.sh
   ```

4. If differences found, review:
   - GARBAGE count must stay 0 for test_8 (both modes)
   - RESULT must stay OK for test_8 (both modes)
   - ETU values must match for mid-session traces
   - No new INVALID Procedure Byte errors

5. Run unit tests:
   ```bash
   python3 tests/test_gsmtap.py -v
   ```

6. Update `tests/baseline.txt` with new baseline if changes are intentional.

## What happened: the decoder rewrite attempt

We attempted a major rewrite of the ISO 7816 decoder (`pd.py`) with these
features:

1. **Edge-counting always** — removed the `native_fast` sample-skip bit
   reader, making all bit reads count CLK edges per bit instead of skipping
   `clock_skip * samples_per_edge` samples.  The idea was drift-immunity.

2. **Signal degradation recovery** — a `degraded` flag tracking rolling
   parity errors; when ≥ 8 of 64 frames fail parity, the decoder re-arms
   the ATR hunt and flags APDUs with `GSMTAP_FLAG_BAD_FCS`.

3. **Clock-drift monitor** — every 128 bytes the decoder re-measures the
   CLK period and re-anchors `samples_per_edge` if the median drifts > 2%.

4. **Fatal TCK check** — the ATR's TCK checksum mismatch was made fatal
   (reject the ATR) instead of being logged as a warning.

5. **Synthetic ATR fallback** — after 8 failed ATR hunts, commit a
   minimal T=0 ATR `[0x3B, 0x00]` and begin decoding, for mid-session
   captures.

## Outcome

The rewrite introduced a regression: **35 garbage APDUs** on `test_8`
where the baseline had **0 garbage**.  The root causes:

1. **Fatal TCK check** — the ATR in the example traces has a wrong TCK
   (`got=f7 expected=80`) due to a bit error in the capture.  The fatal
   check rejected this real ATR, preventing the decoder from ever
   reaching the DATA state.

2. **Signal degradation ATR re-arm** — the `degraded` flag triggered on
   the capture's natural bit errors, re-arming the ATR hunt mid-session
   and fragmenting the APDU stream.

3. **Stale `.pyc` cache** — the Python bytecode cache was not
   regenerated after code changes, causing the running decoder to use
   old code.  This masked the real regression for several test runs.

The edge-counting change itself may also have contributed subtle
bit-sampling differences, but the TCK check and signal degradation were
the primary causes.

## Resolution

We reverted to the known-good baseline (`2055d1c`, the VCC/RST hysteresis
commit) and applied only three essential, minimal fixes on top:

1. **`hasT0`/`hasT1` init in `start()`** — initialize both to `False` for
   `protocol=auto`, preventing `AttributeError` when `starts_with_atr=false`
   enters DATA state without an ATR.

2. **`hasT0=False` guard in `decode_step` DATA state** — when no protocol
   is known, skip byte reading and wait for a warm reset to trigger the
   ATR hunt.

3. **Synthetic T=0 ATR fallback** — after 8 failed ATR hunts, commit
   `[0x3B, 0x00]` and set `hasT0=True` so the decoder can begin
   processing APDUs in mid-session captures.

The `native_fast` sample-skip, signal degradation, clock monitor, and
fatal TCK check were all discarded.  The decoder is now the original
`2055d1c` code plus 24 lines of mid-session support.

## Current architecture (v1.0.0, CLK-synchronous refactor)

The decoder uses a **CLK-synchronous bit reader** for native-CLK captures and
an edge-list DATA reader for the non-native clock modes.  Bit timing comes
from **counting real CLK edges**, not from a sample-count estimate.

### Two bit readers (selected per burst)

| Reader | Timing source | Used when |
|--------|---------------|-----------|
| `_read_byte_clk()` | count `clock_skip` CLK rising edges per ETU, sample DATA at bit centres | native clock mode **and** `clock_skip` known (`_clock_skip_confident`) |
| `_read_byte_edges()` | DATA-edge reconstruction from `bit_samples` | `sample_as_clock`/`detect`, or mid-session before `clock_skip` is recovered |

### Key changes

1. **CLK-synchronous reader.** `_read_byte_clk()` counts `clock_skip` CLK
   rising edges per ETU and samples DATA at the bit centres (1.5 … 9.5 ETU).
   Exact for `0x00`/`0xff` (too few DATA transitions for the edge reader) and
   deterministic, because `clock_skip` is protocol-defined (372 for the ATR,
   FI/DI after PPS).  Safe across Clock Stop: CLK never stops mid-character
   and resumes before the next start bit.  `_wait_clk_rising()` skips most of
   each bit by samples then lands on the exact edge, so it is fast.

2. **No synthetic ATR.** The old `[3B, 00]` fallback fabricated a 2-byte ATR
   from a stray `0x3B`/`0x3F` byte in command traffic (e.g. the FID `3F00` of
   a SELECT) and destroyed the command.  The hunt is bounded and never emits
   a fake ATR.

3. **Command detection during ATR hunt.** A plausible CLA + valid INS is
   replayed to the DATA state and decoded as a command instead of skipped as
   "invalid TS" — this recovers a SELECT when the preceding ATR was missed.

4. **RST resets `clock_skip` to 372** on RST assert (a reset makes the card
   send ATR at the default rate).

5. **PPS on the native path** just updates `clock_skip` from FI/DI (CLK
   period is unchanged, so the new ETU is exact).  No DATA re-measurement
   burst is consumed — previously that silently dropped the first post-PPS
   command.

6. **Mid-session `clock_skip` recovery.** `_measure_etu()` recovers
   `bit_samples`; `_measure_clock_period()` recovers `_samples_per_clock`;
   `_derive_clock_skip_from_etu()` sets `clock_skip = bit_samples /
   _samples_per_clock` and marks it confident.  If the CLK period cannot be
   measured (fully gated CLK), the edge-list reader is used instead.

7. **Data handling.** Valid APDUs are emitted clean; ambiguous frames are
   emitted flagged `GSMTAP_FLAG_BAD_FCS` (never silently dropped); genuine
   idle-low all-zero noise remains suppressed.

### Testing

- `test_8` / `test_7`: 0 garbage in both ATR-included and mid-session modes.
- All other traces: no regressions (smoke test).
- Unit tests: 12/12 pass.

## Mid-session phone decode (legacy note, still applies)

For a live mid-session phone capture (`starts_with_atr=false`,
`protocol=T=0`), the decoder now:

- Recovers the ETU from the live DATA line via `_measure_etu()` (edge-list,
  locked once) so a gated/stopped CLK at a fast ETU (e.g. ~53 samples) is
  decoded instead of mis-read at the 372-clock default.
- Decodes bytes with the edge-list reader `_read_byte_edges` (the only
  reader now), which is drift-immune.
- Runs the normal T=0 framing so each command+response exchange is emitted as
  one APDU.

Validation: `test_8`/`test_7` 0 garbage in both modes; 12 unit tests pass;
phone 16M/24M decode to coherent APDUs with the STK text fully readable and
no `0xff`/`0xfc` garbage.

### T=0 case 3/4 command-data (RESOLVED)

Commands that carry command-data (e.g. `80 12 … d0`, P3=208) send those
P3 bytes on the wire **before** the card's first procedure byte.  The
framing now distinguishes the cases by the card's first procedure byte:

- If the first post-header byte **is the ACK (== INS)** → case 2/4: the
  terminal sent no command data; read `P3` response bytes (+SW), or, for
  `Le == 0` (GET RESPONSE), read the response until the status word.
- Otherwise the byte is terminal command data → case 3/4: read `P3`
  command-data bytes, then the card's procedure byte (ACK/SW/`9E`/`9F`).
  On ACK (case 4) the response is read until the status word.

This consolidates case-3/4 exchanges (e.g. the `80 12`/`80 14` STK envelope
commands) into one C-APDU = header + command data, R-APDU = response + SW
APDU, instead of fragmenting them across frames.  It is gated to
`_edge_read` (mid-session / gated-CLK captures) so ATR-based captures
(`test_8` / `test_7`) keep the original framing unchanged and stay at
0 garbage.

Known residual limitation: case-4 responses read "until SW" terminate on the
first `6x`/`9x` byte, so a response payload that legitimately contains such
a byte (e.g. an FCP `6F` tag) may be truncated.  This affects only case-4
  commands that return data containing `0x6x`/`0x9x`; in practice, the
  phone's main case-4-with-data path is GET RESPONSE with explicit
  `Le > 0` (bounded by `P3`), which is unaffected.  Used P3=0 (Le == 0)
    GET RESPONSE is extremely rare — our test fixtures and phone references
  show only READ RECORD (INS=0x79) using P3=0 (read entire record).

## Decoder methods tried — reliability registry

A running log of decoder approaches, so future work does not re-litigate
discarded ideas.  "Proven" = kept in `pd.py`; "Rejected" = do not re-add.

### Proven reliable (kept)

- **Sample-skip bit reader (`native_fast`).** Original reader; advances bit
  timing with single sample-skip waits.  Reliable for ATR-based captures
  (`test_8`/`test_7`, 0 garbage).  Keep for those.
- **ATR TS validation + resync.** Validate TS (`0x3B`/`0x3F`); resync on the
  next fall if bogus.  Reliable; stops a phantom start bit shifting the ATR
  off-by-one.
- **Warm-reset re-arm.** RST deassert → state `FIND START`, `clock_skip` back
  to 372, hunt cleared.  Reliable; re-ATRs parse at the default rate.
- **1.5-ETU start-bit guard.** Rejects the phantom `0x00` an idle glitch
  inserts before an ATR.  Reliable.
- **VCC/RST 10 ms level-stability hysteresis.** Reports a level only after
  ≥10 ms stable.  Reliable; symmetric power-up/down, kills spurious events
  from a ringing/floating sense line.
- **PPS speed-switch follow (`clock_skip = F/D`).** After an accepted PPS the
  native skip becomes F/D CLK cycles/bit.  Reliable (verified live).
- **T=1 block-chain follow-up bound.** Caps chained I-blocks so garbage
  cannot loop forever.  Reliable.
- **Synthetic T=0 ATR fallback `[0x3B, 0x00]`.** After 8 failed ATR hunts,
  commit a minimal ATR and set `hasT0=True`.  Reliable for mid-session starts
  (no ATR in the trace).
- **ETU auto-detect from DATA via edge counting (`_measure_etu`).** Edge-waits
  to the first DATA start-bit fall, measures ETU from DATA-edge spacing, locks
  it **once**.  Reliable for gated/stopped CLK (phone, ~53 samples).  Locking
  once (not re-measuring) is drift-immune and avoids glitch re-anchors.
- **Edge-list bit reader (`_read_byte_edges`).** Per-byte edge reconstruction
  from the DATA edge list (re-anchors the next byte via `_next_start_fall`).
  Drift-immune.  Reliable for mid-session/edge mode; gated by `_edge_read`.
- **`decode_step` unified dispatch.** One state machine handles
  ATR/PPS/DATA + mid-session.  Reliable; current architecture.
- **`hasT0`/`hasT1` guards + init.** Prevents `AttributeError` and skips byte
  reading until a protocol is known.  Reliable.
- **T=0 case-3/4 ACK==INS discriminator.** First post-header byte == INS ⇒
  case 2/4 (response bounded by `P3`, or read-until-SW for `Le == 0`); else
  command data (read `P3`, then the procedure byte).  Reliable for
  consolidating STK envelope commands.  Gated to `_edge_read`.

### Tried and rejected (do not re-add)

- **Edge-counting as the *sole* bit reader (remove `native_fast`
  entirely).** Subtle per-bit sampling differences regressed `test_8` (35
  garbage).  Edge-counting is fine **as a second reader** (`_read_byte_edges`)
  used only in mid-session mode; it is not a drop-in replacement for the whole
  pipeline.
- **Signal-degradation ATR re-arm (`degraded` flag on ≥8/64 parity errors).**
  Triggered on the capture's natural bit errors, re-armed the ATR hunt
  mid-session, and fragmented the stream.  Rejected.
- **Clock-drift monitor (re-measure CLK every 128 bytes, re-anchor
  `samples_per_edge`).** Unneeded: locking the ETU once is sufficient and
  safer.  Rejected.
- **Fatal TCK check.** The example ATRs carry a wrong TCK (capture bit error,
  `got=f7 expected=80`); fatal rejection blocked the DATA state entirely.
  TCK must stay a non-fatal warning.  Rejected.
- **CLA/P1P2 heuristic routing to T=1.** Misread real T=0 traffic as T=1.
  Rejected.
- **`parse_packet` heuristic / APDU-boundary guessing from CLA/P1P2 + Le/ALG
  tables.** Produced false splits and mis-framed exchanges.  Rejected in favor
  of proper T=0/T=1 transport state machines.
- **`ignore_rst` / `ignore_vcc` options.** Superseded by channel assignment +
  hysteresis.  Rejected.
- **Generic "read response until a `6x`/`9x` status word" for T=0 framing.**
  Any `0x6x`/`0x9x` byte (e.g. command-data `0x6c`, FCP `0x6f`) was taken as
  SW1, truncating/fragmenting exchanges and dropping most of the capture.
  Rejected; replaced by the ACK==INS discriminator (case 2/4 bounded by
  `P3`) with a bounded until-SW only for case 4 / `Le == 0`.

### Open residual limitations

- Case-4 responses read "until SW" still terminate on the first `0x6x`/`0x9x`
  byte, so a response payload containing such a byte may truncate.  The
  phone's main case-4-with-data path is GET RESPONSE (case 2, bounded by
  `P3`) → unaffected.
- Mid-session captures that begin inside an exchange cannot frame the first
  command perfectly (expected; the rest of the stream is clean).
- **Samsung phones — gated CLK, non-default F/D** (`samsung_phone_sample.sr`,
  `samsung_phone2_sample.sr`).  Samsung1 uses F=512/D=32 (16 CLK cycles/bit);
  Samsung2 uses a different rate (~102-111 sample ETU).  `_measure_etu`
  now correctly measures the ETU from DATA edge spacings (after glitch
  filtering), but the first burst may start at a noisy position, producing
  wrong measurements.  Smoke-test only.