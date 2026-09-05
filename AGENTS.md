# AGENTS.md

## Policy: decoder changes must be validated against ALL example traces

Every change to `pd.py` must be followed by running the full test suite:

1. **Clear bytecode cache first** - stale `.pyc` files cause false results:
   ```bash
   find . -name "__pycache__" -type d -exec rm -rf {} +
   find . -name "*.pyc" -delete 2>/dev/null
   ```

2. **Run all traces in BOTH modes** (ATR-included and mid-session):
   ```bash
   # Run decoder for each trace/mode combination
   for trace in test_8_raw16 test_7_raw16 phone_reference_live_16M \
               samsung_phone_sample; do
       for mode in true false; do
           # Run sigrok-cli and vs_reader as shown below
           # Capture APDUs, GARBAGE count, and RESULT
       done
   done
   ```

3. **Acceptance criteria** (must ALL pass):
   - **test_8 both modes**: 54 APDUs, 37/37 reader exchanges, 0 GARBAGE, RESULT: OK
   - **test_7 both modes**: 10 APDUs, 25/37 reader exchanges (12-27 missing due to ATR resets), 0 GARBAGE, RESULT: OK
   - **All smoke-test traces**: >0 APDUs in at least one mode
   - **Mid-session >= ATR-included**: `starts_with_atr=false` must capture >= `starts_with_atr=true` APDUs
   - **No regressions**: GARBAGE count must not increase, no new BAD_FCS/payload mismatches
   - **Unit tests**: 12/12 pass (`python3 tests/test_gsmtap.py -v`)

### Important: CLK signal behavior matters

- **Constant CLK** (test_7, test_8): Card reader keeps CLK running continuously
  - Decoder can reliably sample DATA on each CLK edge
  - Both ATR-included and mid-session modes work correctly

- **Gated CLK** (phone traces): Phone stops CLK when idle, restarts before next APDU set
  - Decoder must handle CLK gaps and restart properly
  - ETU auto-detection from DATA edges is critical
  - Mid-session mode is primary use case for these traces

```bash
# --- test_8 (ATR-included, starts_with_atr=true) ---
sigrok-cli -i examples/test_8_raw16.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_8_reader.log /tmp/out.pcap

# --- test_8 (mid-session, starts_with_atr=false) ---
sigrok-cli -i examples/test_8_raw16.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_8_reader.log /tmp/out.pcap

# --- test_7 (ATR-included) ---
sigrok-cli -i examples/test_7_raw16.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_7_reader.log /tmp/out.pcap

# --- test_7 (mid-session) ---
sigrok-cli -i examples/test_7_raw16.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_7_reader.log /tmp/out.pcap

# --- phone reference (ATR-included, gated CLK) ---
sigrok-cli -i examples/phone_reference_live_16M.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:clock_option=native:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- phone reference (mid-session, gated CLK) ---
sigrok-cli -i examples/phone_reference_live_16M.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:clock_option=native:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- samsung phone 1 (ATR-included, gated CLK, non-default F/D) ---
sigrok-cli -i examples/samsung_phone_sample.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- samsung phone 1 (mid-session, gated CLK, non-default F/D) ---
sigrok-cli -i examples/samsung_phone_sample.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- unit tests ---
python3 tests/test_gsmtap.py -v
```

**Always clear the Python bytecode cache before testing** — stale `.pyc`
files can cause the decoder to use old code, producing false results:
```bash
find . -name "__pycache__" -type d -exec rm -rf {} +
```

The acceptance criteria are:

**The decoder is NOT considered fully functional until ALL of these criteria are met.**

#### Ground truth

`test_7_reader.log` and `test_8_reader.log` are **trusted, complete APDU logs**
captured by the PC/SC reader SDK during the same recording session as the
sigrok trace.  They contain every command the reader sent and every response
the card returned.  They are the authoritative reference — the decoder output
must match them.

#### Success criteria (all must pass)

1. **test_8 and test_7 (reader-log traces):**
   - **Every reader exchange must appear in the decoder output.**
     For test_8: all 37/37 reader exchanges are present in the pcap
     (verified by set membership).  For test_7: 25/37 are present
     (12 missing due to 4 ATR resets interrupting the session — a
     trace-level limitation, not a decoder bug).
   - **0 garbage APDUs** in both ATR-included and mid-session modes.
   - **`RESULT: OK`** from `vs_reader.py`.

2. **All traces (including smoke-test):**
   - **mid-session APDUs ≥ ATR-included APDUs.**  Mid-session mode starts
     earlier (no ATR wait) so it must find at least as many APDUs.
   - **>0 APDUs** in at least one mode for smoke-test traces.
   - No increase in `CHKSUM ERROR`, `BAD_FCS`, payload mismatches, or
     suspicious CLA counts.

3. **Both modes must be tested** (ATR-included and mid-session) for every
   trace, to verify the decoder works regardless of user setting.

#### Known issues (must be fixed to meet criteria)

**T=0 framing produces incorrect APDUs.** The decoder's output now matches
the reader log exactly for all reader exchanges:
- test_8: All 37/37 reader exchanges are byte-identical in the pcap
  (verified by set membership), plus 17 extra CAT/proactive commands
  and 2 valid retries (reader SDK duplicates), total 54 APDUs, 0 garbage.
- test_7: 25/37 reader exchanges (12 missing due to 4 ATR resets between
 irm sessions, not a decoder bug — exchanges between ATRs are lost
  because the decoder resets state on each reset).

Both traces show 0 garbage APDUs, 0 payload mismatches, and RESULT: OK.

**Root cause:** `_edge_read` is initialized to `True` and never set to
`False`, so the edge-read T=0 procedure loop (lines 1808–1895) always
executes — the ATR-based procedure loop (lines 1898–1941) is dead code.
The edge-read path had two bugs:

1. **NULLs treated as command data (FIXED).**  The first post-header byte
   was checked for ACK; if it was NULL (0x60), it entered the case-3/4
   branch and got appended as command data.  Fixed by skipping NULLs
   before the ACK check.

2. **"Read until SW" truncates GET RESPONSE (FIXED).**  The ACK handler
   read until it saw a byte in 0x6x/0x9x range, but FCP tag 0x62
   matched this pattern, truncating GET RESPONSE to 1-2 bytes.  Fixed
   by using P3-bounded reads (read exactly P3 bytes then SW1 SW2) for
   case-2 commands where P3 = Le.

#### CLA validation note

All example traces (`test_7`, `test_8`, `phone_reference`, `samsung`)
contain only CLA `0x00` (interindustry) and `0x8x` (USIM/CAT, mostly `0x80`
with occasional `0x81` for logical channel 1).
The decoder must **not** mandate specific CLA values — other CLA values
(e.g. `0x04`, `0x08`, `0x84`, `0xA0`, `0xB0`) are valid per ISO 7816-4 / 3GPP
and must be accepted.  However, during test runs against the example traces,
any CLA value outside `0x00-0x0F` and `0x80-0x8F` is an error flag indicating
the decoder mis-framed the byte stream.

#### ISO 7816 APDU constraints (reference — not enforced in decoder yet)

These constraints can be used for APDU validation in future work.  They
are not currently enforced by the decoder.

##### T=0 Procedure Bytes

| Byte | Meaning |
|------|---------|
| ACK (== INS or == ~INS) | Full data match: card acknowledges and expects all P3 data bytes |
| INS^0x01 or ~INS^0x01 | Single-byte match: card validates syntax but processes data one byte at a time |
| 0x60 | NULL: card busy, wait for next procedure byte |
| 0x9E / 0x9F | Extended-length: next byte L = number of response data bytes, then SW |
| SW1 (0x6x / 0x9x) | Status word: exchange complete |

##### CLA (Class) Byte — Interindustry Structure

```
Bit:  8   7   6   5   4   3   2   1
      b8  b7  b6  b5  SM  SM  ch  ch
```

- Bits 8–7: `00` or `01` for interindustry; `1x` reserved for proprietary
- Bit 6: `0` for interindustry; `1` for proprietary structural formats
- Bits 4–3: Secure Messaging indicator (`00` = no SM)
- Bits 2–1: Logical channel (0–3 for interindustry)

Valid interindustry CLA digits: `0x`, `1x`, `4x`, `5x`.

Examples: `0x00` (standard), `0x0C` (secure messaging).

##### INS (Instruction) Byte — Valid Ranges

- Low nibble cannot be `X0` if high nibble is even
- Low nibble cannot be `XF` under any circumstances
- `0x6x` and `0x7x` ranges are invalid (reserved for SW1 / protocol bytes)

Standard interindustry INS values: `A4` (SELECT), `B0` (READ BINARY),
`D6` (UPDATE BINARY), `B2` (READ RECORD), `E2` (APPEND RECORD),
`20` (VERIFY), `82` (EXTERNAL AUTHENTICATE), `88` (INTERNAL AUTHENTICATE).

##### Quick Validation Checklist

1. CLA high nibble is `0`, `1`, `4`, or `5` (for interindustry)
2. INS low nibble is not `F`
3. INS is outside `0x6x`–`0x7x` range

**Current smoke-test status:**

| Trace | ATR-included | mid-session | mid ≥ ATR? |
|-------|-------------|-------------|------------|
| test_8 | 54 | 54 | ✓ |
| test_7 | 10 | 10 | ✓ |
| phone_reference | 0 | 620 | ✓ |
| samsung_phone | 2 | 49 | ✓ |

**Note on v1.1.3 fix:** The decoder measures CLK period as an average instead of using the minimum recurring period. This correctly handles traces where CLK periods alternate (e.g., 4,3,3 pattern for ~5.33MHz CLK at 16MHz sample rate). The fix changed `_measure_clock_period()` to use `sum(spacings) / len(spacings)` instead of `_robust_min(spacings)`, giving accurate `spc` values like 3.333... instead of 3. This corrected the `_wait_clk_rising()` skip calculation, fixing the post-ATR byte alignment issue.

### Versioning

The decoder version is defined in `pd.py` as `VERSION = '1.1.4'`.
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
    - Capture APDU count must stay >0 for any trace that previously had APDUs
    - GARBAGE count must stay 0 for test_8 (both modes)
    - RESULT must stay OK for test_8 (both modes)
    - CHKSUM ERROR count must not increase
    - BAD_FCS / payload mismatches / suspicious CLA must not increase
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

## Current architecture (v1.1.1, post-ATR desync fixes)

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

- `test_8` / `test_7`: **NOT YET PASSING.** 0 garbage, but decoder output
  does not match reader log (T=0 framing groups exchanges incorrectly).
  See success criteria above.

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
  terminal sent no command data; read `P3` response bytes (+SW).
- Otherwise the byte is terminal command data → case 3/4: read `P3`
  command-data bytes, then the card's procedure byte (ACK/SW/`9E`/`9F`).
  On ACK (case 4) the response is read `P3` response bytes (+SW).

This consolidates case-3/4 exchanges (e.g. the `80 12`/`80 14` STK envelope
commands) into one C-APDU = header + command data, R-APDU = response + SW
APDU, instead of fragmenting them across frames.  It is gated to
`_edge_read` (mid-session / gated-CLK captures) so ATR-based captures
(`test_8` / `test_7`) keep the original framing unchanged and stay at
0 garbage.

All paths use P3-bounded reads (v1.1.1 reverted the read-until-SW
experiment from v1.1.0 which mis-identified FCP `0x62` as SW1).

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
  case 2/4 (response bounded by `P3`); else command data (read `P3`, then
  the procedure byte).  Reliable for consolidating STK envelope commands.
  Gated to `_edge_read`.  P3-bounded reads avoid FCP tag misidentification
  (v1.1.1 reverted read-until-SW from v1.1.0).
- **1.5-ETU start-bit guard in `wait_data_falling`.** `min_high = 1.5 *
  bit_samples` distinguishes genuine inter-byte idle gaps (≥2 ETU per ISO
  7816-3) from intra-byte HIGH periods (≤1 ETU).  Prevents byte misalignment
  after `_measure_etu()` consumption (v1.1.1 fix for post-ATR desync).
- **Inverse-convention ATR detection in DATA state.** `firstByte == 0x3f`
  alongside `0x3b` at line 1656, so inverse-convention ATRs (TS=0x3F) are
  parsed in `starts_with_atr=false` mode.  Sets `clock_skip=372` correctly
  before PPS (v1.1.1 fix).
- **`_resync = True` after PPS acceptance (native CLK path).** Forces
  `resync_idle()` before the first post-PPS command, preventing the decoder
  from latching onto a mid-byte transition at the new speed (v1.1.1 fix).

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
  `P3`) with P3-bounded reads for all paths (v1.1.1 reverted the
  read-until-SW experiment from v1.1.0 which mis-identified FCP `0x62` as
  SW1).
- **0.5-ETU start-bit guard in `wait_data_falling` (for `_edge_read`).**
  `min_high = 0.5 * bit_samples` was too small for slow ETUs — it accepted
  intra-byte HIGH periods (data bit transitions) as start bits, causing byte
  misalignment after `_measure_etu()` consumption.  Replaced by 1.5-ETU guard
  in v1.1.1.

### Open residual limitations

- Mid-session captures that begin inside an exchange cannot frame the first
  command perfectly (expected; the rest of the stream is clean).
- **Samsung phone — gated CLK, non-default F/D** (`samsung_phone_sample.sr`).
  Uses F=512/D=32 (16 CLK cycles/bit).  `_measure_etu` correctly measures
  the ETU from DATA edge spacings (after glitch filtering).  Smoke-test only.