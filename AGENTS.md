# AGENTS.md

## Policy: decoder changes must be validated against ALL example traces

Every change to `pd.py` must be followed by running the full test suite:

1. **Clear bytecode cache first** - stale `.pyc` files cause false results:
   ```bash
   find . -name "__pycache__" -type d -exec rm -rf {} +
   find . -name "*.pyc" -delete 2>/dev/null
   ```

2. **Run all traces in mid-session mode** (the decoder always runs this way;
   captures
   all APDUs, including cold-boot ATRs):
   ```bash
   # Run decoder for each trace
   for trace in test_8_raw16 test_7_raw16 xiaomi_phone_sample \
               samsung_phone_sample \
               xiaomi_mi_a1_coldboot_sample 4gmodem_coldboot_sample \
               samsung_A55_coldboot_new_cable samsung_A55_coldboot_new_cable_sim2 \
               samsung_S21p_coldboot_new_cable samsung_S21p_coldboot_new_cable_sim2; do
       # Run sigrok-cli and vs_reader as shown below
       # Capture APDUs, GARBAGE count, and RESULT
   done
   ```

3. **Acceptance criteria** (must ALL pass):
   - **test_8 mid-session**: 56 APDUs, 28/37 reader exchanges (9 pre-capture), 0 GARBAGE, RESULT: OK
   - **test_7 mid-session**: 65 APDUs, 37/37 reader exchanges, 0 GARBAGE, RESULT: OK
   - **All smoke-test traces**: >0 APDUs in mid-session mode
   - **No regressions**: GARBAGE count must not increase, no new BAD_FCS/payload mismatches
   - **Unit tests**: 30/30 pass (`python3 tests/test_gsmtap.py -v`)

### Important: CLK signal behavior matters

- **Constant CLK** (test_7, test_8): Card reader keeps CLK running continuously
  - Decoder can reliably sample DATA on each CLK edge
  - Cold-boot re-arm handles warm resets

- **Gated CLK** (phone traces): Phone stops CLK when idle, restarts before next APDU set
  - Decoder must handle CLK gaps and restart properly
  - ETU auto-detection from DATA edges is critical
  - This is the decoder's primary use case

- **Cold boot captured pre-power-up** (`*_coldboot_sample.sr`): VCC/RST are LOW
  at t=0, capture spans the power-on (~17 s at 16 MHz), and the card emits its
  ATR once RST deasserts
  - Decoder must arm the ATR hunt when RST is still low at capture start
    (see "Cold-boot re-arm") and not lock an ETU from pre-ATR power-up traffic
  - It must decode the ATR `3b9f96801f...001e`
  - `rst_detect=true`, `vcc_detect=true` for these fixtures

```bash
# --- test_8 ---
sigrok-cli -i examples/test_8_raw16.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_8_reader.log /tmp/out.pcap

# --- test_7 ---
sigrok-cli -i examples/test_7_raw16.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null
python3 tools/vs_reader.py examples/test_7_reader.log /tmp/out.pcap

# --- xiaomi phone (gated CLK) ---
sigrok-cli -i examples/xiaomi_phone_sample.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:clock_option=native:protocol=T=0:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- samsung phone 1 (gated CLK, non-default F/D) ---
sigrok-cli -i examples/samsung_phone_sample.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- xiaomi_mi_a1_coldboot (starts pre-power-up) ---
#     rst_detect/vcc_detect=true are required for these fixtures.
sigrok-cli -i examples/xiaomi_mi_a1_coldboot_sample.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
  -A iso7816 >/dev/null

# --- 4gmodem_coldboot ---
sigrok-cli -i examples/4gmodem_coldboot_sample.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap \
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
     For test_8: 28/37 reader exchanges are present in the pcap
     (9 missing because they occurred before the capture started —
     a trace-level limitation, not a decoder bug).  For test_7: all
     37/37 are present after the v1.1.10 deglitch fix (previously
     only 10/37 due to ATR resets fragmenting the session).
   - **0 garbage APDUs** in mid-session mode.
   - **`RESULT: OK`** from `vs_reader.py`.

2. **All traces (including smoke-test):**
   - **>0 APDUs** in mid-session mode for smoke-test traces.
   - No increase in `CHKSUM ERROR`, `BAD_FCS`, payload mismatches, or
     suspicious CLA counts.

3. **Every trace must be tested** (the decoder always runs mid-session — it
   captures all APDUs, including cold-boot ATRs).

#### Known issues (must be fixed to meet criteria)

**T=0 framing produces incorrect APDUs.** The decoder's output now matches
the reader log for all reader exchanges:
- test_8: 28/37 reader exchanges are byte-identical in the pcap
  (9 missing because they occurred before the capture started),
  plus 17 extra CAT/proactive commands and 11 valid retries,
  total 56 APDUs, 0 garbage.
- test_7: All 37/37 reader exchanges are byte-identical in the pcap,
  plus 17 CAT/proactive commands, 8 ATRs, and 11 valid retries,
  total 65 APDUs, 0 garbage.

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

All example traces (`test_7`, `test_8`, `xiaomi`, `samsung`)
contain only CLA `0x00` (interindustry) and `0x8x` (USIM/CAT, mostly `0x80`
with occasional `0x81` for logical channel 1).
The decoder must **not** mandate specific CLA values — other CLA values
(e.g. `0x04`, `0x08`, `0x84`, `0xA0`, `0xB0`) are valid per ISO 7816-4 / 3GPP
and must be accepted.  However, during test runs against the example traces,
any CLA value outside `0x00-0x0F` and `0x80-0x8F` is an error flag indicating
the decoder mis-framed the byte stream.

#### ISO 7816 APDU validation (enforced from v1.1.7)

The decoder validates every reassembled T=0 APDU with `validate_t0_apdu()`
before emitting it.  Invalid APDUs are still packed into gsmtap but are
flagged with `GSMTAP_FLAG_BAD_FCS`.

Validation is purely structural (no content scanning of command/response
data), so the false-positive rate is very low.  The checks are:

1. Length is at least 7 bytes (header + SW) and at most `MAX_TPDU_LEN` (271).
2. CLA byte is in the recognized set (`0x00`, `0x04`, `0x08`, `0x80`,
   `0x84`, `0xA0`, `0xB0`).
3. INS byte is plausible: not `0x00`, not in `0x6x`/`0x9x` (status-word
   collision), and the least-significant bit is `0`.
4. The penultimate byte (SW1) is in `0x6x` or `0x9x`.

The current validation deliberately does **not** enforce P3-based length
constraints, because a card may reject a command and send the status word
immediately even when P3 > 0.

#### v1.4.0: CONCAT detection (embedded exchanges, issue #1 gate)

A byte-drop mis-frame swallows several real T=0 exchanges into one
structurally "valid" packet: each swallowed header survives verbatim in the
data region, followed by its P3 data bytes and an interior status word.
Such packets pass `validate_t0_apdu()` but produce wrong APDUs downstream.
`embedded_exchanges()` (pd.py) scans the data region (`[5, n-9]`) for
embedded complete exchanges:

- header `CLA INS P1 P2 P3` where `INS ∈ EMBEDDED_INS` (commands that
  actually occur on these cards: 12/14/20/44/70/88/A2/A4/B0/B2/B6/C0/C2/
  CA/CB/D6/DC/F2) and `P3 ≥ 1`
- CLA valid, or the phantom byte-drop artifact `0x01` (corrupt `0x00`),
  with a one-byte prefix slip tolerated when byte `0x01` precedes a real
  header
- SW1 accepted in a 3-byte slack window after the nominal data end
  (`d1 = s + 5 + p3`), from `EMBEDDED_SW1` (real status bytes that are not
  also frequent data bytes), and the SW must be interior (`sw < n-2`, i.e.
  more exchange data must follow it)

On a hit the decoder flags the packet `GSMTAP_FLAG_BAD_FCS` and logs
`CONCAT APDU: <k> embedded exchange(s) at <offsets>; packet <hex>`, so the
gate works live and offline.  The detector is precision-tuned against all
10 example traces: 0 hits on clean traces (test_8/test_7/4gmodem), and it
flags every known corrupted family:

| Trace | APDUs | CONCAT hits |
|-------|-------|-------------|
| test_8 | 56 | 0 |
| test_7 | 65 | 0 |
| xiaomi_phone | 620 | 4 |
| samsung_phone | 924 | 5 |
| xiaomi_mi_a1_coldboot | 459 | 3 |
| 4gmodem_coldboot | 327 | 0 |
| A55_coldboot_new_cable | 386 | 3 |
| A55_coldboot_new_cable_sim2 | 375 | 2 |
| S21p_coldboot_new_cable | 380 | 3 |
| S21p_coldboot_new_cable_sim2 | 356 | 2 |

The concat packets are BAD_FCS-flagged on the phone traces, so their BAD_FCS
counts now equal the CONCAT counts (deliberate: those APDUs are genuinely
desynced).  `vs_reader.py` reports the same detector; `capture_baseline.sh`
prints `CONCAT APDU count: N` per trace (grep of the `CONCAT APDU:` log line
only, so one line per packet).  Acceptance: test_8/test_7/4gmodem must stay
0; phone-trace counts must not increase.

### v1.4.0: CONCAT gate — embedded-exchange detection (issue #1)

The decoder previously emitted byte-drop-mis-framed APDUs that swallowed
several real exchanges into one "valid" packet (the Samsung/xiaomi
"wrong APDU" family).  Fragmentation is not representable in the
assembled bytes, so this is fixed as a detection gate, not a reframe:

- `embedded_exchanges()` scans the data region for embedded complete
  exchanges (see "v1.4.0: CONCAT detection" under APDU validation).
- Hits are flagged `GSMTAP_FLAG_BAD_FCS` + logged `CONCAT APDU: ...`.
- `vs_reader.py` / `capture_baseline.sh` gain a `CONCAT` metric
  (packet counts match the log lines exactly).
- Unit tests cover the tuned vectors (clean FCP/READ-RECORD/SELECT never
  hit; U1/U4/record-burst/xiaomi swallows are caught).
- VERSION → 1.4.0.  Baseline regenerated with the new CONCAT columns.

A proper *reframing* (re-splitting those packets and byte-dropping the
mis-frame at the source) is the next decoder step; until then the gate
makes the corruption visible in live and offline captures instead of
silently producing wrong APDUs.

### v1.6.0: ATR-hunt deadlock + idle-loop trap fixes

A live Samsung cold-boot capture that never emits a 372-rate ATR exposed two
defects in the ATR hunt (`state == 'FIND START'`):

1. **Deadlock.** `RST low at start` arms the hunt at the spec-default
   `clock_skip=372` with `bit_samples=None`.  The ETU-recovery routine
   `_measure_etu()` is only reachable from the `DATA` state, which the hunt
   can only enter after reading a valid `TS=0x3B/0x3F` (or a plausible
   CLA/INS header) **at 372**.  A card already running at a non-default F/D
   (Samsung `F=512/D=32` -> 16 CLK/bit) produces none, so the hunt reads
   idle `0xFF` forever and never reaches the ETU measurement -- a circular
   dependency.  This is why Samsung (non-default F/D) fails where
   default-F/D devices succeed: not clock rate, but `F/D`.

2. **Trap.** The all-`0xFF` branch unconditionally reset `_atr_hunt_count=0`
   and returned to `FIND START`, so the bounded fall-through to `DATA` was
   unreachable.  With RST re-arm also resetting the counter, the hunt could
   spin forever.

Fixes:

- **Hunt-side ETU recovery.** `_recover_etu_in_hunt()` runs `_measure_etu()`
  + `_derive_clock_skip_from_etu()` from the hunt after the default-rate
  hunt has already failed a few rounds, so a fast device is read at its
  true rate.  It reuses the DATA-path `_confirm_etu()` validation, so a
  noise-locked ETU self-clears after 2 parity failures.  No-op for normal
  ATRs (parsed on hunt 1).
- **Bounded escape.** `_atr_hunt_failure_action(byte)` (pure, unit-tested)
  returns `recover` / `retry` / `resume_data`.  ETU recovery every 2 failed
  rounds up to 3 times; then a hard bound (`_atr_fail_total >= 12`) or the
  all-`0xFF` idle cap (3) falls through to the existing "resuming DATA
  without synthetic ATR" path (clearing `bit_samples` so the DATA path
  re-measures).
- **Persistent counters.** `_atr_fail_total`, `_hunt_etu_attempts`,
  `_atr_idle_resets` are reset only on a successful ATR parse, **not** on
  RST re-arm -- otherwise a phone that power-cycles RST while never sending
  a valid ATR would starve the escape.  Constants: `ATR_HUNT_ETU_ATTEMPTS=3`,
  `ATR_HUNT_IDLE_RESETS=3`, `ATR_HUNT_FAIL_LIMIT=12`.

Verification: no regression on the full trace suite (test_8 56/0/OK,
test_7 65/0/OK, xiaomi 640, xiaomi_cold 473, 4gmodem 327, A55 407/395,
S21p 399/375, target S21p_coldboot 369, all `RESULT: OK`, 0 CONCAT);
54/54 unit tests (7 new hunt-escape regression tests).  VERSION -> 1.6.0.

Known limitation: no on-disk fixture reproduces the exact live failure (all
real captures contain a 372 ATR), so end-to-end proof needs a re-captured
`.sr` from the failing phone; the unit tests cover the loop-escape logic.

### v1.7.1: accept EOFError as clean end-of-stream (newer libsigrokdecode)

Newer libsigrokdecode signals end-of-capture from `wait()` by raising
`EOFError("samples exhausted")`; the 0.5.3 build on the Linux dev box instead
returns `None` / raises `SystemError`, so this only showed up on Windows (a
newer libsigrokdecode).  The framework explicitly accepts `EOFError` out of
`decode()` as normal termination (`instance.c`: "Termination with an
EOFError exception is accepted"), but our `decode()` caught it in the generic
`except Exception` handler, printing a traceback, logging `DECODE ERROR`, and
resyncing -- retrying up to 50 times and flooding the log (looked like a
crash) at the end of every capture.

- `decode()` and the five `except SystemError: raise` guards now use
  `except (SystemError, EOFError): raise`, so the end-of-stream signal
  propagates and libsigrokdecode terminates cleanly.  The critical guard is
  `_measure_clock_period()`, whose `try` wraps a `wait()` loop.
- 2 new unit tests assert `decode()` re-raises `EOFError` and `SystemError`.
- 67/67 unit tests.  VERSION -> 1.7.1.

Deployment note: the Windows decoder is a git clone, so `git pull` there
(and deleting `__pycache__`) picks this up; the EOF error cannot be
reproduced against Linux 0.5.3.

### v1.7.0: spurious end-of-decode hardening + start.sh session resilience

A live capture could end without Ctrl+C (the session simply stopped).  The
frontend symptom was a flood of `sr: session: sr_session_stop: session was
NULL`, but the decoder also had latent paths that could end `decode()` early
on an idle/busy live line.  Fixed:

1. **`_at_eof()`.**  `decode_step()` treated `samplenum == _last_sn` as EOF,
   but a step can legitimately consume only queued bytes (`_replay` /
   `peeked_byte`) without advancing the stream -- e.g. the v1.5.0 invalid-INS
   re-frame.  Such steps are now allowed up to 64 in a row; only a genuinely
   stuck stream with nothing queued ends the decode.
2. **`_stall_check(track=False)`.**  The idle-LEVEL wait in
   `wait_data_falling()` returns immediately at the current sample whenever
   DATA is already idle -- normal on a live idle line, not EOF.  Stall
   counting is now disabled for that wait (only `pins is None` means EOF);
   sample-stall detection is kept for the start-bit EDGE wait.
3. **`resync_idle()` null guard.**  It indexed `pins[self.DATA_IDX]` after
   `wait()` with no `None` check; at stream end that raised `TypeError`.  Now
   sets `_eof` and returns.

**Effect:** `samsung_phone_sample.sr` had been halting at sample ~21.9M of
320M (1 APDU).  It now decodes through sample ~293M to a true end: **939
APDUs**, `CHKSUM=176`.  The extra 6 `CONCAT` packets are real mis-framed STK
bursts that were simply never reached before -- the known Samsung
de-concatenation family; the rest of the suite is unchanged.

**start.sh:** auto-restart is now the **default** (`--no-loop` disables), so
an intermittent FX2 USB stop reconnects instead of ending the session;
per-session pcap suffix (`.N.pcap`) so a restart never overwrites the
previous capture; and the repetitive `sr_session_stop: session was NULL`
teardown line is filtered from stderr (real decoder errors still pass).

Validation: test_8 56/0/OK, test_7 65/0/OK, xiaomi_phone 640, xiaomi_cold
473, 4gmodem 327, A55 407/395, S21p 399/375, target S21p 369 -- all
`RESULT: OK`, 0 CONCAT.  65/65 unit tests (10 new).  VERSION -> 1.7.0.

### v1.5.0: invalid-INS one-byte re-frame (residual CONCATs → 0)

The last CONCAT family (4gmodem/A55_sim2/S21p_sim2) is now **reframed at
the source**, not just gated.  All 10 traces report 0 CONCAT:

| Trace | APDUs | CONCAT hits |
|-------|-------|-------------|
| test_8 | 56 | 0 |
| test_7 | 65 | 0 |
| xiaomi_phone | 640 | 0 |
| samsung_phone | 924 | 0 |
| xiaomi_mi_a1_coldboot | 473 | 0 |
| 4gmodem_coldboot | 327 | 0 |
| A55_coldboot_new_cable | 407 | 0 |
| A55_coldboot_new_cable_sim2 | 395 | 0 |
| S21p_coldboot_new_cable | 399 | 0 |
| S21p_coldboot_new_cable_sim2 | 375 | 0 |

1. **One-byte re-frame on invalid INS.**  When a 5-byte header window passes
   `plausible_cla()` but the INS is unusable (`0x00`, `0x6x`/`0x9x`, or odd
   LSB — ISO 7816-4 §12.1.1), the window is almost always shifted by one
   stray leading byte (e.g. a leftover SW2 read after a PACKETEND).  The old
   code silently dropped all 5 bytes plus resync (`_resync = True`), and when
   `resync_idle()` gave up on a busy burst the next byte became a bogus CLA
   whose P3 swallowed the whole dialog into one CONCAT packet.  Now the
   decoder drops **only** the leading byte (explicitly logged via
   `_note_discard`), re-frames the remaining four via `_replay`, and lets the
   next decode step start a fresh header at the old INS.  Example (4gmodem):
   the stray `0f` after the READ BINARY SW1 `91` re-frames `0f 00 a4 08 04`
   → `00 a4 08 04 02`, recovering the true SELECT `00 a4 08 04 02 2f 00 →
   61 1c` verbatim.
2. **No-silent-discard invariant.**  Every byte the decoder consumes without
   emitting is now explicitly logged via `_note_discard(value, reason,
   idle=...)`.  `idle=True` discards (0x00/0xFF idle stretches, NULLs, stuck
   low) are rate-limited to the 1st + every 256th; `idle=False` discards
   (suspicious CLA, invalid-INS re-frame byte, non-SW bytes in read-until-SW
   scans) always put an `ANN_WARN` and the reason.  Idle-line noise,
   suspicious-CLA, stuck-low, and idle-byte-in-header consumers all go
   through `_consume_first()` (which pops `_replay` before `peeked_byte`) so
   re-framed bytes cannot infinite-loop.
3. **`_consume_first()` semantics.**  `read_byte()` pops `_replay.popleft()`
   first and only falls through to the wire; `peek_byte()` returns
   `_replay[0]` first.  Neither updates `peeked_samplenum`, so the re-frame
   branch explicitly restores `self.peeked_samplenum = es` (the first byte's
   sample) before pushing the 4 remaining bytes — the next header annotates
   from a valid sample number.
4. **Counters.**  `reset()` initializes `_discard_total` / `_idle_discard_total`; every `_note_discard` line carries "discards so far: N" for session-level triage.

The CONCAT detector (`embedded_exchanges()`, v1.4.0) stays as a regression
gate and now reports 0 on every trace.  VERSION → 1.5.0.  Baseline
regenerated.

**Phase B status (v1.5.0).** Two edge-reader hardening fixes shipped, both
verified byte-neutral on all 10 traces (stored baseline unchanged):

- `_next_start_fall()` now rejects sub-ETU phantom falls (a genuine start
  fall must stay LOW for >= half an ETU) — B2.
- `_read_byte_edges()` re-anchors forward on a spurious latch instead of
  dropping the byte (a drop fabricates a 0x00 / shifts the boundary) — B1.

Root cause of the Samsung/xiaomi phone-trace concatenation (the B1/B2 family)
is fixed at the source by the v1.5.0 invalid-INS re-frame — the A55 burst
cases decode clean with 0 CONCAT.  The residual 4gmodem/A55_sim2/S21p_sim2
family (leftover-SW2-shifted header) is also gone.  The planned B3 (strict
positional genuine-start anchor in the no-idle resync path) directly
conflicts with the documented 0.5-vs-1.5-ETU guard trade-off for fast phone
ETUs and risks the Samsung de-concatenation; it needs a dedicated design +
live validation, not an incremental patch.

### v1.3.0: `starts_with_atr` option removed

The entire ATR-included mode was redundant: its only mode-specific logic was a
start-state bootstrap (`FIND START` vs `DATA`) and an early trust hint for
`clock_skip=372`, both of which mid-session decoding reproduces via the
warm-reset / cold-boot re-arms already handled in `state == 'DATA'`
(starting the hunt instead of a fixed initial state).  Every trace in the
suite produces identical APDU/GARBAGE/CHKSUM results with the option removed.
Removed:

- The `starts_with_atr` decoder option (schema + the 6 branching sites in
  `pd.py`: initial state, `_clock_skip_confident` bootstrap, the
  `handle_atr` samplenum save/restore, the cold-boot re-arm guard, and the
  ETU re-measure condition — now `self.bit_samples is None or
  self._pps_speed_changed`).
- `--starts-with-atr` from `start.sh` (now warned as obsolete).

The decoder always starts in `DATA` and re-arms the ATR hunt as needed.

### v1.2.1: cold-boot capture support

A capture that starts pre-power-up (VCC/RST low at t=0) previously locked a
bogus ETU (`bit_samples=1548`, `clock_skip=369`) from pre-ATR power-up DATA
transitions in mid-session mode, so the real ATR never synced.  Fixed in
`241b7ed`:

- **Priming.** First `decode_step` reads the initial RST/VCC levels instead of
  defaulting `last_rst`/`last_vcc` to 0 (which fabricated a reset edge).
- **Cold-boot re-arm.** RST low at capture start → arm the hunt at the
  spec-default rate (FIND START, `clock_skip=372`, no ETU lock).
- **Guarded deassert re-arm.** The 10 ms-hysteresis-confirmed deassert lands
  mid-ATR on warm resets; it only re-arms when `state == 'DATA'` so it no
  longer garbles the in-flight ATR read (test_8 mid-session CHKSUM 18→0,
  test_7 ATR-included 2→0).

New fixtures `xiaomi_mi_a1_coldboot_sample.sr` / `4gmodem_coldboot_sample.sr`
decode their full ATR in both modes with 0 GARBAGE.

### v1.2.0: start-bit deglitch (Samsung de-concatenation)

Samsung phone traces with gated CLK and non-default F/D (16 CLK/ETU)
produced concatenated APDUs: multiple T=0 exchanges merged into a single
GSMTAP packet.  The v1.1.9 fixes (turnaround idle handling, edge-list
deglitch) improved other phone traces but the Samsung trace still showed
concatenation because the CLK-synchronous reader's start-bit detector
could not use the edge-list deglitch filter.

Fix applied (v1.2.0):
- Add a 2-sample deglitch in `wait_data_falling()`: after the 1.5-ETU
  minimum-high guard passes, skip 2 additional samples and re-check DATA.
  If DATA returns to idle, the start bit was a glitch → continue hunting.
  This eliminates 1-sample (62.5 ns) LOW glitches in inter-byte guard
  times that caused byte-level misalignment in the CLK-sync reader.

Results:
- Samsung mid-session: 52 → 924 APDUs (de-concatenated), all valid ISO 7816
  commands (SELECT, GET RESPONSE, READ BINARY, STATUS, STK envelope), 0 GARBAGE.
- test_7 ATR: 10 → 65 APDUs, all 37/37 reader exchanges now captured
  (was 10/37 in v1.1.9 due to ATR resets fragmenting the session).
- test_8 ATR: 54 → 56 APDUs, 28/37 reader exchanges (unchanged — 9 missing
  are pre-capture, not a decoder issue).
- Xiaomi mid-session: 620 APDUs (unchanged, no regression).

**Glitch rejection measurements** (`-l 5` session log):

| Trace | Glitches rejected | Notes |
|-------|-------------------|-------|
| test_8 (reader) | 6 | Constant CLK, minor noise/turnaround artifacts |
| test_7 (reader) | 14 | Constant CLK, more activity than test_8 |
| xiaomi (phone) | **0** | Edge-list `_deglitch_edges()` filters before `wait_data_falling` |
| samsung (phone) | **1041** | CLK-sync reader has no upstream deglitch, confirms FX2LP pull-up hypothesis |

Xiaomi shows 0 because the edge-list reader's `_deglitch_edges()` (0.2×ETU
threshold) removes sub-ETU pulses before they reach `wait_data_falling()`.
The CLK-sync reader has no equivalent filter, so Samsung catches every
glitch.  The 6–14 glitches on reader traces are minor noise or turnaround
artifacts in the constant-CLK captures.

The 2-sample advance in `wait_data_falling` shifts `_start_fall` by 2
samples, but at Samsung's 16 CLK/ETU (~72 samples) this is negligible
(<3% of a bit period) and does not affect downstream byte reading.

**Design note: magic number.** `_min_pulse_samples = 2` is tuned for the
primary 16 MHz sample rate (2 samples ≈ 125 ns, well within the FX2LP
pull-up rise time of 200–500 ns).  At other sample rates the value would
need adjustment — but since all current traces are 16 MHz, this is left
as a hardcoded constant rather than a decoder option.  If 12 MHz or
24 MHz traces are added later, consider making it configurable or
scaling it from the sample rate.

**Logging.** Each rejected start-bit glitch is logged with a running
count (`start-bit glitch rejected (#N)`) visible in the session log.
This helps diagnose whether the deglitch is too aggressive on a
particular capture — if the count is unexpectedly high, the 2-sample
window may be filtering real start bits.

### Proven data rates (all at 16 MHz sample rate)

| Trace | ETU (samples) | CLK/ETU | Mode |
|-------|---------------|---------|------|
| test_8 | ~43 | 372 (standard) | constant CLK, ATR+PPS |
| test_7 | ~43 | 372 (standard) | constant CLK, warm resets |
| xiaomi | ~53 | recovered from DATA | gated CLK, mid-session |
| samsung | ~72 | 16 (F=512/D=32) | gated CLK, non-standard F/D |

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

| Trace | APDUs |
|-------|-------|
| test_8 | 56 |
| test_7 | 65 |
| xiaomi_phone | 640 |
| samsung_phone | 924 |
| xiaomi_mi_a1_coldboot | 473 |
| 4gmodem_coldboot | 327 |
| A55_coldboot_new_cable | 407 |
| A55_coldboot_new_cable_sim2 | 395 |
| S21p_coldboot_new_cable | 380 |
| S21p_coldboot_new_cable_sim2 | 356 |

The baseline runs every trace through the decoder once
(intentional since v1.3.0: the `starts_with_atr` option was removed and the
decoder always runs mid-session — it captures all APDUs, including cold-boot
ATRs, and is the only mode that works on gated-CLK phone traces).

The four `samsung_*_coldboot_new_cable*_sim2` fixtures were captured with the
new short cable (30 mm wires, external pull resistors GND→VCC and VCC→DATA),
named channels `DATA/VCC/RST/CLK` on bits 0/2/4/5 at 16 MHz.  All four decode
their full cold-boot ATR (`3b9f9580…` on SIM1, `3b9f9680…` on SIM2) with
0 GARBAGE / 0 BAD_FCS.  S21p SIM2 carries 197 CHKSUM (dirty-wire parity
noise, BAD_FCS still 0); A55 SIM2 is clean (0 CHKSUM).  The `_sim2` fixtures
are cropped to the power-on window (the 17–21 s of pre-power idle was
removed).

Cold-boot fixtures start **before power-up**
(VCC/RST low at t=0); the decoder must arm the ATR hunt when RST is still low
at capture start and decode the full ATR once the card wakes (~17 s in).
`l8star_coldboot_sample.sr` was captured in the same session but had a
dirty-wire tail (GARBAGE=1 / RESULT UNCLEAN) and was dropped from the suite.

**Note on v1.1.3 fix:** The decoder measures CLK period as an average instead of using the minimum recurring period. This correctly handles traces where CLK periods alternate (e.g., 4,3,3 pattern for ~5.33MHz CLK at 16MHz sample rate). The fix changed `_measure_clock_period()` to use `sum(spacings) / len(spacings)` instead of `_robust_min(spacings)`, giving accurate `spc` values like 3.333... instead of 3. This corrected the `_wait_clk_rising()` skip calculation, fixing the post-ATR byte alignment issue.

### GSMTAP wire-format extensions

The GSMTAP-SIM output deviates from libosmocore's gsmtap.h in three
documented ways (see README.md "GSMTAP events" and the comments in
`gsmtap_stream.py`): sub_type 0x02 (`GSMTAP_SIM_PPS`) carries the PPS
request + response combined under the spec's `PPS_REQ` value (the spec
splits into `PPS_REQ` 0x02 / `PPS_RSP` 0x03; 0x03 is unused here);
0x10/0x11 (`RST_EVENT`/`VCC_EVENT`) are custom line-event subtypes; and
`GSMTAP_FLAG_BAD_FCS` writes flags into the header `res` byte, which
official gsmtap.h reserves — a simtrace2-sniff convention.

### Versioning

The decoder version is defined in `pd.py` as `VERSION = '1.7.1'`.
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
    - GARBAGE count must stay 0 for test_8 (mid-session)
    - RESULT must stay OK for test_8 (mid-session)
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

For a live mid-session phone capture (`protocol=T=0`),
the decoder now:

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
- **Warm-reset re-arm (guarded).** RST deassert → re-arm the ATR hunt
  (`FIND START`, `clock_skip` 372, cleared ETU) **only when `state == 'DATA'`**
  (hunt genuinely idle).  Deasserts that arrive while `FIND START`/`ATR` is in
  progress just log "RST deasserted (hunt/ATR already in progress)" and leave
  state alone — an unguarded mid-ATR re-arm corrupted the in-flight ATR read
  (test_8 mid-session CHKSUM 18→0, test_7 ATR-included 2→0 after the guard).
  Reliable; re-ATRs parse at the default rate.
- **Cold-boot priming.** One-shot on the first `decode_step`: `wait({'skip': 0})`
  reads the *initial* VCC/RST levels instead of defaulting `last_rst`/`last_vcc`
  to `0`.  Without this, a capture that starts pre-power-up fabricated a spurious
  reset at sample 0.
- **Cold-boot re-arm.** When the capture starts with RST **low** (VCC not yet
  on), arm the hunt immediately regardless of start conditions: state
  `FIND START`,
  `_atr_hunt_count=0`, `clock_skip=372`, `bit_samples=None` (no ETU lock), so the
  pre-ATR power-up DATA transitions cannot lock a bogus ETU (`bit_samples=1548`,
  `clock_skip=369` before this fix).  Logs "RST low at start: expecting cold-boot
  ATR".  Decodes the full cold-boot ATR on `xiaomi_mi_a1_coldboot_sample.sr` /
  `4gmodem_coldboot_sample.sr` (0 GARBAGE).
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
  parsed by the default state.  Sets `clock_skip=372` correctly
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
  the ETU from DATA edge spacings (after glitch filtering).  Now passes
  with 0 GARBAGE and de-concatenated APDUs after v1.1.10 deglitch fix.

### v1.1.6 fix: bounded T=0 loops and explicit EOF handling

Tightened the edge-read T=0 procedure-byte handlers to prevent runaway
reads and to surface end-of-capture explicitly.

1. **Bounded all "read until SW" / turnaround-skip loops.**  Replaced the
   unbounded ACK-handler `while` and the open-ended `range(512)` loops with
   `for _ in range(MAX_TPDU_LEN)`.  Added EOF checks so the decoder returns
   cleanly at end-of-capture instead of consuming zeros/turnaround bytes
   indefinitely.

2. **`read_byte()` / `peek_byte()` return `None` on EOF.**  Previously both
   methods returned `0x00` when the sample stream ended, making it
   impossible for callers to distinguish real data from padding.  They now
   return `None`; the T=0 DATA-state header and procedure-byte loops check
   for `None` and exit the current exchange.

3. **Skip turnaround idle bytes before appending.**  The P3=0 and case-4
   ACK "read until SW" paths now mirror the v1.1.5 unexpected-byte fix:
   non-SW bytes (including 0xFF turnaround artifacts) are skipped before
   the status word is appended, rather than being added to the packet.

### v1.1.5 fix: turnaround idle bytes in edge-read path

Samsung phone traces with gated CLK had 5 garbage APDUs (BAD_FCS) in
mid-session mode.  Root cause: two code paths in the edge-read T=0
procedure-byte handler did not skip turnaround idle bytes (0xFF) on the
bidirectional DATA line.

1. **ACK handler (case 2/4):** After reading P3 response bytes, the code
   read 2 raw bytes as SW1 SW2.  For case-3 commands (SELECT with data),
   the terminal sends command data after ACK, then the DATA line idles
   (0xFF) before the card sends SW.  The idle 0xFF was mis-identified as
   SW1.  Fixed by adding a `while` loop that skips non-SW bytes before
   reading SW1.

2. **"Unexpected byte" handler (procedure byte loop):** Non-SW bytes
   (e.g. 0xFF turnaround) were appended to the packet before scanning for
   SW, corrupting the SW position.  Fixed by moving `packet.append(pb)`
   inside the SW1 check so non-SW bytes are skipped.