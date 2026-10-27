# sigrok_iso7816_stream

📢 Project news and updates: [Website](https://atroshin.ru) · [Telegram channel](https://t.me/youeyeseesee)

Fork of [svenso/sigrok_iso7816](https://github.com/svenso/sigrok_iso7816) with
**live GSMTAP UDP streaming**, making a cheap FX2 logic analyzer (Saleae clone)
behave like a SIMtrace2 sniffer:

```
SIM card ⇄ reader (passive tap on the contacts)
    → FX2 logic analyzer (fx2lafw, 8ch, 24MHz max)
    → sigrok-cli + iso7816 decoder
    → GSMTAP UDP :4729  →  [SIMtrace Analyser](https://github.com/anttro/simtrace-analyser) / Wireshark
```

[SIMtrace Analyser](https://github.com/anttro/simtrace-analyser) is the
recommended tool for visualising live traces and viewing saved captures —
it can also import/export GSMTAP pcap files (including the PCAP written by
this decoder's `pcap_file=<path>` option).

## Install and start

Both ways install the same decoder — pick one:

- **Download (recommended)** — a release archive.  Nothing to clone and no git
  history: extract it, run `setup`, then `start`.  Best if you only want to
  capture.
- **Source checkout** — a `git clone`.  The same runtime plus the development
  material: `tests/` and the trace/baseline tools (`tools/capture_baseline.sh`,
  `tools/compare_baseline.sh`, `tools/vs_reader.py`).  Example traces
  (`examples/`) are gitignored and stay local in either case.  Release archives
  do not contain `tests/`, the dev tools or `examples/`.

### Download (recommended)

Grab the latest archive from
[Releases](https://github.com/anttro/sigrok_iso7816_stream/releases/latest):

- `sigrok_iso7816_stream-<version>.tar.gz` — Linux
- `sigrok_iso7816_stream-<version>.zip` — Windows

Each release also publishes `SHA256SUMS`, which lists **both** archives; keep
it next to the file you downloaded and verify:

```bash
sha256sum -c --ignore-missing SHA256SUMS   # GNU coreutils (Linux)
```

On Windows run `certutil -hashfile sigrok_iso7816_stream-<version>.zip SHA256`
and compare the output with the `.zip` line in `SHA256SUMS`.

#### Linux (download)

```bash
tar xzf sigrok_iso7816_stream-<version>.tar.gz
cd sigrok_iso7816_stream-<version>
./setup.sh
./start.sh
```

`setup.sh` verifies sigrok-cli and the FX2 firmware package
(`sigrok-firmware-fx2lafw`) are installed, symlinks the project directory into
`~/.local/share/libsigrokdecode/decoders/iso7816` (user-local decoders shadow
system-wide ones), and probes the connected device for its maximum supported
samplerate.

#### Windows (download)

Prerequisites:

1. **sigrok-cli** Windows installer (0.7.2 x86_64) from
   [sigrok.org/wiki/Downloads](https://sigrok.org/wiki/Downloads) — the tested
   release.  Nightly Windows installers are also published on that page; they
   may change the sigrok-cli syntax or the decoder API, so the 0.7.2 release
   installer remains the supported version.
   If sigrok-cli fails to start with error `0xc0150002`, install the
   [Visual C++ 2010 Redistributable](https://www.microsoft.com/en-us/download/details.aspx?id=26999)
   (`msvcr100.dll` is required by the bundled Python runtime).
2. fx2lafw firmware ships bundled with the installer — no separate download.

Driver setup (FX2 dongles need WinUSB, the vendor driver won't work):

- Run **Zadig**, which ships *inside* the sigrok-cli installation directory
  (also reachable from the Start menu). Select the FX2 device in its dropdown
  and install the **WinUSB** driver.
- After firmware upload the device re-enumerates with a different VID/PID —
  if it still isn't found, run Zadig a **second time** for the re-enumerated
  entry.
- Windows binds drivers per USB port when no serial number is present:
  moving the dongle to another port may require repeating Zadig.

Then extract the release `.zip` (right-click → Extract All in Explorer) and
run, inside the extracted folder:

```bat
setup.bat
start.bat
```

`setup.bat` verifies sigrok-cli and bundled firmware, registers this project's
decoder via a junction into `%LOCALAPPDATA%\libsigrokdecode\decoders\iso7816`
(confirmed by `sigrok-cli -L` listing `iso7816`), and probes the device's
accepted samplerates.  The release zip ships the batch files with CRLF line
endings, so no conversion is needed.  `start.bat --help` lists its options
(the core subset of `start.sh`: channels, samplerate, clock, host/port, pcap,
protocol, debug).

### Source checkout

#### Linux (source checkout)

```bash
git clone git@github.com:anttro/sigrok_iso7816_stream.git
cd sigrok_iso7816_stream
./setup.sh
./start.sh
```

`setup.sh` performs the same checks and symlink as above.

#### Windows (source checkout)

The Windows prerequisites (sigrok-cli + the Visual C++ 2010 Redistributable,
the bundled fx2lafw firmware, and the Zadig/WinUSB driver setup) are the same
as in [Windows (download)](#windows-download) above.

```bat
git clone git@github.com:anttro/sigrok_iso7816_stream.git
cd sigrok_iso7816_stream
setup.bat
start.bat
```

`setup.bat` performs the same checks and junction registration as above.
`start.bat` supports the core option subset; the space form is the primary
one, and `--clk=CH` also works (`start.bat --help` lists them):

```bat
start.bat --clk D1 --data D6
```

Note: batch files need CRLF line endings; the repo enforces this via
`.gitattributes`, so a fresh clone on Windows is already correct (the release
zip ships the same CRLF files).

## Usage

`start.sh` captures continuously at 16 MHz until Ctrl+C (`rc=130`) and streams
GSMTAP to 127.0.0.1:4729.  Defaults: pins D5=CLK, D0=I/O, D4=RST, D2=VCC.
Override via args:

```bash
./start.sh --clk=D1 --data=D6          # different wiring
./start.sh --no-rst --no-vcc           # CLK+I/O only
./start.sh --host=10.0.28.7            # stream to a remote analyser
./start.sh --pcap=session.pcap         # also record decoded events to PCAP
./start.sh --debug                     # full decoder + sigrok output (all
                                       # annotation rows + libsigrok -l 4);
                                       # by default only decoded APDUs and
                                       # decoder warnings/errors are shown
```

On Windows, `start.bat` takes the same core options (space form; the
`--opt=value` form also works) — see the Windows install notes above.

### Wiring

The recommended tap is the short cable with external pull resistors (see
*The tap in practice* below): 10 kΩ to GND on VCC (pulls low when off) and
47 kΩ to VCC on DATA (faster rise to high).  Its pin mapping is **fixed and
known in advance** — see the "Pin mapping" table below — and is exactly what
`start.sh` defaults to (`D5`=CLK, `D0`=I/O, `D4`=RST, `D2`=VCC).  No wiring
auto-detection is needed; the pins never move.

> **GND first.** Plug GND first and verify it manually (continuity meter
> or known-good contact) — a missing or loose ground masquerades as every
> other fault at once: floating lines, phantom start bits, all-zero frames.

### Pin mapping

The FX2 clone channels are assigned via `-P iso7816:clk=N:data=N:rst=N:vcc=N`.
The recommended short-cable tap (external pull resistors) uses fixed pins that
are exactly `start.sh`'s defaults; `--clk`/`--data`/`--rst`/`--vcc` remap them
if you wire differently:

| FX2 channel | SIM contact | Signal |
|-------------|-------------|--------|
| D0 | C7 | I/O |
| D2 | C1 | VCC (digital level only!) |
| D4 | C2 | RST |
| D5 | C3 | CLK |
| GND | C5 | GND |

FX2 input threshold is TTL-ish (~1.4V): 1.8V-class cards may read unreliably;
3V/5V classes are fine.

### Clock modes

- `native` (default) — live captures.  The decoder follows the PPS speed
  switch and re-arms on RST, so warm resets and post-PPS traffic decode
  correctly.
- `detect` — for offline experiments or captures without PPS.  It does not
  follow the PPS switch, so post-PPS traffic can be misread.
- `sample_as_clock` — experimental upstream mode; not recommended for SIM
  captures.

### Troubleshooting live capture

**The capture stops early (especially on Windows).** A common cause is the
wrong USB driver. The Saleae Logic driver works only with Saleae Logic
software; sigrok needs the **WinUSB** driver. Install it with **Zadig**
(bundled with the sigrok-cli installer) and repeat the assignment after the
device re-enumerates with the firmware's VID/PID. See the sigrok documentation:

- https://sigrok.org/wiki/Windows#Drivers
- https://sigrok.org/wiki/Fx2lafw

**Device not found / no signal.** Check the WinUSB driver (Windows), the
fx2lafw firmware, the wiring and GND (see Wiring), and try another USB port or
a known-good cable. Cheap USB cables and hubs are common causes of stalls.

**The capture ends by itself (`rc=0`).** The FX2 is at its USB bandwidth limit
at high samplerates. Lower `--samplerate`, avoid hubs, and close other USB
traffic. `start.sh` automatically restarts the capture on `rc=0` (default 20
restarts, 2 s apart; `--no-loop`, `--max-restarts=N`, `--restart-delay=S`).
With `--pcap=FILE`, each restart writes `FILE.<N>.<ext>`.

`start.sh` runs until Ctrl+C; keystrokes do not stop it (the "press any key"
prompt is disabled). Useful options:

```bash
./start.sh --pcap=s.pcap --log=s.log           # record events and the rc= verdict
./start.sh ... --samplerate=24M                # more timing headroom if needed
./start.sh ... --klog                          # also record the kernel journal
./start.sh ... --debug                         # full decoder + sigrok output
```

- `--log` records the session-end `rc=` line.
- The decoder logs `SIGNAL INTEGRITY WARNING` when ≥ 8 of the last 64 frames
  fail parity.
- Desynced packets are kept and flagged `GSMTAP_FLAG_BAD_FCS` in the GSMTAP
  header `res` byte — visible in Wireshark as a BAD-FCS warning.

### Raw sigrok-cli

Equivalent commands without the wrapper scripts:

```bash
# Minimal: CLK+I/O only, live stream to localhost:4729
sigrok-cli -d fx2lafw --config samplerate=12M --continuous \
  -P iso7816:clk=D0:data=D1:clock_option=detect -A iso7816

# Full wiring: CLK + I/O + RST + VCC with line event tracking
sigrok-cli -d fx2lafw --config samplerate=12M --continuous \
  -P iso7816:clk=D5:data=D0:rst=D4:vcc=D2:clock_option=native:rst_detect=true:vcc_detect=true \
  -A iso7816

# Stream to a remote analyser / disable streaming / write PCAP file
... -P iso7816:...:gsmtap_host=10.0.28.7 ...
... -P iso7816:...:gsmtap_enable=false ...
... -P iso7816:...:pcap_file=trace.pcap ...

# Classic upstream mode: binary PCAP to stdout
sigrok-cli -i capture.sr -P iso7816:clk=2:data=0 -B iso7816=pcap > out.pcap
```

## The tap in practice

![Components](resources/components.jpg)
*Components used in the build*

![In action with phone](resources/in_action_phone.jpg)
*The rig tapping a phone SIM session*

![In action](resources/in_action.jpg)
*The rig tapping a card-reader session*

![SIM adapter](resources/sim_adapter.jpg)
*The SIM-tap adapter*

![SIM adapter pinout](resources/sim_adapter_pinout.jpg)
*Tap wiring on the SIM contacts*

![Short cable](resources/short_cable.jpg)
*The short-cable tap — reduces loop area and rise-time artifacts*

![Short cable wiring](resources/short_cable_wiring.jpg)
*Short-cable wiring detail*

![Short cable gear](resources/short_cable_gear.jpg)
*Short cable with the breakout gear*

![Short cable pull resistors](resources/short_cable_pull_resistors.jpg)
*Short cable with external pull resistors — 10 kΩ to GND on VCC (pulls low when off), 47 kΩ to VCC on DATA (faster rise to high)*

## Features

| Feature | Description |
|---------|-------------|
| Live GSMTAP stream | Every decoded event is sent as a GSMTAP-SIM UDP packet (default on, mimics simtrace2-sniff) |
| Correct sub_types | ATR=0x01 and PPS=0x02 are tagged properly in PCAP output |
| ATR/PPS in PCAP | ATR and combined PPS request+response are emitted as PCAP packets |
| RST tracking (optional) | `rst_detect=true`: emits reset assert/deassert events (sub_type 0x10) |
| VCC tracking (optional) | `vcc_detect=true`: emits power on/off events (sub_type 0x11) |
| Direct PCAP file | `pcap_file=<path>` writes PCAP without shell redirection |
| Start-bit deglitch | Suppresses sub-ETU LOW glitches (2 samples at 16 MHz, scaled to the samplerate) |
| Mid-session ETU lock | Recovers the ETU from DATA for captures without a usable CLK; a rate that fails parity is re-measured |
| ATR / resync guards | Validates the ATR, ignores mis-framed ATR candidates, and re-aligns after a desync |
| Inverse convention | Supports direct (TS=0x3B) and inverse (TS=0x3F) cards |
| T=1 blocks | Decodes NAD/PCB/LEN/INF/LRC with M-bit chaining; the I-block INF is emitted as the APDU |
| Parity flag | Packets containing a parity-error byte are flagged `GSMTAP_FLAG_BAD_FCS` |
| Rate-aware thresholds | Deglitch, guard and ETU floors scale with the capture samplerate |

## Decoder options

| Option | Default | Description |
|--------|---------|-------------|
| `clock_option` | `native` | `native`, `detect`, `sample_as_clock` (see upstream FAQ) |
| `protocol` | `auto` | `auto`, `T=0`, `T=1` |
| `gsmtap_enable` | `true` | Live GSMTAP UDP streaming |
| `gsmtap_host` | `127.0.0.1` | GSMTAP destination host |
| `gsmtap_port` | `4729` | GSMTAP destination port |
| `pcap_file` | *(empty)* | Write PCAP to this file in addition to binary output |
| `rst_detect` | `false` | Track RST pin events (requires the `rst` channel to be assigned) |
| `vcc_detect` | `false` | Track VCC pin events (requires the `vcc` channel to be assigned) |

Channels: `clk`, `data` (required); `rst`, `vcc` (optional — assign only when
the corresponding wire is physically connected).

## GSMTAP events

GSMTAP header: version 2, type SIM (0x04), UDP port 4729.

| sub_type | Name | Payload |
|----------|------|---------|
| 0x00 | APDU | raw T=0/T=1 packet bytes |
| 0x01 | ATR | raw ATR bytes |
| 0x02 | PPS request | raw PPS request bytes |
| 0x03 | PPS response | raw PPS response bytes |
| 0x10 | RST event (custom) | `[direction, level, flags, clk_hz_be32]` — CLK frequency appended when known |
| 0x11 | VCC event (custom) | `[direction, level, 0x00]` |

Event payload byte semantics:
- RST: `direction` 1 = reset asserted (high→low), 0 = deasserted (low→high);
  `level` = line level after the transition.
- VCC: `direction` 1 = power applied (low→high), 0 = removed (high→low);
  `level` = line level after the transition.

0x00-0x03 match libosmocore's gsmtap.h: standard values and payloads
(PPS request and response are emitted as separate packets).  0x10/0x11
are custom extensions not defined in libosmocore's gsmtap.h.

RST events carry the measured CLK frequency when it is known: `flags`
bit 0 is then set and the frequency follows as a big-endian uint32 in Hz
(7-byte payload).  When the rate is not yet measured the payload stays
3 bytes, so consumers that read only the first two bytes are unaffected.
Combined with the F/D negotiated in the ATR/PPS, the data rate is
`clk_hz × D / F` bits/s.

Header extensions: flags such as `GSMTAP_FLAG_BAD_FCS` are written into
the header `res` byte, which official gsmtap.h marks reserved (RFU).
This carriage is this decoder's own extension (upstream simtrace2-sniff
never sets `res`); the flag semantics mirror simtrace2's per-message USB
data flags and are not part of the libosmocore spec.

## RST/VCC detection notes and limitations

- Events are detected **asynchronously before the first ATR** (power-on /
  reset release are captured once the level is stable) and **at packet
  boundaries** between T=0/T=1 packets afterwards.
- Edges occurring entirely *within* a packet transfer are observed as a net
  level change at the next boundary; short pulses inside a packet can be missed.
- VCC is digital-only: the decoder sees powered/not-powered, never the
  voltage class (1.8/3/5V).
- **RST and VCC use level-stability hysteresis at 10 ms** (samplerate-scaled):
  a new level is reported only once it has been continuously stable for ≥ 10 ms.
  This makes power-up and power-down symmetric and suppresses ringing and
  short glitches.
- **VCC events are generally unreliable — prefer not to track VCC.** A floating
  or unconnected VCC sense pin reads HIGH at all times (logic-high with no load),
  so the decoder sees "powered" constantly and emits spurious power events on
  every bounce.  Unless your tap derives VCC from a clean, loaded source, it is
  better to **leave the `vcc` channel unassigned** (do not pass `--vcc`) and keep
  `vcc_detect=false`; RST tracking is usually enough to see resets.  Only enable
  VCC tracking on a tap with a solid VCC sense (and a solid GND — see wiring notes).
- Unassigned optional channels are ignored even if `rst_detect`/`vcc_detect`
  is enabled (guarded via `has_channel()`).

## Development and testing

The decoder is validated against example captures with `tools/vs_reader.py`.
Trace fixtures are kept locally and are not part of the repository.

### Validation against the reader SDK (`tools/vs_reader.py`)

On a controlled rig (PC/SC reader driven by software) the reference APDU log
from the reader SDK can be diffed against the decoded PCAP:

```bash
sigrok-cli -i <trace>.sr \
  -P iso7816:clk=D5:data=D0:rst=D4:vcc=D2:clock_option=native:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=out.pcap \
  -A iso7816
python3 tools/vs_reader.py <reader-log>.log out.pcap
```

`vs_reader.py` aligns each reader-log exchange to the capture APDUs
(byte-exact LCS match) and classifies the leftovers as proactive/CAT
(unseen by the reader SDK), pre-capture/dropped, or garbage.

### Cold-boot captures (capture starts before power-up)

When the capture starts before power-up, RST is still low at sample 0.  Use
`rst_detect=true` and `protocol=T=0`; the decoder arms the ATR hunt on the
initial RST level and decodes the full ATR.  Example:

```bash
sigrok-cli -i <coldboot>.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=out.pcap \
  -A iso7816
```

### Capture scenarios: reader (constant CLK) and phone (Clock Stop Mode)

- **Reader / constant-CLK capture** — the reader drives a steady CLK for the
  whole session.  Validate it against the reader SDK with
  `tools/vs_reader.py <reader-log>.log out.pcap`.
- **Phone / gated or stopped-CLK capture** — the phone gates or stops CLK
  between transfers (Clock Stop Mode), so the ETU cannot be derived from CLK.
  Run with `protocol=T=0`; the decoder recovers the ETU from the DATA line and
  decodes with the edge-list reader.  T=0 case 3/4 commands (e.g. `80 12`/`80 14`
  STK envelopes) are consolidated into one command→response APDU.

Recommended invocations:

```bash
# Reader capture (controlled rig, CLK always running)
sigrok-cli -i <trace>.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=out.pcap \
  -A iso7816
python3 tools/vs_reader.py <reader-log>.log out.pcap

# Phone capture (mid-session, gated/stopped CLK)
sigrok-cli -i <phone>.sr \
  -P iso7816:clk=CLK:data=DATA:rst=RST:clock_option=native:rst_detect=true:vcc_detect=false:protocol=T=0:gsmtap_enable=false:pcap_file=out.pcap \
  -A iso7816
```

### Data rates and ETUs

Reference values observed on the example captures at a 16 MHz samplerate:

| Trace | CLK mode | ETU (samples) | CLK/ETU | Convention | Notes |
|-------|----------|---------------|---------|------------|-------|
| test_8 | constant | ~43 | 372 (standard) | Direct | PC/SC reader, ATR+PPS+APDUs |
| test_7 | constant | ~43 | 372 (standard) | Direct | PC/SC reader, warm resets |
| xiaomi | gated/stopped | ~53 | recovered from DATA | Direct | Phone, mid-session |
| samsung | gated/stopped | ~72 | 16 (F=512/D=32) | Direct | Phone, non-standard F/D, STK menu |
| alcor_reader | constant | ~53 | 16 (F=512/D=32) | Direct | PC/SC reader, CLK 4.0 MHz at ATR -> 4.8 MHz after PPS |

The decoder auto-detects the ETU and selects the bit reader (CLK-sync for
constant CLK, edge-list for gated/stopped CLK).  No manual configuration is
needed beyond `clock_option=native` and `protocol=T=0` for phone captures.

Parity is **even** per TS 102 221 ("an even number of bits set to '1'
including the parity bit"); frames failing the check are flagged as
`CHKSUM ERROR` but still decoded.

## License

GPL-2.0+, same as upstream.
