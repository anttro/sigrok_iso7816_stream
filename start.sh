#!/bin/bash
# sigrok_iso7816_stream launcher: capture ISO 7816 and stream GSMTAP to :4729.
set -euo pipefail

CLK=D1
DATA=D6
RST=D0
VCC=D4
SAMPLERATE=16M
CLOCK=native
HOST=127.0.0.1
PORT=4729
PCAP=""
DEBUG=""
LOG=""
KLOG=""
LOOP=0              # --loop: restart on rc=0 (device stopped streaming)
MAX_RESTARTS=20     # --max-restarts=N (0 = unlimited)
RESTART_DELAY=2     # --restart-delay=S seconds between restarts
PROTOCOL="T=0"      # --protocol: T=0 (default; live phone captures start
                     #   mid-session, so we recover the ETU from the live line
                     #   and frame full command+response APDU exchanges), T=1,
                     #   or auto
STARTS_WITH_ATR=false # --starts-with-atr: false (live mid-session capture) or
                     #   true (capture begins with an ATR)
# Records which channel pins the user explicitly named via --clk/--data/
# --rst/--vcc.  When ANY of these is given, defaults are NOT injected for the
# remaining channels (a default RST/VCC pin could clash with a user pin), so
# only the named channels are used.  --no-rst/--no-vcc are toggles and do not
# trigger this (they keep the other defaults).
CLK_SET=""; DATA_SET=""; RST_SET=""; VCC_SET=""

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --clk=CH          CLK channel        (default: ${CLK})
  --data=CH         I/O channel        (default: ${DATA})
  --rst=CH          RST channel        (default: ${RST})
  --vcc=CH          VCC channel        (default: ${VCC})
  Note: naming any of --clk/--data/--rst/--vcc disables the other channels'
  defaults -- only the channels you name are used (no injected pins to clash).
  Use --no-rst/--no-vcc to drop RST/VCC while keeping the remaining defaults.
  --samplerate=SR   Sample rate (default: ${SAMPLERATE}).  Override to
                    24M if you need the extra timing headroom; 16M is the
                    FX2's comfortable sustained USB rate.
  --clock=MODE      clock_option       (default: ${CLOCK})
                    native         spec timing, counts CLK edges; wants
                                   ~2+ samples per CLK period
                    detect         measures cycles/bit from the ATR;
                                   upstream calls it "most stable"
                    sample_as_clock experimental
  --host=IP         GSMTAP destination (default: ${HOST})
  --port=N          GSMTAP port        (default: ${PORT})
  --pcap=FILE       Also write decoded events to FILE (offline analysis)
  --debug           Verbose libsigrokdecode logging (-l 4)
  --log=FILE        Tee all output into FILE (postmortem / exit diagnosis)
  --klog[=FILE]     Also record the kernel journal (journalctl -kf) to
                    FILE (default: klog.log) -- needs journal read
                    permission; captures xHCI/USB errors at exit moments.
  --no-rst          Disable RST tracking
  --no-vcc          Disable VCC tracking
  --protocol=MODE   ISO 7816 protocol for mid-session decode: T=0 (default),
                    T=1, or auto.  Live phone captures start mid-session, so a
                    fixed protocol lets the decoder emit raw bursts instead of
                    hunting for a (non-existent) ATR.
  --starts-with-atr=BOOL  true if the capture begins with an ATR (default: false,
                    for live mid-session captures).
  --loop            Auto-restart when the capture ends on its own (rc=0, device
                    stopped streaming).  Loops until you press Ctrl+C (rc=130)
                    or a real error.  Useful for a flaky FX2 that drops the USB
                    transfer mid-session.
  --max-restarts=N  Cap --loop restarts (default: 20; 0 = unlimited).
  --restart-delay=S Seconds to wait between restarts (default: 2).
  -h, --help        Show this help

GSMTAP stream defaults to 127.0.0.1:4729 (simtrace2-pysniff compatible).

Capture runs continuously until Ctrl+C.  stdin is detached from sigrok-cli
so pressing keys/Enter in the terminal does NOT stop the capture (sigrok's
"press any key to stop acquisition" prompt is disabled).

NOTE: clock_option=native counts CLK edges, so the samplerate must stay
above ~2 samples per CLK period (>= 8 MHz for a 3.579 MHz card clock).
Sustained 12 MHz capture can overrun FX2 USB buffers -> dropped sample
chunks appear as torn/fragmented packets; lower rates reduce that risk.
EOF
    exit 0
}

norm_proto() {
    # Normalize a --protocol value to the decoder's accepted form (T=0 / T=1 / auto).
    case "$1" in
        T=0|T0|t0) echo "T=0" ;;
        T=1|T1|t1) echo "T=1" ;;
        auto|AUTO) echo "auto" ;;
        *)         echo "auto" ;;
    esac
}

for arg in "$@"; do
    case "${arg}" in
        --clk=*)         CLK="${arg#*=}"; CLK_SET=1 ;;
        --data=*)        DATA="${arg#*=}"; DATA_SET=1 ;;
        --rst=*)         RST="${arg#*=}"; RST_SET=1 ;;
        --vcc=*)         VCC="${arg#*=}"; VCC_SET=1 ;;
        --samplerate=*)  SAMPLERATE="${arg#*=}" ;;
        --clock=*)       CLOCK="${arg#*=}" ;;
        --host=*)        HOST="${arg#*=}" ;;
        --port=*)        PORT="${arg#*=}" ;;
        --pcap=*)        PCAP="${arg#*=}" ;;
        --debug)         DEBUG=1 ;;
        --log=*)         LOG="${arg#*=}" ;;
        --klog)          KLOG="klog.log" ;;
        --klog=*)        KLOG="${arg#*=}" ;;
        --no-rst)        RST="" ;;
        --no-vcc)        VCC="" ;;
        --protocol=*)    PROTOCOL="$(norm_proto "${arg#*=}")" ;;
        --starts-with-atr=*) STARTS_WITH_ATR="${arg#*=}" ;;
        --loop)          LOOP=1 ;;
        --max-restarts=*) MAX_RESTARTS="${arg#*=}" ;;
        --restart-delay=*) RESTART_DELAY="${arg#*=}" ;;
        -h|--help)       usage ;;
        *) echo "Unknown option: ${arg} (see --help)" >&2; exit 1 ;;
    esac
done

# If the user named any channel pin, do NOT inject defaults for the channels
# they didn't name -- a default RST/VCC pin (D0/D4) can clash with a user
# pin (e.g. --data=D4), and the decoder should only use the named channels.
if [ -n "${CLK_SET}${DATA_SET}${RST_SET}${VCC_SET}" ]; then
    [ -z "${CLK_SET}" ]  && CLK=""
    [ -z "${DATA_SET}" ] && DATA=""
    [ -z "${RST_SET}" ]  && RST=""
    [ -z "${VCC_SET}" ]  && VCC=""
fi

LINK="${HOME}/.local/share/libsigrokdecode/decoders/iso7816"
if [ ! -e "${LINK}/pd.py" ]; then
    echo "Decoder not installed (${LINK} missing or broken)." >&2
    echo "Run ./setup.sh first." >&2
    exit 1
fi

# Preflight: confirm the FX2 device is present and that every channel we
# are about to assign actually exists on it.  A wrong/missing channel name
# would otherwise surface later as a confusing "device stopped streaming"
# (rc=0) or a sigrok-cli abort; fail loudly here instead.
SHOW_OUT="$(sigrok-cli -d fx2lafw --show 2>&1)" || SHOW_OUT=""
if ! echo "${SHOW_OUT}" | grep -q 'channels:'; then
    echo "ERROR: FX2 device not found or firmware not loaded." >&2
    echo "Connect the analyzer and run ./setup.sh (installs sigrok-firmware-fx2lafw)." >&2
    exit 1
fi
DEV_CHANS="$(echo "${SHOW_OUT}" | grep -oP 'channels: \K.*' | tr -s ' ')"
validate_chan() {
    # $1 = role (clk/data/rst/vcc), $2 = channel name
    if [ -z "$2" ]; then
        echo "ERROR: '$1' channel is empty. Use --$1=CH (e.g. --$1=D1)." >&2
        exit 1
    fi
    if ! echo " ${DEV_CHANS} " | grep -qw "$2"; then
        echo "ERROR: channel '$2' ($1) is not valid on this device." >&2
        echo "Available channels: ${DEV_CHANS}" >&2
        exit 1
    fi
}
validate_chan clk "${CLK}"
validate_chan data "${DATA}"
[ -n "${RST}" ] && validate_chan rst "${RST}"
[ -n "${VCC}" ] && validate_chan vcc "${VCC}"

# A physical channel can carry only one signal.  Assigning the same channel
# to two decoder inputs (e.g. --clk=D0 with the default --rst=D0) makes the
# decoder hang/burst after the ATR, because the shared pin drives both sample
# reads and line-event detection at once.  Reject that before launching.
check_dup() {
    # $1 = role A, $2 = value A, $3 = role B, $4 = value B
    [ -z "$2" ] || [ -z "$4" ] && return 0
    if [ "$2" = "$4" ]; then
        echo "ERROR: '$1' and '$3' are both assigned to channel '$2'." >&2
        echo "A channel cannot carry two signals at once. Use --no-$3 or set" >&2
        echo "--$3 to a different pin (see the pinout in the README)." >&2
        exit 1
    fi
}
check_dup clk  "${CLK}"  rst  "${RST}"
check_dup clk  "${CLK}"  vcc  "${VCC}"
check_dup data "${DATA}" rst  "${RST}"
check_dup data "${DATA}" vcc  "${VCC}"

echo "Channels: clk=${CLK} data=${DATA}${RST:+ rst=${RST}}${VCC:+ vcc=${VCC}}"

OPTS="clk=${CLK}:data=${DATA}:clock_option=${CLOCK}"
OPTS+=":gsmtap_host=${HOST}:gsmtap_port=${PORT}"
[ -n "${RST}" ] && OPTS+=":rst=${RST}:rst_detect=true"
[ -n "${VCC}" ] && OPTS+=":vcc=${VCC}:vcc_detect=true"
OPTS+=":starts_with_atr=${STARTS_WITH_ATR}:protocol=${PROTOCOL}"

echo "ISO 7816 streamer — clk=${CLK} data=${DATA}${RST:+ rst=${RST}}${VCC:+ vcc=${VCC}} clock=${CLOCK}"
echo "Protocol: ${PROTOCOL} | starts_with_atr=${STARTS_WITH_ATR}"
echo "Samplerate: ${SAMPLERATE} | GSMTAP -> ${HOST}:${PORT}${PCAP:+ | pcap: ${PCAP}}${LOG:+ | log: ${LOG}}"
echo "Capture runs until you press Ctrl+C (stdin is detached, so keypresses"
echo "do NOT stop it)."
echo ""

if [ -n "${LOG}" ]; then
    exec > >(tee "${LOG}") 2>&1
fi

KLOG_PID=""
if [ -n "${KLOG}" ]; then
    if journalctl -kf > "${KLOG}" 2>/dev/null &
    then
        KLOG_PID=$!
        echo "Kernel journal -> ${KLOG} (pid ${KLOG_PID})"
    else
        echo "journalctl -kf unavailable (permissions?); kernel log disabled" >&2
        KLOG_PID=""
    fi
fi
cleanup() {
    [ -n "${KLOG_PID}" ] && kill "${KLOG_PID}" 2>/dev/null || true
    [ -n "${ANNOT_TMP}" ] && rm -f "${ANNOT_TMP}" 2>/dev/null || true
    [ -n "${FIFO_PID}" ] && kill "${FIFO_PID}" 2>/dev/null || true
    [ -n "${FIFO}" ] && rm -f "${FIFO}" 2>/dev/null || true
}
trap cleanup EXIT

ANNOT_TMP="$(mktemp -t iso7816_annot.XXXXXX)" || ANNOT_TMP=""
FIFO=""
FIFO_PID=""

run_once() {
    # $1 = samplerate, $2 = pcap file for this session (may be empty)
    local rate="$1"
    local pcap_opt=""
    [ -n "$2" ] && pcap_opt=":pcap_file=$2"
    # Blocking, keypress-free stdin: sigrok-cli's "press any key to stop"
    # waits on stdin.  /dev/null EOFs instantly and stops the capture (the
    # bug introduced when detaching stdin), and a real keypress would too.
    # A background `sleep` holds the pipe open without ever sending a byte,
    # so the capture runs until the genuine SIGINT (Ctrl+C).  We track and
    # reap the sleep via a FIFO.
    FIFO="$(mktemp -u -t iso7816_fifo.XXXXXX)"
    mkfifo "${FIFO}"
    sleep 1000000 > "${FIFO}" &
    FIFO_PID=$!
    sigrok-cli -d fx2lafw \
        --config samplerate="${rate}" \
        --continuous \
        -C 'D0,D1,D2,D3,D4,D5,D6,D7' \
        ${DEBUG:+-l 4} \
        -P "iso7816:${OPTS}${pcap_opt}" \
        -A iso7816 < "${FIFO}" | tee "${ANNOT_TMP}"
    local rc=${PIPESTATUS[0]}
    kill "${FIFO_PID}" 2>/dev/null || true
    rm -f "${FIFO}" 2>/dev/null || true
    return "${rc}"
}

report_exit() {
    # $1 = session number, $2 = exit code
    case "$2" in
        0)   reason="capture ended (device stopped streaming on its own)" ;;
        130) reason="SIGINT (Ctrl+C)" ;;
        137) reason="SIGKILL (OOM?)" ;;
        141) reason="SIGPIPE" ;;
        *)   reason="error" ;;
    esac
    echo "=== session #$1 ended rc=$2: $reason ($(date +%T))"

    # rc=0 means the device itself stopped streaming -- this is distinct
    # from an idle line, which with --continuous would keep running until
    # Ctrl+C (rc=130).  An idle capture (started before the card is
    # powered) is completely normal and must not be treated as a failure.
    if [ "$2" -eq 0 ]; then
        local n=0
        [ -n "${ANNOT_TMP}" ] && [ -f "${ANNOT_TMP}" ] \
            && n=$(wc -l < "${ANNOT_TMP}" 2>/dev/null || echo 0)
        if [ "$n" -eq 0 ]; then
            echo "NOTE: decoded 0 events. An idle line is normal (e.g. capture" >&2
            echo "started before the SIM was powered). The device stopping on" >&2
            echo "its own (rc=0) is a device-level issue, not an idle line:" >&2
            echo "  - FX2 unplugged / lost USB connection mid-capture" >&2
            echo "  - fx2lafw firmware hiccup" >&2
            echo "  - USB bandwidth ceiling (try a lower --samplerate)" >&2
        else
            echo "Decoded ${n} events before the device stopped." >&2
        fi
    fi
}

set +e
if [ "${LOOP}" -eq 1 ]; then
    tries=0
    while true; do
        tries=$((tries + 1))
        run_once "${SAMPLERATE}" "${PCAP}"
        rc=$?
        report_exit "${tries}" "$rc"
        # A non-zero rc means a genuine stop: Ctrl+C (130) or an error.
        # Only rc=0 (device stopped streaming on its own) triggers a restart.
        if [ "$rc" -ne 0 ]; then
            break
        fi
        if [ "${MAX_RESTARTS}" -gt 0 ] && [ "${tries}" -ge "${MAX_RESTARTS}" ]; then
            echo "Reached max restarts (${MAX_RESTARTS}); stopping." >&2
            break
        fi
        echo "Device stopped (rc=0); restarting in ${RESTART_DELAY}s ..." >&2
        sleep "${RESTART_DELAY}"
    done
    exit "$rc"
else
    run_once "${SAMPLERATE}" "${PCAP}"
    rc=$?
    report_exit "single" "$rc"
    exit "$rc"
fi
