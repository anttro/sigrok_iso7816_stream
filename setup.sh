#!/bin/bash
# sigrok_iso7816_stream setup: verify sigrok-cli and register the decoder.
set -euo pipefail

DRAIN_TEST=""
case "${1:-}" in
    --drain-test) DRAIN_TEST="force" ;;
    --help|-h)
        echo "Usage: $0 [--drain-test]"
        echo "  --drain-test  run the long CPU drain test without prompting"
        exit 0
        ;;
    "")
        ;;
    *)
        echo "Unknown option: $1 (see --help)" >&2
        exit 1
        ;;
esac

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
DECODERS_DIR="${HOME}/.local/share/libsigrokdecode/decoders"
LINK="${DECODERS_DIR}/iso7816"
FIRMWARE_DIRS=(
    /usr/share/sigrok-firmware
    /usr/share/sigrok/firmware
    /usr/local/share/sigrok-firmware
)

printf 'Checking sigrok-cli... '
if ! command -v sigrok-cli >/dev/null 2>&1; then
    echo "NOT FOUND"
    echo "  Install it first, e.g.: sudo apt install sigrok-cli"
    exit 1
fi
echo "found ($(command -v sigrok-cli))"
sigrok-cli --version 2>/dev/null | sed 's/^/  /'

printf 'Checking FX2 firmware... '
FW_FOUND=""
for dir in "${FIRMWARE_DIRS[@]}"; do
    if compgen -G "${dir}/fx2lafw-*.fw" >/dev/null; then
        FW_FOUND="${dir}"
        break
    fi
done
if [ -z "${FW_FOUND}" ]; then
    echo "NOT FOUND"
    echo "  fx2lafw firmware files are missing."
    echo "  Arch/CachyOS: sudo pacman -S sigrok-firmware-fx2lafw"
    echo "  Debian/Ubuntu: sudo apt install sigrok-firmware-fx2lafw"
    exit 1
fi
echo "ok (${FW_FOUND})"

printf 'Checking decoder directory... '
mkdir -p "${DECODERS_DIR}"
echo "ok (${DECODERS_DIR})"

printf 'Installing decoder symlink... '
if [ -L "${LINK}" ]; then
    rm "${LINK}"
elif [ -e "${LINK}" ]; then
    echo ""
    echo "  ${LINK} exists and is not a symlink; refusing to overwrite." >&2
    exit 1
fi
ln -s "${REPO_DIR}" "${LINK}"
echo "ok"

printf 'Verifying... '
target="$(readlink -f "${LINK}")"
if [ "${target}" = "${REPO_DIR}" ] && [ -f "${target}/pd.py" ]; then
    echo "ok (${LINK} -> ${target})"
else
    echo "FAILED" >&2
    exit 1
fi

printf 'Probing hardware max samplerate... '
MAX_RATE=""
DEVICE_MSG=""
for rate in 1M 2M 4M 8M 12M 16M 20M 24M; do
    result="$(sigrok-cli -d fx2lafw --config "samplerate=${rate}" --continuous \
        --time 20 -P 'iso7816:clk=D0:data=D1' 2>&1 || true)"
    if echo "${result}" | grep -q "Unable to claim"; then
        DEVICE_MSG="blocked (another program holds the device; stop it and re-run)"
        break
    fi
    if echo "${result}" | grep -q "Failed to open device\|No devices found"; then
        DEVICE_MSG="skipped (no FX2 device connected)"
        break
    fi
    if ! echo "${result}" | grep -qE "invalid argument|Unable to sample|Could not start"; then
        MAX_RATE="${rate}"
    fi
done

if [ -n "${DEVICE_MSG}" ]; then
    echo "${DEVICE_MSG}"
elif [ -n "${MAX_RATE}" ]; then
    echo "${MAX_RATE}"
    if [ "${MAX_RATE}" != "24M" ]; then
        echo "  Device rejects rates above ${MAX_RATE}. Rates up to 24 MHz need"
        echo "  8-bit sampling: only channels D0-D7 may be enabled (enabling"
        echo "  A0/analog forces 16-bit collection, capped at 12 MHz)."
        echo "  start.sh restricts channels accordingly."
    fi
else
    echo "unknown (device present but no rate accepted)"
fi

# --- optional long-duration CPU drain test -------------------------------
# The probe above only checks whether the *device* accepts a rate.  On a slow
# host the FX2 FIFO overflows and the device stops on its own a few seconds in,
# even though the rate was accepted.  Ask before running: on a known-fast
# machine it is wasted time.  Each candidate runs up to DRAIN_DURATION_MS; an
# early stop means the host cannot drain that rate.
DRAIN_DURATION_MS=15000
CANDIDATES_MHZ="24 20 16 12 8 4 2 1"
CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/sigrok_iso7816_stream"
CONFIG_FILE="${CONFIG_DIR}/samplerate"

drain_survives() {  # $1 = rate string ("16M"), $2 = budget ms
    local rate="$1" budget_ms="$2" start_ms elapsed_ms
    start_ms="$(date +%s%3N)"
    sigrok-cli -d fx2lafw --config "samplerate=${rate}" --continuous \
        --time "${budget_ms}" -P 'iso7816:clk=D0:data=D1' >/dev/null 2>&1 || true
    elapsed_ms="$(( $(date +%s%3N) - start_ms ))"
    [ "${elapsed_ms}" -ge $(( budget_ms * 70 / 100 )) ]
}

if [ -n "${MAX_RATE}" ] && [ -z "${DEVICE_MSG}" ]; then
    if [ "${DRAIN_TEST}" != "force" ]; then
        printf '\nRun a long CPU drain test to find the highest *sustainable* rate?\n'
        printf '  (skip on known-fast machines; ~15s per rate on slow ones) [y/N] '
        read -r ans || true
        case "${ans}" in
            [Yy]*) DRAIN_TEST="yes" ;;
            *)     DRAIN_TEST="no" ;;
        esac
    fi
    if [ "${DRAIN_TEST}" = "yes" ] || [ "${DRAIN_TEST}" = "force" ]; then
        MAX_MHZ="${MAX_RATE%M}"
        SUSTAINABLE=""
        echo "Drain test (an early stop means the host cannot keep up):"
        for mhz in ${CANDIDATES_MHZ}; do
            [ "${mhz}" -le "${MAX_MHZ}" ] || continue
            printf '  %sM ... ' "${mhz}"
            if drain_survives "${mhz}M" "${DRAIN_DURATION_MS}"; then
                echo "sustained"
                SUSTAINABLE="${mhz}"
                break
            fi
            echo "stopped early"
        done
        if [ -n "${SUSTAINABLE}" ]; then
            echo "Highest sustainable rate: ${SUSTAINABLE}M"
            if [ "${SUSTAINABLE}" -lt 16 ]; then
                printf 'This host cannot sustain the 16M default. Write a config\n'
                printf '  pinning %sM in %s? [y/N] ' "${SUSTAINABLE}" "${CONFIG_FILE}"
                read -r ans || true
                case "${ans}" in
                    [Yy]*)
                        mkdir -p "${CONFIG_DIR}"
                        printf '%sM\n' "${SUSTAINABLE}" > "${CONFIG_FILE}"
                        echo "Wrote ${CONFIG_FILE}; start.sh will use ${SUSTAINABLE}M."
                        ;;
                    *)
                        echo "Config not written; start.sh will keep trying 16M here."
                        echo "  Per-run override: ./start.sh --samplerate=${SUSTAINABLE}M"
                        ;;
                esac
            fi
        else
            echo "No rate survived ${DRAIN_DURATION_MS} ms - device or host problem."
        fi
    fi
fi

echo "Done. Run ./start.sh to begin capture."
