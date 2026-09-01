#!/bin/bash
# sigrok_iso7816_stream setup: verify sigrok-cli and register the decoder.
set -euo pipefail

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

echo "Done. Run ./start.sh to begin capture."
