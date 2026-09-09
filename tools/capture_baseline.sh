#!/bin/bash
# Capture baseline measurements for all traces in mid-session mode.
# Usage: ./tools/capture_baseline.sh > tests/baseline.txt
# Compare with: diff tests/baseline.txt <(./tools/capture_baseline.sh)

set -e
cd "$(dirname "$0")/.."

# Clear stale bytecode cache — prevents false results from old code.
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

run_test() {
    local label="$1"
    shift
    echo "=== $label ==="
    # Run decoder, capture stderr too
    local output
    output=$("$@" 2>&1) || true
    # Extract key metrics
    echo "$output" | grep -E "iso7816 decoder v|etu recovered|ENDATR|CHKSUM ERROR|INVALID Procedure|desynced APDU|CONCAT APDU|warm reset|Invalid TS|No valid TS|RST low at start|RST deasserted|expecting cold-boot" | head -20
    # CHKSUM errors are a key degradation signal.
    chksum_count=$(echo "$output" | grep -c "CHKSUM ERROR" || true)
    echo "CHKSUM ERROR count: $chksum_count"
    # CONCAT: packets with embedded exchanges (mis-frame swallowed several
    # real exchanges into one "valid" APDU).  Must stay 0 for clean traces.
    # grep the log form (with ':'), not the annotation text, so each packet
    # is counted once.
    concat_count=$(echo "$output" | grep -c "CONCAT APDU:" || true)
    echo "CONCAT APDU count: $concat_count"
    # Check for vs_reader results if pcap exists
    if [ -f /tmp/out.pcap ]; then
        local reader_log=""
        case "$label" in
            test_8*) reader_log="examples/test_8_reader.log" ;;
            test_7*) reader_log="examples/test_7_reader.log" ;;
        esac
        if [ -n "$reader_log" ] && [ -f "$reader_log" ]; then
            python3 tools/vs_reader.py "$reader_log" /tmp/out.pcap 2>&1 || true
        else
            # No ground-truth reader log; run pcap-only analysis to surface
            # BAD_FCS / suspicious CLA / payload issues.
            python3 tools/vs_reader.py --pcap-only /tmp/out.pcap 2>&1 || true
        fi
    fi
    echo ""
}

# Signal diagnostic: extract key metrics from .sr trace
signal_diag() {
    local sr_file="$1"
    local clk="$2"
    local data="$3"
    local rst_opt=""
    local vcc_opt=""
    [ -n "$4" ] && rst_opt="--rst $4"
    [ -n "$5" ] && vcc_opt="--vcc $5"
    python3 tools/signal_diagnostic.py "$sr_file" --clk "$clk" --data "$data" $rst_opt $vcc_opt 2>&1 \
        | grep -E 'Frequency|Period|Rising|Transitions|First activity|stable|noisy' | head -10
}

echo "=== Baseline captured $(date -Iseconds) ==="
echo ""

# test_8
run_test "test_8" sigrok-cli -i examples/test_8_raw16.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# test_7
run_test "test_7" sigrok-cli -i examples/test_7_raw16.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# xiaomi_phone_sample
run_test "xiaomi_phone_sample" timeout 30 sigrok-cli -i examples/xiaomi_phone_sample.sr -P iso7816:clk=CLK:data=DATA:rst=RST:clock_option=native:protocol=T=0:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# xiaomi_mi_a1_coldboot_sample — capture starts BEFORE power-up (VCC low at t=0).
# Regression fixture: must arm the ATR hunt when RST is still low at start
# and start decoding the ATR once the card wakes up.
run_test "xiaomi_mi_a1_coldboot" timeout 300 sigrok-cli -i examples/xiaomi_mi_a1_coldboot_sample.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# 4gmodem_coldboot_sample — same pre-power-up capture shape, modem SIM.
run_test "4gmodem_coldboot" timeout 300 sigrok-cli -i examples/4gmodem_coldboot_sample.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# samsung_A55_coldboot_new_cable — Samsung A55 with the new short cable
# (30 mm wires, external pull resistors GND->VCC and VCC->DATA), named
# channels DATA/VCC/RST/CLK on bits 0/2/4/5.
run_test "samsung_A55_coldboot_new_cable" timeout 300 sigrok-cli -i examples/samsung_A55_coldboot_new_cable.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# samsung_A55_coldboot_new_cable_sim2 — A55 SIM slot 2, same cable; trace
# cropped to the power-on window (~21 s of pre-power idle removed).
run_test "samsung_A55_coldboot_new_cable_sim2" timeout 300 sigrok-cli -i examples/samsung_A55_coldboot_new_cable_sim2.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# samsung_S21p_coldboot_new_cable — Samsung S21+ with the new short cable.
run_test "samsung_S21p_coldboot_new_cable" timeout 300 sigrok-cli -i examples/samsung_S21p_coldboot_new_cable.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# samsung_S21p_coldboot_new_cable_sim2 — S21+ SIM slot 2, same cable; trace
# cropped to the power-on window (~17 s of pre-power idle removed).
run_test "samsung_S21p_coldboot_new_cable_sim2" timeout 300 sigrok-cli -i examples/samsung_S21p_coldboot_new_cable_sim2.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:rst_detect=true:vcc_detect=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# signal diagnostics
echo "=== signal diagnostics ==="
echo "--- test_8 ---"
signal_diag examples/test_8_raw16.sr CLK DATA RST VCC
echo "--- test_7 ---"
signal_diag examples/test_7_raw16.sr CLK DATA RST VCC
echo "--- xiaomi_phone_sample ---"
signal_diag examples/xiaomi_phone_sample.sr CLK DATA RST
echo "--- samsung_A55_coldboot_new_cable ---"
signal_diag examples/samsung_A55_coldboot_new_cable.sr CLK DATA RST VCC
echo "--- samsung_S21p_coldboot_new_cable ---"
signal_diag examples/samsung_S21p_coldboot_new_cable.sr CLK DATA RST VCC

# unit tests
echo "=== unit tests ==="
python3 tests/test_gsmtap.py -v 2>&1
