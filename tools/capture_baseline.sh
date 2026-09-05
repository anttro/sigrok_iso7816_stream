#!/bin/bash
# Capture baseline measurements for all traces in both modes.
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
    echo "$output" | grep -E "iso7816 decoder v|etu recovered|ENDATR|CHKSUM ERROR|INVALID Procedure|desynced APDU|warm reset|Invalid TS|No valid TS" | head -20
    # CHKSUM errors are a key degradation signal.
    chksum_count=$(echo "$output" | grep -c "CHKSUM ERROR" || true)
    echo "CHKSUM ERROR count: $chksum_count"
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
run_test "test_8 ATR-included" sigrok-cli -i examples/test_8_raw16.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "test_8 mid-session" sigrok-cli -i examples/test_8_raw16.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# test_7
run_test "test_7 ATR-included" sigrok-cli -i examples/test_7_raw16.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "test_7 mid-session" sigrok-cli -i examples/test_7_raw16.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# xiaomi_phone_sample
run_test "xiaomi_phone_sample ATR-included" timeout 30 sigrok-cli -i examples/xiaomi_phone_sample.sr -P iso7816:clk=CLK:data=DATA:rst=RST:clock_option=native:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "xiaomi_phone_sample mid-session" timeout 30 sigrok-cli -i examples/xiaomi_phone_sample.sr -P iso7816:clk=CLK:data=DATA:rst=RST:clock_option=native:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# samsung_phone_sample
run_test "samsung_phone_sample ATR-included" timeout 30 sigrok-cli -i examples/samsung_phone_sample.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "samsung_phone_sample mid-session" timeout 30 sigrok-cli -i examples/samsung_phone_sample.sr -P iso7816:clk=CLK:data=DATA:rst=RST:vcc=VCC:clock_option=native:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# signal diagnostics
echo "=== signal diagnostics ==="
echo "--- test_8 ---"
signal_diag examples/test_8_raw16.sr CLK DATA RST VCC
echo "--- test_7 ---"
signal_diag examples/test_7_raw16.sr CLK DATA RST VCC
echo "--- xiaomi_phone_sample ---"
signal_diag examples/xiaomi_phone_sample.sr CLK DATA RST
echo "--- samsung_phone_sample ---"
signal_diag examples/samsung_phone_sample.sr CLK DATA RST VCC

# unit tests
echo "=== unit tests ==="
python3 tests/test_gsmtap.py -v 2>&1
