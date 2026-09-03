#!/bin/bash
# Capture baseline measurements for all traces in both modes.
# Usage: ./tools/capture_baseline.sh > tests/baseline.txt
# Compare with: diff tests/baseline.txt <(./tools/capture_baseline.sh)

set -e
cd "$(dirname "$0")/.."

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

echo "=== Baseline captured $(date -Iseconds) ==="
echo ""

# test_8
run_test "test_8 ATR-included" sigrok-cli -i examples/test_8_raw16.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "test_8 mid-session" sigrok-cli -i examples/test_8_raw16.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# test_7
run_test "test_7 ATR-included" sigrok-cli -i examples/test_7_raw16.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "test_7 mid-session" sigrok-cli -i examples/test_7_raw16.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# phone_reference
run_test "phone_reference ATR-included" timeout 30 sigrok-cli -i examples/phone_reference_live_16M.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "phone_reference mid-session" timeout 30 sigrok-cli -i examples/phone_reference_live_16M.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# samsung_phone_sample
run_test "samsung_phone_sample ATR-included" timeout 30 sigrok-cli -i examples/samsung_phone_sample.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "samsung_phone_sample mid-session" timeout 30 sigrok-cli -i examples/samsung_phone_sample.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# samsung_phone2_sample
run_test "samsung_phone2_sample ATR-included" timeout 30 sigrok-cli -i examples/samsung_phone2_sample.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "samsung_phone2_sample mid-session" timeout 30 sigrok-cli -i examples/samsung_phone2_sample.sr -P iso7816:clk=D1:data=D6:rst=D0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# sunrise_phone_sample
run_test "sunrise_phone_sample ATR-included" timeout 30 sigrok-cli -i examples/sunrise_phone_sample.sr -P iso7816:clk=D0:data=D1:clock_option=native:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "sunrise_phone_sample mid-session" timeout 30 sigrok-cli -i examples/sunrise_phone_sample.sr -P iso7816:clk=D0:data=D1:clock_option=native:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# sim_turnon
run_test "sim_turnon ATR-included" timeout 60 sigrok-cli -i examples/sim_turnon_2_clicking_around_ds.sr -P iso7816:clk=1:data=0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=true:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816
run_test "sim_turnon mid-session" timeout 60 sigrok-cli -i examples/sim_turnon_2_clicking_around_ds.sr -P iso7816:clk=1:data=0:clock_option=native:rst_detect=true:protocol=T=0:starts_with_atr=false:gsmtap_enable=false:pcap_file=/tmp/out.pcap -A iso7816

# unit tests
echo "=== unit tests ==="
python3 tests/test_gsmtap.py -v 2>&1
