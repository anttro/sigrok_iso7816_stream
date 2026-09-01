#!/bin/bash
# Compare current decoder output against saved baseline.
# Usage: ./tools/compare_baseline.sh
# Prerequisites: tests/baseline.txt exists (run capture_baseline.sh first)

set -e
cd "$(dirname "$0")/.."

BASELINE="tests/baseline.txt"

if [ ! -f "$BASELINE" ]; then
    echo "ERROR: No baseline found at $BASELINE"
    echo "Run ./tools/capture_baseline.sh > tests/baseline.txt first"
    exit 1
fi

# Capture current output
CURRENT=$(mktemp)
trap "rm -f $CURRENT" EXIT
./tools/capture_baseline.sh > "$CURRENT" 2>&1

# Compare
echo "=== Comparing against baseline ==="
echo ""

# Strip timestamps and test execution times before comparing
BASELINE_CLEAN=$(mktemp)
CURRENT_CLEAN=$(mktemp)
trap "rm -f $BASELINE_CLEAN $CURRENT_CLEAN" EXIT

grep -v "^=== Baseline captured" "$BASELINE" | grep -v "^Ran [0-9]* tests in" > "$BASELINE_CLEAN"
grep -v "^=== Baseline captured" "$CURRENT" | grep -v "^Ran [0-9]* tests in" > "$CURRENT_CLEAN"

if diff -u "$BASELINE_CLEAN" "$CURRENT_CLEAN"; then
    echo "IDENTICAL - no changes detected"
    exit 0
else
    echo ""
    echo "DIFFERENCES FOUND - review above"
    echo ""
    echo "Key metrics to check:"
    echo "  - GARBAGE count must be 0 for test_8 (both modes)"
    echo "  - RESULT must be OK for test_8 (both modes)"
    echo "  - ETU values must match for mid-session traces"
    echo "  - No new INVALID Procedure Byte errors"
    exit 1
fi
