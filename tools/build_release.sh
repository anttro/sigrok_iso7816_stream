#!/bin/bash
# Build the GitHub release archives from a git ref.
# Usage: ./tools/build_release.sh [REF]
#
# REF defaults to HEAD.  The archives carry an explicit path allowlist: the
# decoder, the setup/start scripts, tools/vs_reader.py, the two READMEs, the
# license and the images the READMEs reference.  The allowlist is passed to
# `git archive` as its pathspec, so tests/, AGENTS.md, the CI config and the
# development tools never enter the release — and the repository's own
# (auto-generated) source archives are not affected.
#
# A v* tag must match the VERSION line in that ref's pd.py.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

die() { echo "build_release: $*" >&2; exit 1; }

REF="${1:-HEAD}"
git rev-parse --verify "$REF^{commit}" >/dev/null 2>&1 || die "unknown ref: $REF"

VERSION="$(git show "$REF:pd.py" | sed -n "s/^VERSION = '\([0-9][0-9.]*\)'.*/\1/p")"
[ -n "$VERSION" ] || die "cannot read VERSION from $REF:pd.py"

case "$REF" in
    v*)
        [ "${REF#v}" = "$VERSION" ] || \
            die "tag $REF does not match pd.py VERSION '$VERSION'"
        ;;
esac

PREFIX="sigrok_iso7816_stream-${VERSION}"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/sigrok_release.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

# --- expected release contents (allowlist) -------------------------------
# The base runtime files plus every image referenced from the READMEs.
# Each README embeds its own language variant of the pipeline diagram, so the
# two diagrams are added explicitly instead of joining the shared-photo check.
LANG_RES="resources/diagram_en.svg resources/diagram_ru.svg"
README_RES="$(git show "$REF:README.md" \
    | grep -oE '\]\(resources/[^)]+' | sed 's/](//' \
    | grep -v -e '^resources/diagram_en\.svg$' -e '^resources/diagram_ru\.svg$' \
    | LC_ALL=C sort -u || true)"
[ -n "$README_RES" ] || die "no resources/ images referenced from $REF:README.md"
README_RUS_RES="$(git show "$REF:README_RUS.md" \
    | grep -oE '\]\(resources/[^)]+' | sed 's/](//' \
    | grep -v -e '^resources/diagram_en\.svg$' -e '^resources/diagram_ru\.svg$' \
    | LC_ALL=C sort -u || true)"
[ "$README_RES" = "$README_RUS_RES" ] || \
    die "README.md and README_RUS.md reference different resources/ images"
for res in $LANG_RES; do
    git cat-file -e "$REF:$res" 2>/dev/null || die "missing $res at $REF"
done

EXPECTED="$STAGE/expected.list"
{
    printf '%s\n' \
        __init__.py pd.py gsmtap_stream.py \
        setup.sh start.sh setup.bat start.bat \
        tools/vs_reader.py README.md README_RUS.md LICENSE
    printf '%s\n' "$README_RES"
    printf '%s\n' resources/diagram_en.svg resources/diagram_ru.svg
} | LC_ALL=C sort -u > "$EXPECTED"

PATHS=()
while IFS= read -r path; do
    PATHS+=("$path")
done < "$EXPECTED"

# Build into the staging directory; dist/ is only touched after every check
# passes, so a failed build never leaves unverified archives behind.
git archive --format=tar.gz --prefix="${PREFIX}/" "$REF" \
    -o "$STAGE/${PREFIX}.tar.gz" -- "${PATHS[@]}"
git archive --format=zip --prefix="${PREFIX}/" "$REF" \
    -o "$STAGE/${PREFIX}.zip" -- "${PATHS[@]}"

# --- archive listings ----------------------------------------------------
list_archive() {
    case "$1" in
        *.zip)
            if command -v unzip >/dev/null 2>&1; then
                unzip -Z1 "$1"
            else
                python3 - "$1" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    for name in z.namelist():
        print(name)
PY
            fi
            ;;
        *)
            tar tzf "$1"
            ;;
    esac
}

normalize_listing() {
    # Strip the top-level prefix, drop directory entries, sort.
    awk -v p="$PREFIX/" '
        index($0, p) == 1 {
            name = substr($0, length(p) + 1)
            if (name != "" && name !~ /\/$/) print name
        }' | LC_ALL=C sort
}

DEV_PATHS=(
    tests/
    AGENTS.md
    .github/
    .gitignore
    .gitattributes
    examples/
    tools/build_release.sh
    tools/capture_baseline.sh
    tools/compare_baseline.sh
    tools/signal_diagnostic.py
)

check_archive_listing() {
    local archive="$1" listing="$2" actual="$3" path
    # Defense in depth: the pathspec already excludes these, but a future
    # refactor must not silently ship them.
    for path in "${DEV_PATHS[@]}"; do
        if grep -qF "${PREFIX}/${path}" "$listing"; then
            die "$archive unexpectedly contains dev-only path ${path}"
        fi
    done
    normalize_listing < "$listing" > "$actual"
    if ! diff -u "$EXPECTED" "$actual" > "$STAGE/list.diff"; then
        cat "$STAGE/list.diff" >&2
        die "$archive contents do not match the release allowlist (expected vs actual above)"
    fi
}

list_archive "$STAGE/${PREFIX}.tar.gz" > "$STAGE/tar.list"
list_archive "$STAGE/${PREFIX}.zip" > "$STAGE/zip.list"
check_archive_listing "$STAGE/${PREFIX}.tar.gz" "$STAGE/tar.list" "$STAGE/tar.files"
check_archive_listing "$STAGE/${PREFIX}.zip" "$STAGE/zip.list" "$STAGE/zip.files"

# --- unpack and verify both archives -------------------------------------
mkdir -p "$STAGE/tar" "$STAGE/zip"
tar xzf "$STAGE/${PREFIX}.tar.gz" -C "$STAGE/tar"
TAR_DIR="$STAGE/tar/$PREFIX"
[ -f "$TAR_DIR/pd.py" ] || die "tar.gz did not unpack ${PREFIX}/pd.py"

if command -v unzip >/dev/null 2>&1; then
    unzip -q "$STAGE/${PREFIX}.zip" -d "$STAGE/zip"
else
    python3 - "$STAGE/${PREFIX}.zip" "$STAGE/zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    z.extractall(sys.argv[2])
PY
fi
ZIP_DIR="$STAGE/zip/$PREFIX"
[ -f "$ZIP_DIR/pd.py" ] || die "zip did not unpack ${PREFIX}/pd.py"

check_tree() {
    local src="$1" label="$2" file found
    found="$(sed -n "s/^VERSION = '\([0-9][0-9.]*\)'.*/\1/p" "$src/pd.py")"
    [ "$found" = "$VERSION" ] || \
        die "$label: pd.py VERSION '$found', expected '$VERSION'"
    python3 -m py_compile "$src/pd.py" "$src/gsmtap_stream.py" "$src/__init__.py" || \
        die "$label: py_compile failed"
    for file in setup.sh start.sh; do
        bash -n "$src/$file" || die "$label: bash -n $file failed"
    done
    for file in setup.bat start.bat; do
        python3 - "$src/$file" <<'PY' || die "$label: $file is not CRLF-terminated"
import sys
data = open(sys.argv[1], 'rb').read()
if b'\n' not in data or data.count(b'\n') != data.count(b'\r\n'):
    sys.exit(1)
PY
    done
    for file in setup.sh start.sh; do
        if grep -q $'\r' "$src/$file"; then
            die "$label: $file contains CR (expected LF only)"
        fi
    done
}

check_tree "$TAR_DIR" "tar.gz"
check_tree "$ZIP_DIR" "zip"

[ -x "$TAR_DIR/setup.sh" ] || die "setup.sh is not executable in the tar.gz"
[ -x "$TAR_DIR/start.sh" ] || die "start.sh is not executable in the tar.gz"

# --- checksums and publish ----------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
    SHA256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
    SHA256=(shasum -a 256)
else
    die "neither sha256sum nor shasum is available"
fi
(cd "$STAGE" && "${SHA256[@]}" "${PREFIX}.tar.gz" "${PREFIX}.zip" > SHA256SUMS)

# Verified: replace any previous release files so a later `gh release upload
# dist/*` can never attach a stale archive.
mkdir -p dist
rm -f dist/sigrok_iso7816_stream-*.tar.gz \
      dist/sigrok_iso7816_stream-*.zip \
      dist/SHA256SUMS
mv "$STAGE/${PREFIX}.tar.gz" "$STAGE/${PREFIX}.zip" "$STAGE/SHA256SUMS" dist/

echo "Built release archives (VERSION $VERSION):"
du -h "dist/${PREFIX}.tar.gz" "dist/${PREFIX}.zip"
echo ""
echo "dist/SHA256SUMS:"
cat dist/SHA256SUMS
