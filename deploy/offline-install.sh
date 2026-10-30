#!/usr/bin/env bash
# Offline installation of Ferry.
#
#   build    Connected side. Builds the Ferry wheel plus every dependency wheel
#            for the target platform into a wheelhouse directory, and writes
#            SHA256SUMS next to them.
#   install  Disconnected side. Verifies SHA256SUMS, creates a virtualenv and
#            installs Ferry from the wheelhouse only (pip never contacts an index).
#
# Examples
#   deploy/offline-install.sh build --out wheelhouse                       # for this machine's platform
#   deploy/offline-install.sh build --out wheelhouse --platform manylinux_2_28_x86_64 --python 3.11
#   deploy/offline-install.sh install --wheelhouse /media/transfer/wheelhouse --dest /opt/ferry
set -euo pipefail

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

sha_tool() {
  if command -v sha256sum >/dev/null 2>&1; then echo "sha256sum"; else echo "shasum -a 256"; fi
}

build() {
  local out="wheelhouse" platform="" pyver="" python="${PYTHON:-python3}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --platform) platform="$2"; shift 2 ;;
      --python) pyver="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -f pyproject.toml ] || { echo "run build from the Ferry source tree (pyproject.toml not found)" >&2; exit 2; }
  mkdir -p "$out"

  echo "Building the Ferry wheel"
  "$python" -m pip wheel --no-deps --quiet . -w "$out"

  local deps
  deps="$("$python" -c 'import tomllib; print(" ".join(tomllib.load(open("pyproject.toml", "rb"))["project"]["dependencies"]))')"
  echo "Downloading dependency wheels: $deps"
  if [ -n "$platform" ] || [ -n "$pyver" ]; then
    [ -n "$platform" ] && [ -n "$pyver" ] || { echo "--platform and --python must be given together" >&2; exit 2; }
    # shellcheck disable=SC2086
    "$python" -m pip download --quiet --only-binary=:all: --platform "$platform" --python-version "$pyver" \
      --implementation cp -d "$out" $deps
  else
    # shellcheck disable=SC2086
    "$python" -m pip download --quiet --only-binary=:all: -d "$out" $deps
  fi

  ( cd "$out" && rm -f SHA256SUMS && $(sha_tool) ./*.whl > SHA256SUMS )
  echo
  echo "Wheelhouse: $out ($(ls "$out"/*.whl | wc -l | tr -d ' ') wheels)"
  echo "Checksums:  $out/SHA256SUMS"
  echo "Move the whole directory through your approved transfer process, then on the target:"
  echo "  deploy/offline-install.sh install --wheelhouse <dir> --dest /opt/ferry"
}

install() {
  local wh="" dest="" python="${PYTHON:-python3}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --wheelhouse) wh="$2"; shift 2 ;;
      --dest) dest="$2"; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "$wh" ] && [ -n "$dest" ] || usage
  [ -f "$wh/SHA256SUMS" ] || { echo "$wh/SHA256SUMS is missing; refusing to install unverified wheels" >&2; exit 1; }

  echo "Verifying wheel checksums"
  ( cd "$wh" && $(sha_tool) -c SHA256SUMS )
  local listed present
  listed="$(grep -c . "$wh/SHA256SUMS")"
  present="$(ls "$wh"/*.whl | wc -l | tr -d ' ')"
  [ "$listed" = "$present" ] || { echo "SHA256SUMS lists $listed wheels but $present are present; refusing" >&2; exit 1; }

  echo "Creating virtualenv $dest"
  "$python" -m venv "$dest"
  echo "Installing from the wheelhouse only (no index access)"
  "$dest/bin/pip" install --quiet --no-index --find-links "$wh" ferry-airgap
  echo
  echo "Installed: $("$dest/bin/ferry" version)"
  echo "Next: $dest/bin/ferry --data-dir /var/lib/ferry init   (see docs/deployment.md)"
}

case "${1:-}" in
  build) shift; build "$@" ;;
  install) shift; install "$@" ;;
  *) usage ;;
esac
