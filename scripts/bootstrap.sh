#!/usr/bin/env bash
set -Eeuo pipefail

readonly INSTALLER_VERSION="${CENTRALCLOUD_INSTALLER_VERSION:-1.0.7}"
readonly RELEASE_BASE="${CENTRALCLOUD_INSTALLER_RELEASE_BASE:-https://github.com/CentralCorp-Cloud/centralcloud-installer/releases/download/v${INSTALLER_VERSION}}"

fail() {
  printf 'CentralCloud bootstrap: %s\n' "$1" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "run this script with sudo"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

case "$(uname -s)" in
  Linux) ;;
  *) fail "only Linux is supported" ;;
esac

[[ -r /etc/os-release ]] || fail "/etc/os-release is required"
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) ;;
  *) fail "unsupported operating system: ${ID:-unknown} ${VERSION_ID:-unknown}" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  download() { curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$1" --output "$2"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget --https-only --quiet "$1" --output-document="$2"; }
else
  fail "curl or wget is required"
fi

workdir="$(mktemp -d)"
cleanup() {
  find "${workdir}" -type f -delete 2>/dev/null || true
  rmdir "${workdir}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
umask 077

asset="centralcloud-installer_${INSTALLER_VERSION}_linux_${arch}"
download "${RELEASE_BASE}/${asset}" "${workdir}/${asset}"
download "${RELEASE_BASE}/checksums.txt" "${workdir}/checksums.txt"
(
  cd "${workdir}"
  grep " ${asset}$" checksums.txt | sha256sum --check --strict -
)
chmod 0700 "${workdir}/${asset}"
"${workdir}/${asset}" install "$@"
