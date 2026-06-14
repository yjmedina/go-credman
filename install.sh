#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="credman"
INSTALL_DIR="/usr/local/bin"
INSTALL_PATH="${INSTALL_DIR}/${BINARY_NAME}"
DATA_DIR="${HOME}/.credman"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: ${0##*/} [--uninstall|--help]

  (no flags)    Build ${BINARY_NAME} and install it to ${INSTALL_PATH}.
  --uninstall   Remove ${INSTALL_PATH}. Leaves ${DATA_DIR} untouched.
  --help        Show this message.
EOF
}

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

sudo_if_needed() {
    local target_dir="$1"; shift
    if [ -w "$target_dir" ]; then
        "$@"
    else
        log "elevating with sudo for ${target_dir}"
        sudo "$@"
    fi
}

do_install() {
    command -v go >/dev/null 2>&1 || die "go is not installed or not on PATH. See https://go.dev/dl/"

    local go_version
    go_version="$(go env GOVERSION 2>/dev/null || true)"
    log "using ${go_version:-unknown go version}"

    cd "$SCRIPT_DIR"
    [ -f go.mod ]  || die "go.mod not found in ${SCRIPT_DIR}"
    [ -f main.go ] || die "main.go not found in ${SCRIPT_DIR}"

    log "building ${BINARY_NAME}"
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${BINARY_NAME}" ./ \
        || die "go build failed"

    [ -d "$INSTALL_DIR" ] || sudo_if_needed "$(dirname "$INSTALL_DIR")" mkdir -p "$INSTALL_DIR"

    if [ -e "$INSTALL_PATH" ]; then
        log "overwriting existing ${INSTALL_PATH}"
    fi

    sudo_if_needed "$INSTALL_DIR" install -m 0755 "${SCRIPT_DIR}/${BINARY_NAME}" "$INSTALL_PATH"
    log "installed ${BINARY_NAME} to ${INSTALL_PATH}"

    local resolved
    resolved="$(command -v "$BINARY_NAME" || true)"
    if [ -z "$resolved" ]; then
        warn "${BINARY_NAME} not found on PATH. Is ${INSTALL_DIR} on your \$PATH?"
    elif [ "$resolved" != "$INSTALL_PATH" ]; then
        warn "PATH resolves ${BINARY_NAME} to ${resolved}, not ${INSTALL_PATH}"
    else
        log "PATH check: ${resolved}"
    fi

    log "smoke test: ${BINARY_NAME} --help"
    "$INSTALL_PATH" --help >/dev/null 2>&1 \
        || warn "${BINARY_NAME} --help exited non-zero (binary still installed)"

    log "done. Run: ${BINARY_NAME} --help"
}

do_uninstall() {
    if [ ! -e "$INSTALL_PATH" ]; then
        log "${INSTALL_PATH} not present, nothing to uninstall"
    else
        sudo_if_needed "$INSTALL_DIR" rm -f "$INSTALL_PATH"
        log "removed ${INSTALL_PATH}"
    fi

    if [ -d "$DATA_DIR" ]; then
        log "user data preserved at ${DATA_DIR}"
        log "to wipe it as well, run: rm -rf \"${DATA_DIR}\""
    fi
}

case "${1:-}" in
    ""|--install)   do_install ;;
    --uninstall)    do_uninstall ;;
    -h|--help)      usage ;;
    *)              usage; exit 2 ;;
esac
