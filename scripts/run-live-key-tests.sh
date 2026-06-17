#!/usr/bin/env bash
# run-live-key-tests.sh — safely run the destructive LINUX-ROOT + LIVE-KEY bats
# tier WITHOUT losing the operator's Anthropic API key.
#
# WHY: the mutating suite exercises Slice-1's deprovision_aios_state, which does
# `rm -rf /var/log/osgania /opt/osgania /etc/osgania` to reset to a clean slate.
# That `rm -rf /etc/osgania` WIPES /etc/osgania/secrets/anthropic-api-key — the
# operator's real key. It is correct for Slice-1's own teardown (the secrets dir
# must be empty per PV-10), but it destroys operator state placed AFTER
# provisioning. The per-test backup/restore in HA-09-S3 only protects HA-09-S3;
# a Slice-1 deprovision in the same suite run still deletes the key. So protect it
# at the SUITE level: back the key up before the run and restore it afterward —
# even on failure or Ctrl-C (EXIT/INT/TERM trap).
#
# Usage (as root on a DISPOSABLE Slice-1 + 2a box that holds a real key):
#   scripts/run-live-key-tests.sh [extra bats args...]
set -euo pipefail

KEY=/etc/osgania/secrets/anthropic-api-key
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP=""

restore_key() {
    if [[ -n "$BACKUP" && -f "$BACKUP" ]]; then
        install -d -m 0700 -o root -g root "$(dirname "$KEY")"
        install -m 600 -o root -g root "$BACKUP" "$KEY"
        rm -f "$BACKUP"
        printf 'run-live-key-tests.sh: restored operator key to %s\n' "$KEY" >&2
    fi
}
trap restore_key EXIT INT TERM

if [[ "$(uname)" != "Linux" || "$EUID" -ne 0 ]]; then
    printf 'run-live-key-tests.sh: must run as root on Linux (disposable box only)\n' >&2
    exit 2
fi

if [[ -f "$KEY" ]]; then
    BACKUP="$(mktemp)"
    cp -p "$KEY" "$BACKUP"
    printf 'run-live-key-tests.sh: backed up operator key (%s bytes) before the destructive suite\n' \
        "$(stat -c%s "$KEY")" >&2
else
    printf 'run-live-key-tests.sh: no operator key present at %s (live-key tests will skip)\n' "$KEY" >&2
fi

PROVISION_TEST_ALLOW_MUTATION=1 LIVE_KEY_AVAILABLE=1 bats "$REPO_ROOT/tests/" "$@"
# restore_key runs on EXIT (success or failure).
