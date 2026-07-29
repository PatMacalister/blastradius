#!/bin/sh
# Scheduled-run wrapper for the VPS deployment.
#
# Deliberately a shell loop rather than cron: the container has one job, `docker compose logs`
# is where the operator already looks, and a cron daemon inside a container adds a scheduler
# whose failures are silent. A loop that logs every wake-up is easier to trust.
#
#   INTERVAL_SECONDS  how long to sleep between runs (default: 7 days)
#   RUN_AT_START      "1" to run immediately on boot rather than sleeping first
#   WATCH_MODE        "scan" (default) or "test" — what exit 1 MEANS, and how to say so
#
# The two jobs this wraps disagree about exit 1, and the difference is not cosmetic:
#
#   scan  the changelog scanner returns 1 for "something auth-relevant was announced".
#         That is news to read, not a malfunction.
#   test  the contract runner returns 1 for "assertions failed" — a provider module is now
#         wrong about a live API, which is the failure this whole project exists to catch.
#
# Both were previously logged as "ATTENTION: relevant change detected. Review the digest
# above", and a passing run of either as "clean: nothing relevant changed". Applied to the
# test runner both are misleading: a failed contract run read as informational drift news
# rather than as a broken module, which is exactly the wrong direction to be vague in.

set -u

INTERVAL_SECONDS="${INTERVAL_SECONDS:-604800}"
RUN_AT_START="${RUN_AT_START:-1}"
WATCH_MODE="${WATCH_MODE:-scan}"

if [ "$#" -eq 0 ]; then
  echo "usage: watch-loop.sh <command> [args...]" >&2
  exit 2
fi

if [ "$RUN_AT_START" != "1" ]; then
  echo "[watch] sleeping ${INTERVAL_SECONDS}s before first run"
  sleep "$INTERVAL_SECONDS"
fi

while true; do
  echo "[watch] === run starting: $* ==="
  if "$@"; then
    if [ "$WATCH_MODE" = "test" ]; then
      echo "[watch] === PASS: every live assertion held ==="
    else
      echo "[watch] === clean: nothing relevant changed ==="
    fi
  else
    status=$?
    if [ "$status" -eq 1 ]; then
      if [ "$WATCH_MODE" = "test" ]; then
        # Not news. A module's claim about a live API no longer holds, or a test credential
        # expired, and the two look identical from here — see ops/ROTATION-RUNBOOK.md.
        echo "[watch] === FAILED: live assertions did not hold. A provider module may now be"
        echo "[watch]     reporting incorrectly. Do NOT re-stamp lastVerified until you know why. ==="
      else
        echo "[watch] === ATTENTION: relevant change announced. Review the digest above. ==="
      fi
    else
      echo "[watch] === ERROR: command exited $status ==="
    fi
  fi
  echo "[watch] sleeping ${INTERVAL_SECONDS}s"
  sleep "$INTERVAL_SECONDS"
done
