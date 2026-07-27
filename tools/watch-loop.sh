#!/bin/sh
# Scheduled-run wrapper for the VPS deployment.
#
# Deliberately a shell loop rather than cron: the container has one job, `docker compose logs`
# is where the operator already looks, and a cron daemon inside a container adds a scheduler
# whose failures are silent. A loop that logs every wake-up is easier to trust.
#
#   INTERVAL_SECONDS  how long to sleep between runs (default: 7 days)
#   RUN_AT_START      "1" to run immediately on boot rather than sleeping first
#
# Exit code 1 from the changelog scanner means "something auth-relevant changed", not
# "failure". It must not kill the container, so it is caught and logged loudly instead.

set -u

INTERVAL_SECONDS="${INTERVAL_SECONDS:-604800}"
RUN_AT_START="${RUN_AT_START:-1}"

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
    echo "[watch] === clean: nothing relevant changed ==="
  else
    status=$?
    # 1 is the scanner's "go look at this" signal. Anything else is a real malfunction.
    if [ "$status" -eq 1 ]; then
      echo "[watch] === ATTENTION: relevant change detected. Review the digest above. ==="
    else
      echo "[watch] === ERROR: command exited $status ==="
    fi
  fi
  echo "[watch] sleeping ${INTERVAL_SECONDS}s"
  sleep "$INTERVAL_SECONDS"
done
