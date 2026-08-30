#!/usr/bin/env bash
set -uo pipefail

attempt_limit="${1:-}"
initial_delay="${2:-}"
shift 2 2>/dev/null || {
    echo "Usage: $0 ATTEMPTS INITIAL_DELAY_SECONDS COMMAND [ARGUMENT ...]" >&2
    exit 2
}

[[ "$attempt_limit" =~ ^[1-9][0-9]*$ ]] || {
    echo "Retry gate failed: ATTEMPTS must be a positive integer" >&2
    exit 2
}
[[ "$initial_delay" =~ ^[1-9][0-9]*$ ]] || {
    echo "Retry gate failed: INITIAL_DELAY_SECONDS must be a positive integer" >&2
    exit 2
}
[[ $# -gt 0 ]] || {
    echo "Retry gate failed: no command was provided" >&2
    exit 2
}

attempt=1
while true; do
    "$@"
    exit_code=$?
    if [[ "$exit_code" -eq 0 ]]; then
        exit 0
    fi
    if [[ "$attempt" -ge "$attempt_limit" ]]; then
        echo "Retry gate failed: command exited $exit_code after $attempt attempts" >&2
        exit "$exit_code"
    fi
    delay=$((initial_delay * attempt))
    echo "Command exited $exit_code; retrying attempt $((attempt + 1))/$attempt_limit in ${delay}s" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
done
