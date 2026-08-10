#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
simplelogin_commit="$(tr -d '[:space:]' <"$script_dir/SIMPLELOGIN_COMMIT")"

export SIMPLELOGIN_COMMIT="$simplelogin_commit"
export SIMPLELOGIN_APP_DIR="${SIMPLELOGIN_APP_DIR:-$(dirname "$repository_root")/simplelogin-upstream}"
export SIMPLELOGIN_HTTP_PORT="${SIMPLELOGIN_HTTP_PORT:-17777}"
export SIMPLELOGIN_SMTP_PORT="${SIMPLELOGIN_SMTP_PORT:-20381}"
export SIMPLELOGIN_MAILPIT_HTTP_PORT="${SIMPLELOGIN_MAILPIT_HTTP_PORT:-18025}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-bitwarden-simplelogin-lab}"

compose_file="$script_dir/compose.yml"
compose=(docker compose --project-name "$COMPOSE_PROJECT_NAME" --file "$compose_file")
official_remote="https://github.com/simple-login/app.git"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  }
}

ensure_docker() {
  require_command docker
  docker info >/dev/null 2>&1 || {
    printf 'Docker is installed but its daemon is unavailable\n' >&2
    exit 1
  }
  docker compose version >/dev/null
}

ensure_source() {
  require_command git
  if [[ ! -e "$SIMPLELOGIN_APP_DIR/.git" ]]; then
    if [[ -e "$SIMPLELOGIN_APP_DIR" ]]; then
      printf 'SimpleLogin source path exists but is not a git clone: %s\n' "$SIMPLELOGIN_APP_DIR" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$SIMPLELOGIN_APP_DIR")"
    git clone --filter=blob:none "$official_remote" "$SIMPLELOGIN_APP_DIR"
  fi

  local remote
  remote="$(git -C "$SIMPLELOGIN_APP_DIR" remote get-url origin)"
  case "$remote" in
    https://github.com/simple-login/app.git|git@github.com:simple-login/app.git)
      ;;
    *)
      printf 'refusing unexpected SimpleLogin origin: %s\n' "$remote" >&2
      exit 1
      ;;
  esac

  if [[ -n "$(git -C "$SIMPLELOGIN_APP_DIR" status --porcelain)" ]]; then
    printf 'refusing to change dirty SimpleLogin clone: %s\n' "$SIMPLELOGIN_APP_DIR" >&2
    exit 1
  fi

  if ! git -C "$SIMPLELOGIN_APP_DIR" cat-file -e "${simplelogin_commit}^{commit}" 2>/dev/null; then
    git -C "$SIMPLELOGIN_APP_DIR" fetch --depth 1 origin "$simplelogin_commit"
  fi
  git -C "$SIMPLELOGIN_APP_DIR" checkout --detach "$simplelogin_commit" >/dev/null
  [[ "$(git -C "$SIMPLELOGIN_APP_DIR" rev-parse HEAD)" == "$simplelogin_commit" ]]
}

wait_for_url() {
  local url="$1"
  local attempts="${2:-90}"
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if curl --silent --show-error --fail "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'timed out waiting for %s\n' "$url" >&2
  return 1
}

wait_for_port() {
  local port="$1"
  local attempts="${2:-60}"
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if python3 - "$port" <<'PY'
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
    pass
PY
    then
      return 0
    fi
    sleep 1
  done
  printf 'timed out waiting for local TCP port %s\n' "$port" >&2
  return 1
}

start_mail() {
  "${compose[@]}" --profile mail up --detach mailpit email
  wait_for_url "http://127.0.0.1:${SIMPLELOGIN_MAILPIT_HTTP_PORT}/readyz"
  wait_for_port "$SIMPLELOGIN_SMTP_PORT"
}

provision() {
  local with_mail="${1:-0}"
  ensure_docker
  ensure_source
  require_command curl
  require_command python3

  "${compose[@]}" build app
  "${compose[@]}" up --detach postgres redis
  "${compose[@]}" run --rm app alembic upgrade head
  "${compose[@]}" run --rm app python init_app.py
  "${compose[@]}" up --detach app
  wait_for_url "http://127.0.0.1:${SIMPLELOGIN_HTTP_PORT}/health"
  if [[ "$with_mail" == "1" ]]; then
    start_mail
  fi
  printf 'SimpleLogin %s is ready at http://127.0.0.1:%s\n' "$simplelogin_commit" "$SIMPLELOGIN_HTTP_PORT"
}

seed_json() {
  "${compose[@]}" exec --no-TTY app python /lab/seed.py | tail -n 1
}

seed_fixtures() {
  require_command jq
  local seeded
  seeded="$(seed_json)"
  jq -e '.api_key and .user_email and .seeded_aliases' >/dev/null <<<"$seeded"
  jq '{user_email,seeded_aliases,seeded_contact}' <<<"$seeded"
}

verify_ready() {
  require_command curl
  require_command jq
  wait_for_url "http://127.0.0.1:${SIMPLELOGIN_HTTP_PORT}/health" 5

  local credentials api_key user_email user_info database_ready
  credentials="$(seed_json)"
  api_key="$(jq -r '.api_key' <<<"$credentials")"
  user_email="$(jq -r '.user_email' <<<"$credentials")"
  user_info="$(curl --silent --show-error --fail-with-body \
    --header "Authentication: ${api_key}" \
    "http://127.0.0.1:${SIMPLELOGIN_HTTP_PORT}/api/user_info")"
  jq -e --arg email "$user_email" '.email == $email' >/dev/null <<<"$user_info"
  database_ready="$("${compose[@]}" exec --no-TTY postgres \
    psql --username simplelogin --dbname simplelogin --tuples-only --no-align \
    --command 'SELECT 1;')"
  [[ "$database_ready" == "1" ]]
  printf 'SimpleLogin authenticated API and PostgreSQL are ready\n'
}

run_lifecycle() {
  local with_mail="${1:-0}"
  require_command cargo
  require_command curl
  require_command jq

  if [[ "$with_mail" == "1" ]]; then
    start_mail
  fi

  local credentials
  credentials="$(seed_json)"
  jq -e '.api_key and .user_email and .seeded_aliases' >/dev/null <<<"$credentials"

  SIMPLELOGIN_BASE_URL="http://127.0.0.1:${SIMPLELOGIN_HTTP_PORT}" \
  SIMPLELOGIN_API_KEY="$(jq -r '.api_key' <<<"$credentials")" \
  SIMPLELOGIN_USER_EMAIL="$(jq -r '.user_email' <<<"$credentials")" \
  SIMPLELOGIN_LAB_SCRIPT="$script_dir/lab.sh" \
  SIMPLELOGIN_MAIL_TEST="$with_mail" \
  SIMPLELOGIN_MAILPIT_URL="http://127.0.0.1:${SIMPLELOGIN_MAILPIT_HTTP_PORT}" \
  bash "$script_dir/lifecycle.sh"
}

usage() {
  cat <<'EOF'
Usage: support/simplelogin/lab.sh COMMAND [--mail]

Commands:
  provision   Clone/pin/build/migrate/start the real SimpleLogin environment
  seed        Reset deterministic fixtures without printing the generated API key
  ready       Verify PostgreSQL and the authenticated API using an ephemeral key
  reset       Delete local lab data and provision a clean environment
  inspect     Print persisted state without API key values
  lifecycle   Run the real API, SDK, and database lifecycle checks
  test        Provision and run lifecycle checks
  down        Stop the environment and delete its local Docker volumes
  logs        Follow service logs (add --mail to include mail services)
EOF
}

command_name="${1:-}"
option="${2:-}"
with_mail=0
if [[ "$command_name" != "db-scalar" ]]; then
  if [[ "$option" == "--mail" ]]; then
    with_mail=1
  elif [[ -n "$option" ]]; then
    usage >&2
    exit 2
  fi
fi

case "$command_name" in
  provision)
    provision "$with_mail"
    ;;
  seed)
    seed_fixtures
    ;;
  ready)
    verify_ready
    ;;
  reset)
    ensure_docker
    "${compose[@]}" --profile mail down --volumes --remove-orphans
    provision "$with_mail"
    ;;
  inspect)
    "${compose[@]}" exec --no-TTY postgres \
      psql --username simplelogin --dbname simplelogin \
      --file /dev/stdin <"$script_dir/inspect-state.sql"
    ;;
  db-scalar)
    [[ $# -eq 2 ]] || exit 2
    "${compose[@]}" exec --no-TTY postgres \
      psql --username simplelogin --dbname simplelogin --tuples-only --no-align \
      --command "$2"
    ;;
  lifecycle)
    run_lifecycle "$with_mail"
    ;;
  test)
    provision "$with_mail"
    run_lifecycle "$with_mail"
    ;;
  down)
    ensure_docker
    "${compose[@]}" --profile mail down --volumes --remove-orphans
    ;;
  logs)
    if [[ "$with_mail" == "1" ]]; then
      "${compose[@]}" --profile mail logs --follow
    else
      "${compose[@]}" logs --follow postgres redis app
    fi
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
