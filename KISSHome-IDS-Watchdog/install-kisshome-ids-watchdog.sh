#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="kisshome-ids-watchdog"
SCRIPT_PATH="/usr/local/bin/${SERVICE_NAME}.sh"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_PATH="/etc/systemd/system/${SERVICE_NAME}.timer"

# Defaults (can be overridden with flags on install)
DEFAULT_PORT="5000"
DEFAULT_INTERVAL="2min"          # systemd span: e.g. 2min, 5min, 30s, hourly
DEFAULT_IMAGE="kisshome/ids:stable"

print_usage() {
  cat <<'EOF'
Usage:
  install-kisshome-ids-watchdog.sh --shared-path <ABSOLUTE_PATH> [--port <PORT>] [--interval <SYSTEMD_SPAN>] [--test]
  install-kisshome-ids-watchdog.sh --uninstall

Options:
  --shared-path, -s   (required for install) Absolute host path to mount into the container as /shared
  --port, -p          External port to publish to container port 5000 (default: 5000)
  --interval          systemd timer frequency (default: 2min). Examples: 1min, 5min, 30s, hourly
  --test              Use image tag 'kisshome/ids:test' instead of ':stable'
  --uninstall         Stop/disable timer & service and remove installed files
  --help, -h          Show this help

Examples:
  sudo bash install-kisshome-ids-watchdog.sh --shared-path /home/gas/kisshome-ids
  sudo bash install-kisshome-ids-watchdog.sh --shared-path /data/kisshome --port 5044 --interval 1min --test
  sudo bash install-kisshome-ids-watchdog.sh --uninstall
EOF
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Please run as root (e.g. via sudo)." >&2
    exit 1
  fi
}

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
    echo "systemd not detected. This installer requires systemd (Linux)." >&2
    exit 1
  fi
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "'docker' CLI not found in PATH. Please install Docker and try again." >&2
    exit 1
  fi
}

is_integer() { [[ "$1" =~ ^[0-9]+$ ]] ;}

uninstall() {
  echo "Stopping and disabling timer/service (if present)…"
  systemctl disable --now "${SERVICE_NAME}.timer" 2>/dev/null || true
  systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true

  echo "Removing unit files…"
  rm -f "$SERVICE_PATH" "$TIMER_PATH"

  echo "Reloading systemd daemon…"
  systemctl daemon-reload

  echo "Removing watchdog script (if present)…"
  rm -f "$SCRIPT_PATH"

  echo "Uninstall complete."
}

write_watchdog_script() {
  # This script consumes env vars:
  #   SHARED_PATH (required), PORT (default 5000), IMAGE (default kisshome/ids:stable)
  mkdir -p "$(dirname "$SCRIPT_PATH")"
  cat > "$SCRIPT_PATH" <<'WATCHDOG'
#!/usr/bin/env bash
# kisshome-ids-watchdog.sh
# Checks the kisshome_ids container /status endpoint and restarts the container fresh on error.
# Also checks if a newer $IMAGE exists and (when status is Error or Running) restarts onto the newest image.
# Pulls are rate-limited to at most once per hour to respect Docker Hub limits.

set -euo pipefail

CONTAINER_NAME="kisshome_ids"
IMAGE="${IMAGE:-kisshome/ids:stable}"

# --- Runtime configuration via environment ---
: "${SHARED_PATH:?SHARED_PATH environment variable (absolute host path) is required}"
PORT="${PORT:-5000}"

# --- Internal tuning ---
CURL_TIMEOUT=5
RETRY_COUNT=2
MIN_RESTART_INTERVAL_SECS=60
STATE_DIR="/var/tmp"
LAST_RESTART_FILE="$STATE_DIR/kisshome_ids_last_restart"

# Docker Hub pull rate limiting (100 pulls / 6h) -> we attempt at most one pull/hour (per image)
PULL_KEY="$(echo "$IMAGE" | sed 's/[^A-Za-z0-9]/_/g')"
PULL_STATE_FILE="$STATE_DIR/kisshome_ids_last_pull_${PULL_KEY}"
PULL_INTERVAL_SECS=3600

log() {
  local msg="$1"
  if command -v logger >/dev/null 2>&1; then
    logger -t kisshome-ids-watchdog "$msg"
  fi
  echo "$(date '+%F %T') kisshome-ids-watchdog: $msg"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Basic sanity checks
if ! have docker; then
  log "docker CLI not found in PATH."
  exit 1
fi

# Ensure shared path exists
if [[ ! -d "$SHARED_PATH" ]]; then
  log "Shared path '$SHARED_PATH' does not exist."
  exit 1
fi

# Build docker run command (no sudo; service runs as root)
DOCKER_RUN_CMD=(
  docker run --rm -d
  --name "$CONTAINER_NAME"
  -p "${PORT}:5000"
  --security-opt apparmor=unconfined
  -v "${SHARED_PATH}:/shared:Z"
  "$IMAGE"
)

STATUS_URL="http://127.0.0.1:${PORT}/status"

is_running() {
  docker ps --filter "name=^/${CONTAINER_NAME}$" --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"
}

running_image_id() {
  docker inspect -f '{{.Image}}' "$CONTAINER_NAME" 2>/dev/null || true
}

tag_image_id() {
  docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || true
}

extract_status() {
  if have jq; then
    jq -r '.message.status // empty'
  else
    python3 - <<'PY' || true
import sys, json
try:
    data = json.load(sys.stdin)
    print((data.get("message") or {}).get("status",""))
except Exception:
    pass
PY
  fi
}

# Returns API status on stdout, exit 0 if reachable, 1 if unreachable
get_api_status() {
  local attempt=0
  while (( attempt <= RETRY_COUNT )); do
    if RESP_JSON=$(curl --fail -sS --max-time "$CURL_TIMEOUT" \
        -H 'accept: application/json' "$STATUS_URL"); then
      local status
      status=$(printf '%s' "$RESP_JSON" | extract_status | tr -d '\r\n')
      if [[ -z "$status" ]]; then
        echo "UNKNOWN"
        return 0
      fi
      echo "$status"
      return 0
    fi
    attempt=$((attempt+1))
    sleep 2
  done
  return 1
}

# Pull latest tag no more than once per hour; always pull if no local tag exists.
# Sets globals: HAS_NEW_TAG (0/1), RUNNING_OUTDATED (0/1), NEW_TAG_ID (string)
pull_and_check_update() {
  HAS_NEW_TAG=0
  RUNNING_OUTDATED=0
  NEW_TAG_ID=""

  local before_tag_id after_tag_id run_id
  before_tag_id="$(tag_image_id || true)"

  local now last_pull=0 need_pull=1
  now=$(date +%s)
  if [[ -f "$PULL_STATE_FILE" ]]; then
    last_pull=$(cat "$PULL_STATE_FILE" 2>/dev/null || echo 0)
  fi

  # If we already have a local tag and last pull was < 1h ago, skip pulling
  if [[ -n "$before_tag_id" && $(( now - last_pull )) -lt $PULL_INTERVAL_SECS ]]; then
    need_pull=0
    log "Skipping docker pull for rate limit (last pull $((now - last_pull))s ago; threshold ${PULL_INTERVAL_SECS}s)."
  fi

  if (( need_pull == 1 )); then
    log "Checking for newer image: $IMAGE (hourly-limited pull)…"
    if docker pull "$IMAGE" >/dev/null 2>&1; then
      date +%s > "$PULL_STATE_FILE"
    else
      log "docker pull $IMAGE failed (continuing with existing local image if present)."
    fi
  fi

  after_tag_id="$(tag_image_id || true)"
  run_id="$(running_image_id || true)"

  if [[ -n "$after_tag_id" && "$after_tag_id" != "$before_tag_id" ]]; then
    HAS_NEW_TAG=1
    NEW_TAG_ID="$after_tag_id"
    if [[ -z "$before_tag_id" ]]; then
      log "Initial local image for $IMAGE obtained."
    else
      log "New tag detected for $IMAGE."
    fi
  fi

  if [[ -n "$run_id" && -n "$after_tag_id" && "$run_id" != "$after_tag_id" ]]; then
    RUNNING_OUTDATED=1
  fi
}

restart_container() {
  local now
  now=$(date +%s)
  local last=0
  if [[ -f "$LAST_RESTART_FILE" ]]; then
    last=$(cat "$LAST_RESTART_FILE" 2>/dev/null || echo 0)
  fi
  local delta=$(( now - last ))
  if (( delta < MIN_RESTART_INTERVAL_SECS )); then
    log "Skipping restart (last restart $delta s ago; threshold $MIN_RESTART_INTERVAL_SECS s)."
    return 1
  fi

  log "Restarting container: $CONTAINER_NAME"

  if is_running; then
    if ! docker stop -t 10 "$CONTAINER_NAME" >/dev/null 2>&1; then
      log "docker stop failed or container already gone; forcing remove."
    fi
  fi

  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

  "${DOCKER_RUN_CMD[@]}" >/dev/null
  date +%s > "$LAST_RESTART_FILE"
  log "Container started clean with image $IMAGE on port ${PORT} mounting ${SHARED_PATH}."
}

# --- Main ---
# Ensure container exists if not running
if ! is_running; then
  log "Container not running; starting it."
  restart_container || true
fi

# Get current API status (or mark unreachable)
STATUS="UNREACHABLE"
if STATUS_OUT=$(get_api_status); then
  STATUS="$STATUS_OUT"
else
  STATUS="UNREACHABLE"
fi
log "Current service status: $STATUS"

# Hourly-limited pull + image comparison
pull_and_check_update

# Decide on restart:
# 1) If unreachable -> restart (and we have just pulled if allowed; will use newest local).
# 2) If status == Error -> restart (start newest local).
# 3) If status == Running AND running image is outdated -> restart to update.
# 4) Otherwise, no restart (e.g., training/Started), even if newer image exists; defer.
SHOULD_RESTART=0
REASON=""

if [[ "$STATUS" == "UNREACHABLE" ]]; then
  SHOULD_RESTART=1
  REASON="endpoint unreachable"
elif [[ "$STATUS" == "Error" ]]; then
  SHOULD_RESTART=1
  REASON="status=Error"
elif [[ "$STATUS" == "Running" && "${RUNNING_OUTDATED:-0}" -eq 1 ]]; then
  SHOULD_RESTART=1
  REASON="newer image available and status=Running"
fi

if (( SHOULD_RESTART == 1 )); then
  if (( RUNNING_OUTDATED == 1 )); then
    log "Running image is outdated relative to current local $IMAGE; will restart to update (${REASON})."
  else
    log "Will restart due to ${REASON}."
  fi
  restart_container || true
  # Post-restart quick check (optional)
  if STATUS_OUT=$(get_api_status); then
    log "Service status after restart: $STATUS_OUT"
    exit 0
  else
    log "Service unreachable after restart."
    exit 1
  fi
else
  if (( RUNNING_OUTDATED == 1 )); then
    log "Newer image available, but current status is '$STATUS' (not Error/Running). Deferring update."
  else
    log "Service healthy and up-to-date (status='$STATUS')."
  fi
  exit 0
fi
WATCHDOG

  chmod 0755 "$SCRIPT_PATH"
}

write_service_units() {
  local shared_path="$1"
  local port="$2"
  local interval="$3"
  local image="$4"

  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Kisshome IDS watchdog (health-check + hourly-limited image update)
Wants=docker.service network-online.target
After=docker.service network-online.target

[Service]
Type=oneshot
User=root
Group=root
# pass runtime configuration to the watchdog
Environment="SHARED_PATH=${shared_path}"
Environment="PORT=${port}"
Environment="IMAGE=${image}"
# ensure docker is resolvable
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=${SCRIPT_PATH}

# Optional hardening (ensure it doesn't block docker socket access):
# NoNewPrivileges=yes
# PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

  cat > "$TIMER_PATH" <<EOF
[Unit]
Description=Run ${SERVICE_NAME} every ${interval}

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}
AccuracySec=30s
RandomizedDelaySec=10s
Unit=${SERVICE_NAME}.service

[Install]
WantedBy=timers.target
EOF
}

main() {
  local uninstall_flag="0"
  local shared_path=""
  local port="${DEFAULT_PORT}"
  local interval="${DEFAULT_INTERVAL}"
  local image="${DEFAULT_IMAGE}"
  local use_test="0"

  # Parse args
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --uninstall) uninstall_flag="1"; shift ;;
      --shared-path|-s) shared_path="${2:-}"; shift 2 ;;
      --port|-p) port="${2:-}"; shift 2 ;;
      --interval) interval="${2:-}"; shift 2 ;;
      --test) use_test="1"; shift ;;
      --help|-h) print_usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; print_usage; exit 1 ;;
    esac
  done

  require_root
  require_systemd

  if [[ "$uninstall_flag" == "1" ]]; then
    uninstall
    exit 0
  fi

  require_docker

  # Apply image selection
  if [[ "$use_test" == "1" ]]; then
    image="kisshome/ids:test"
  fi

  # Validate inputs
  if [[ -z "$shared_path" ]]; then
    echo "--shared-path is required for install." >&2
    print_usage
    exit 1
  fi

  # Resolve to absolute path if possible
  if command -v realpath >/dev/null 2>&1; then
    shared_path="$(realpath -m "$shared_path")"
  elif [[ "$shared_path" != /* ]]; then
    shared_path="$(cd "$(dirname "$shared_path")" && pwd -P)/$(basename "$shared_path")"
  fi

  if [[ ! -d "$shared_path" ]]; then
    echo "Shared path does not exist: $shared_path" >&2
    exit 1
  fi

  if [[ -z "$port" ]] || ! is_integer "$port" || (( port < 1 || port > 65535 )); then
    echo "Invalid --port value: ${port}. Must be an integer between 1 and 65535." >&2
    exit 1
  fi

  echo "Installing watchdog:"
  echo "  Shared path : $shared_path"
  echo "  Port        : $port (published to container 5000)"
  echo "  Interval    : $interval"
  echo "  Image       : $image"

  write_watchdog_script
  write_service_units "$shared_path" "$port" "$interval" "$image"

  echo "Reloading systemd daemon…"
  systemctl daemon-reload

  echo "Enabling and starting timer…"
  systemctl enable --now "${SERVICE_NAME}.timer"

  echo "Done."
  echo
  echo "Check status:"
  echo "  systemctl status ${SERVICE_NAME}.timer"
  echo "  systemctl status ${SERVICE_NAME}.service"
  echo "  journalctl -u ${SERVICE_NAME}.service -n 100 --no-pager"
  echo
  echo "The watchdog polls http://127.0.0.1:${port}/status, attempts 'docker pull ${image}' at most once/hour,"
  echo "and restarts if status is Error/unreachable, or if status is Running and the running image is older than the local tag."
}

main "$@"
