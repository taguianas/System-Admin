#!/usr/bin/env bash
# =============================================================================
# create_users.sh — Batch user creation from a CSV file
#
# Usage:
#   sudo ./create_users.sh [OPTIONS] <csv_file>
#
# CSV format (header row is skipped):
#   username,group,shell,password
#
#   - username  : login name (required)
#   - group     : primary group; created automatically if it doesn't exist
#   - shell     : login shell, e.g. /bin/bash  (default: /bin/bash)
#   - password  : plain-text password; leave blank to auto-generate a temp one
#
# Options:
#   -l, --log-dir DIR   Directory for log files       (default: ../../logs)
#   -e, --expiry DAYS   Force password change on first login (default: yes, 0)
#   -d, --dry-run       Print actions without executing them
#   -h, --help          Show this help message
#
# Examples:
#   sudo ./create_users.sh sample_users.csv
#   sudo ./create_users.sh --dry-run sample_users.csv
#   sudo ./create_users.sh --log-dir /var/log/sysadmin sample_users.csv
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../../logs"
DEFAULT_SHELL="/bin/bash"
FORCE_EXPIRY=true
DRY_RUN=false
CSV_FILE=""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_log() {
    local level="$1"; shift
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local msg="$ts [$level] $*"
    echo "$msg" >&2
    echo "$msg" >> "$LOG_FILE"
}
log_info()  { _log "INFO    " "$@"; }
log_warn()  { _log "WARNING " "$@"; }
log_error() { _log "ERROR   " "$@"; }
log_debug() { [[ "$DRY_RUN" == true ]] && _log "DRY-RUN " "$@" || true; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,1\}//'
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--log-dir)  LOG_DIR="$2"; shift 2 ;;
            -e|--expiry)   FORCE_EXPIRY="$2"; shift 2 ;;
            -d|--dry-run)  DRY_RUN=true; shift ;;
            -h|--help)     usage ;;
            -*)            echo "Unknown option: $1" >&2; exit 1 ;;
            *)             CSV_FILE="$1"; shift ;;
        esac
    done

    if [[ -z "$CSV_FILE" ]]; then
        echo "Error: CSV file argument is required." >&2
        echo "Run with --help for usage." >&2
        exit 1
    fi

    if [[ ! -f "$CSV_FILE" ]]; then
        echo "Error: CSV file not found: $CSV_FILE" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: this script must be run as root (use sudo)." >&2
        exit 1
    fi
}

check_commands() {
    local missing=()
    for cmd in useradd groupadd chage usermod openssl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: required commands not found: ${missing[*]}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Generate a random 12-char password: letters + digits + symbols
generate_password() {
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c 12
}

# Hash a plain-text password for use with usermod -p
hash_password() {
    openssl passwd -6 "$1"
}

# Ensure a group exists; create it if needed
ensure_group() {
    local group="$1"
    if getent group "$group" &>/dev/null; then
        log_info "Group '$group' already exists — skipping creation"
    else
        if [[ "$DRY_RUN" == true ]]; then
            log_debug "Would create group: $group"
        else
            groupadd "$group"
            log_info "Created group: $group"
        fi
    fi
}

# Create a single user
create_user() {
    local username="$1"
    local group="$2"
    local shell="$3"
    local password="$4"
    local generated=false

    # Validate shell
    if ! grep -qx "$shell" /etc/shells 2>/dev/null; then
        log_warn "Shell '$shell' not listed in /etc/shells — using $DEFAULT_SHELL instead"
        shell="$DEFAULT_SHELL"
    fi

    # Check for existing user
    if id "$username" &>/dev/null; then
        log_warn "User '$username' already exists — skipping"
        return 0
    fi

    # Auto-generate password if not provided
    if [[ -z "$password" ]]; then
        password="$(generate_password)"
        generated=true
    fi

    local hashed_pw
    hashed_pw="$(hash_password "$password")"

    if [[ "$DRY_RUN" == true ]]; then
        log_debug "Would run: useradd -m -g $group -s $shell -p '<hashed>' $username"
        [[ "$generated" == true ]] && log_debug "Would auto-generate password for $username"
        [[ "$FORCE_EXPIRY" == true ]] && log_debug "Would force password change at first login for $username"
        return 0
    fi

    # Create the user
    useradd \
        --create-home \
        --gid "$group" \
        --shell "$shell" \
        --password "$hashed_pw" \
        "$username"

    log_info "Created user: $username (group=$group, shell=$shell)"

    # Force password change on first login
    if [[ "$FORCE_EXPIRY" == true ]]; then
        chage -d 0 "$username"
        log_info "Set first-login password change for: $username"
    fi

    # Print temp password to stdout so admin can distribute it securely
    if [[ "$generated" == true ]]; then
        # Write to a temp credentials file only root can read
        local cred_file
        cred_file="$(dirname "$LOG_FILE")/new_user_credentials.txt"
        install -m 600 /dev/null "$cred_file" 2>/dev/null || true
        echo "$username  $password" >> "$cred_file"
        log_warn "Auto-generated password for '$username' written to: $cred_file"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    check_root
    check_commands

    # Set up log file
    mkdir -p "$LOG_DIR"
    LOG_FILE="${LOG_DIR}/create_users.log"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    log_info "=== create_users.sh started ==="
    log_info "CSV file : $CSV_FILE"
    log_info "Dry run  : $DRY_RUN"

    local total=0 created=0 skipped=0 failed=0

    # Read CSV — skip header line and blank/comment lines
    while IFS=',' read -r username group shell password || [[ -n "$username" ]]; do
        # Skip header, blank lines, and comments
        [[ "$username" =~ ^[[:space:]]*(#|username|$) ]] && continue

        # Strip leading/trailing whitespace from each field
        username="$(echo "$username" | xargs)"
        group="$(echo "$group" | xargs)"
        shell="$(echo "$shell" | xargs)"
        password="$(echo "$password" | xargs)"

        # Apply defaults
        [[ -z "$shell" ]] && shell="$DEFAULT_SHELL"
        [[ -z "$group" ]] && group="$username"  # default: same-name primary group

        (( total++ )) || true

        # Validate username (Linux convention)
        if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            log_error "Invalid username '$username' — skipping"
            (( failed++ )) || true
            continue
        fi

        ensure_group "$group"

        if create_user "$username" "$group" "$shell" "$password"; then
            (( created++ )) || true
        else
            (( failed++ )) || true
        fi

    done < <(grep -v $'^\r$' "$CSV_FILE")   # strip Windows CR if present

    log_info "=== Summary: $total total, $created created, $skipped skipped, $failed failed ==="

    if [[ $failed -gt 0 ]]; then
        log_warn "Some users failed — check $LOG_FILE for details"
        exit 1
    fi
}

main "$@"
