#!/usr/bin/env bash
# =============================================================================
# delete_users.sh — Clean removal of user accounts
#
# Usage:
#   sudo ./delete_users.sh [OPTIONS] <csv_file | username [username ...]>
#
# Input modes:
#   CSV file  : same format as create_users.sh — only the username column is used
#   Arguments : one or more usernames passed directly on the command line
#
# What it does for each user:
#   1. Locks the account (passwd -l) to prevent new logins
#   2. Kills all active processes owned by the user
#   3. Archives the home directory → <archive_dir>/<username>_<timestamp>.tar.gz
#   4. Removes the user's crontab
#   5. Deletes the user account (userdel)
#   6. Optionally removes the primary group if it has no other members
#
# Options:
#   -a, --archive-dir DIR  Where to store home archives (default: /var/backups/user-archives)
#   -l, --log-dir DIR      Directory for log files     (default: ../../logs)
#   -k, --keep-home        Do NOT delete the home directory after archiving
#   -g, --keep-group       Do NOT remove the user's primary group
#   -d, --dry-run          Print actions without executing them
#   -h, --help             Show this help message
#
# Examples:
#   sudo ./delete_users.sh alice bob
#   sudo ./delete_users.sh --dry-run offboarded_users.csv
#   sudo ./delete_users.sh --archive-dir /mnt/archive alice
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../../logs"
ARCHIVE_DIR="/var/backups/user-archives"
KEEP_HOME=false
KEEP_GROUP=false
DRY_RUN=false
INPUTS=()   # CSV file path or list of usernames

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
log_dry()   { _log "DRY-RUN " "$@"; }

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
            -a|--archive-dir)  ARCHIVE_DIR="$2"; shift 2 ;;
            -l|--log-dir)      LOG_DIR="$2"; shift 2 ;;
            -k|--keep-home)    KEEP_HOME=true; shift ;;
            -g|--keep-group)   KEEP_GROUP=true; shift ;;
            -d|--dry-run)      DRY_RUN=true; shift ;;
            -h|--help)         usage ;;
            -*)                echo "Unknown option: $1" >&2; exit 1 ;;
            *)                 INPUTS+=("$1"); shift ;;
        esac
    done

    if [[ ${#INPUTS[@]} -eq 0 ]]; then
        echo "Error: provide a CSV file or at least one username." >&2
        echo "Run with --help for usage." >&2
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
    for cmd in userdel passwd tar crontab pkill; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: required commands not found: ${missing[*]}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Resolve input: CSV or bare usernames
# ---------------------------------------------------------------------------
collect_usernames() {
    local -n _out_array=$1   # nameref to caller's array

    for input in "${INPUTS[@]}"; do
        if [[ -f "$input" ]]; then
            log_info "Reading usernames from CSV: $input"
            while IFS=',' read -r username _rest || [[ -n "$username" ]]; do
                [[ "$username" =~ ^[[:space:]]*(#|username|$) ]] && continue
                username="$(echo "$username" | xargs)"
                [[ -n "$username" ]] && _out_array+=("$username")
            done < <(grep -v $'^\r$' "$input")
        else
            _out_array+=("$input")
        fi
    done
}

# ---------------------------------------------------------------------------
# Delete one user
# ---------------------------------------------------------------------------
delete_user() {
    local username="$1"

    # Verify the user exists
    if ! id "$username" &>/dev/null; then
        log_warn "User '$username' does not exist — skipping"
        return 0
    fi

    local home_dir
    home_dir="$(getent passwd "$username" | cut -d: -f6)"

    local primary_group
    primary_group="$(id -gn "$username" 2>/dev/null || echo "")"

    log_info "--- Processing user: $username (home=$home_dir, group=$primary_group) ---"

    # 1. Lock the account
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would lock account: passwd -l $username"
    else
        passwd -l "$username" &>/dev/null || log_warn "Could not lock $username (already locked?)"
        log_info "Locked account: $username"
    fi

    # 2. Kill active processes
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would kill processes owned by: $username"
    else
        local procs
        procs="$(pgrep -u "$username" 2>/dev/null | tr '\n' ' ' || true)"
        if [[ -n "$procs" ]]; then
            pkill -TERM -u "$username" 2>/dev/null || true
            sleep 2
            pkill -KILL -u "$username" 2>/dev/null || true
            log_info "Killed processes for: $username (PIDs: $procs)"
        else
            log_info "No running processes for: $username"
        fi
    fi

    # 3. Archive home directory
    if [[ -d "$home_dir" ]]; then
        local ts
        ts="$(date '+%Y%m%d_%H%M%S')"
        local archive_name="${username}_${ts}.tar.gz"
        local archive_path="${ARCHIVE_DIR}/${archive_name}"

        if [[ "$DRY_RUN" == true ]]; then
            log_dry "Would archive: $home_dir → $archive_path"
        else
            mkdir -p "$ARCHIVE_DIR"
            chmod 700 "$ARCHIVE_DIR"

            if tar -czf "$archive_path" -C "$(dirname "$home_dir")" "$(basename "$home_dir")" 2>/dev/null; then
                chmod 600 "$archive_path"
                local size
                size="$(du -sh "$archive_path" | cut -f1)"
                log_info "Archived home directory: $archive_path ($size)"
            else
                log_error "Failed to archive home directory for $username — aborting deletion"
                return 1
            fi
        fi
    else
        log_warn "Home directory not found for $username: $home_dir"
    fi

    # 4. Remove crontab
    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would remove crontab for: $username"
    else
        if crontab -u "$username" -l &>/dev/null 2>&1; then
            crontab -u "$username" -r
            log_info "Removed crontab for: $username"
        else
            log_info "No crontab for: $username"
        fi
    fi

    # 5. Delete the user account
    local userdel_flags=("--force")
    [[ "$KEEP_HOME" == false ]] && userdel_flags+=("--remove")

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would run: userdel ${userdel_flags[*]} $username"
    else
        userdel "${userdel_flags[@]}" "$username"
        log_info "Deleted user: $username"
    fi

    # 6. Optionally remove primary group
    if [[ "$KEEP_GROUP" == false && -n "$primary_group" ]]; then
        # Only remove the group if it is now empty (no other members)
        if getent group "$primary_group" &>/dev/null; then
            local members
            members="$(getent group "$primary_group" | cut -d: -f4)"
            if [[ -z "$members" ]]; then
                if [[ "$DRY_RUN" == true ]]; then
                    log_dry "Would remove empty primary group: $primary_group"
                else
                    groupdel "$primary_group" 2>/dev/null && \
                        log_info "Removed empty primary group: $primary_group" || \
                        log_warn "Could not remove group '$primary_group' (may be used elsewhere)"
                fi
            else
                log_info "Group '$primary_group' still has members — keeping it"
            fi
        fi
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
    LOG_FILE="${LOG_DIR}/delete_users.log"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    log_info "=== delete_users.sh started ==="
    log_info "Archive dir : $ARCHIVE_DIR"
    log_info "Keep home   : $KEEP_HOME"
    log_info "Keep group  : $KEEP_GROUP"
    log_info "Dry run     : $DRY_RUN"

    local usernames=()
    collect_usernames usernames

    if [[ ${#usernames[@]} -eq 0 ]]; then
        log_error "No valid usernames found in input."
        exit 1
    fi

    local total=${#usernames[@]} deleted=0 failed=0

    for username in "${usernames[@]}"; do
        if delete_user "$username"; then
            (( deleted++ )) || true
        else
            (( failed++ )) || true
        fi
    done

    log_info "=== Summary: $total total, $deleted deleted, $failed failed ==="

    if [[ $failed -gt 0 ]]; then
        log_warn "Some deletions failed — check $LOG_FILE for details"
        exit 1
    fi
}

main "$@"
