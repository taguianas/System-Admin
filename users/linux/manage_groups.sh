#!/usr/bin/env bash
# ===========================================================================
# manage_groups.sh — Group management utility
#
# Usage:
#   sudo ./manage_groups.sh <command> [OPTIONS] [ARGS]
#
# Commands:
#   create  <group> [--gid GID]          Create a new group
#   delete  <group> [--force]            Delete a group (--force skips member check)
#   add     <group> <user> [user ...]    Add one or more users to a group
#   remove  <group> <user> [user ...]    Remove one or more users from a group
#   list    <group>                      List members of a group
#   show    <user>                       Show all groups a user belongs to
#   bulk    <csv_file>                   Apply a CSV of group operations (see below)
#
# Bulk CSV format (header row is skipped):
#   action,group,username
#   add,developers,alice
#   add,developers,bob
#   remove,qa,charlie
#   create,devops,
#   delete,oldteam,
#
# Global options:
#   -l, --log-dir DIR   Directory for log files (default: ../../logs)
#   -d, --dry-run       Print actions without executing them
#   -h, --help          Show this help message
#
# Examples:
#   sudo ./manage_groups.sh create developers
#   sudo ./manage_groups.sh add developers alice bob carol
#   sudo ./manage_groups.sh remove developers alice
#   sudo ./manage_groups.sh list developers
#   sudo ./manage_groups.sh show alice
#   sudo ./manage_groups.sh bulk group_changes.csv
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/../../logs"
DRY_RUN=false
COMMAND=""

# ---------------------------------------------------------------------------
# Logging (LOG_FILE is set in main after LOG_DIR is resolved)
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
    for cmd in groupadd groupdel gpasswd getent; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Error: required commands not found: ${missing[*]}" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

cmd_create() {
    local group="$1"
    local gid="${2:-}"

    if getent group "$group" &>/dev/null; then
        log_warn "Group '$group' already exists — skipping"
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would create group: $group${gid:+ (GID=$gid)}"
        return 0
    fi

    if [[ -n "$gid" ]]; then
        groupadd --gid "$gid" "$group"
    else
        groupadd "$group"
    fi
    log_info "Created group: $group$(getent group "$group" | awk -F: '{print " (GID="$3")"}')"
}

cmd_delete() {
    local group="$1"
    local force="${2:-false}"

    if ! getent group "$group" &>/dev/null; then
        log_warn "Group '$group' does not exist — skipping"
        return 0
    fi

    # Check for members
    local members
    members="$(getent group "$group" | cut -d: -f4)"
    if [[ -n "$members" && "$force" != true ]]; then
        log_error "Group '$group' still has members: $members"
        log_error "Use --force to delete anyway, or remove members first."
        return 1
    fi

    if [[ -n "$members" && "$force" == true ]]; then
        log_warn "Force-deleting group '$group' with members: $members"
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_dry "Would delete group: $group"
        return 0
    fi

    groupdel "$group"
    log_info "Deleted group: $group"
}

cmd_add() {
    local group="$1"
    shift
    local users=("$@")

    if ! getent group "$group" &>/dev/null; then
        log_error "Group '$group' does not exist. Create it first."
        return 1
    fi

    for user in "${users[@]}"; do
        if ! id "$user" &>/dev/null; then
            log_error "User '$user' does not exist — skipping"
            continue
        fi

        # Check if already a member
        if id -nG "$user" | grep -qw "$group"; then
            log_warn "User '$user' is already in group '$group' — skipping"
            continue
        fi

        if [[ "$DRY_RUN" == true ]]; then
            log_dry "Would add '$user' to group '$group'"
        else
            gpasswd -a "$user" "$group"
            log_info "Added '$user' to group '$group'"
        fi
    done
}

cmd_remove() {
    local group="$1"
    shift
    local users=("$@")

    if ! getent group "$group" &>/dev/null; then
        log_error "Group '$group' does not exist."
        return 1
    fi

    for user in "${users[@]}"; do
        if ! id "$user" &>/dev/null; then
            log_warn "User '$user' does not exist — skipping"
            continue
        fi

        if ! id -nG "$user" | grep -qw "$group"; then
            log_warn "User '$user' is not in group '$group' — skipping"
            continue
        fi

        if [[ "$DRY_RUN" == true ]]; then
            log_dry "Would remove '$user' from group '$group'"
        else
            gpasswd -d "$user" "$group"
            log_info "Removed '$user' from group '$group'"
        fi
    done
}

cmd_list() {
    local group="$1"

    if ! getent group "$group" &>/dev/null; then
        log_error "Group '$group' does not exist."
        return 1
    fi

    local gid members
    gid="$(getent group "$group" | cut -d: -f3)"
    members="$(getent group "$group" | cut -d: -f4)"

    echo ""
    echo "Group   : $group"
    echo "GID     : $gid"

    if [[ -z "$members" ]]; then
        echo "Members : (none)"
    else
        echo "Members :"
        tr ',' '\n' <<< "$members" | while read -r m; do
            echo "  - $m"
        done
    fi
    echo ""
}

cmd_show() {
    local user="$1"

    if ! id "$user" &>/dev/null; then
        log_error "User '$user' does not exist."
        return 1
    fi

    local primary secondary
    primary="$(id -gn "$user")"
    secondary="$(id -Gn "$user" | tr ' ' '\n' | grep -v "^${primary}$" | sort || true)"

    echo ""
    echo "User          : $user"
    echo "UID           : $(id -u "$user")"
    echo "Primary group : $primary (GID=$(id -g "$user"))"
    echo "Other groups  :"
    if [[ -z "$secondary" ]]; then
        echo "  (none)"
    else
        echo "$secondary" | while read -r g; do
            local gid
            gid="$(getent group "$g" | cut -d: -f3)"
            echo "  - $g (GID=$gid)"
        done
    fi
    echo ""
}

cmd_bulk() {
    local csv_file="$1"

    if [[ ! -f "$csv_file" ]]; then
        log_error "Bulk CSV file not found: $csv_file"
        return 1
    fi

    log_info "Processing bulk operations from: $csv_file"
    local line_num=0 ok=0 failed=0

    while IFS=',' read -r action group username || [[ -n "$action" ]]; do
        (( line_num++ )) || true

        # Skip header, blank lines, comments
        [[ "$action" =~ ^[[:space:]]*(#|action|$) ]] && continue

        action="$(echo "$action" | xargs)"
        group="$(echo "$group" | xargs)"
        username="$(echo "$username" | xargs)"

        case "$action" in
            create)
                cmd_create "$group" && (( ok++ )) || (( failed++ )) || true
                ;;
            delete)
                cmd_delete "$group" && (( ok++ )) || (( failed++ )) || true
                ;;
            add)
                if [[ -z "$username" ]]; then
                    log_error "Line $line_num: 'add' requires a username"
                    (( failed++ )) || true
                else
                    cmd_add "$group" "$username" && (( ok++ )) || (( failed++ )) || true
                fi
                ;;
            remove)
                if [[ -z "$username" ]]; then
                    log_error "Line $line_num: 'remove' requires a username"
                    (( failed++ )) || true
                else
                    cmd_remove "$group" "$username" && (( ok++ )) || (( failed++ )) || true
                fi
                ;;
            *)
                log_error "Line $line_num: unknown action '$action' (expected: create, delete, add, remove)"
                (( failed++ )) || true
                ;;
        esac
    done < <(grep -v $'^\r$' "$csv_file")

    log_info "Bulk complete: $ok succeeded, $failed failed"
    [[ $failed -gt 0 ]] && return 1 || return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    # Parse global flags first, then the subcommand and its arguments
    local -a remaining=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -l|--log-dir) LOG_DIR="$2"; shift 2 ;;
            -d|--dry-run) DRY_RUN=true; shift ;;
            -h|--help)    usage ;;
            *)            remaining+=("$1"); shift ;;
        esac
    done

    if [[ ${#remaining[@]} -eq 0 ]]; then
        echo "Error: no command given." >&2
        echo "Run with --help for usage." >&2
        exit 1
    fi

    COMMAND="${remaining[0]}"
    remaining=("${remaining[@]:1}")   # shift off the command

    check_root
    check_commands

    # Set up log file
    mkdir -p "$LOG_DIR"
    LOG_FILE="${LOG_DIR}/manage_groups.log"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    log_info "=== manage_groups.sh: $COMMAND ${remaining[*]:-} ==="

    case "$COMMAND" in
        create)
            [[ ${#remaining[@]} -lt 1 ]] && { log_error "create requires a group name"; exit 1; }
            local gid=""
            if [[ "${remaining[1]:-}" == "--gid" ]]; then
                gid="${remaining[2]:-}"
            fi
            cmd_create "${remaining[0]}" "$gid"
            ;;
        delete)
            [[ ${#remaining[@]} -lt 1 ]] && { log_error "delete requires a group name"; exit 1; }
            local force=false
            [[ "${remaining[1]:-}" == "--force" ]] && force=true
            cmd_delete "${remaining[0]}" "$force"
            ;;
        add)
            [[ ${#remaining[@]} -lt 2 ]] && { log_error "add requires a group name and at least one user"; exit 1; }
            cmd_add "${remaining[0]}" "${remaining[@]:1}"
            ;;
        remove)
            [[ ${#remaining[@]} -lt 2 ]] && { log_error "remove requires a group name and at least one user"; exit 1; }
            cmd_remove "${remaining[0]}" "${remaining[@]:1}"
            ;;
        list)
            [[ ${#remaining[@]} -lt 1 ]] && { log_error "list requires a group name"; exit 1; }
            cmd_list "${remaining[0]}"
            ;;
        show)
            [[ ${#remaining[@]} -lt 1 ]] && { log_error "show requires a username"; exit 1; }
            cmd_show "${remaining[0]}"
            ;;
        bulk)
            [[ ${#remaining[@]} -lt 1 ]] && { log_error "bulk requires a CSV file path"; exit 1; }
            cmd_bulk "${remaining[0]}"
            ;;
        *)
            log_error "Unknown command: '$COMMAND'"
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
}

main "$@"
