#!/usr/bin/env python3
"""
audit_users.py — Cross-platform user account auditing tool.

Collects account information and produces JSON and/or HTML reports covering:
  - All local user accounts
  - Last login time and days of inactivity
  - Accounts inactive beyond a configurable threshold (default: 90 days)
  - Accounts with no password / locked accounts (Linux)
  - Accounts with password-never-expires policy
  - Admin / sudo privileges
  - Accounts that have never logged in

Linux:  reads /etc/passwd, /etc/shadow (needs root), /etc/group, lastlog
Windows: queries via PowerShell Get-LocalUser / Get-LocalGroupMember

Usage
-----
    # Linux — full audit (root needed for /etc/shadow)
    sudo python audit_users.py
    sudo python audit_users.py --format html --output report.html
    sudo python audit_users.py --format json,html --output-dir /tmp/audit
    sudo python audit_users.py --inactive-days 60 --include-system

    # Windows — run as Administrator
    python audit_users.py --format html
    python audit_users.py --inactive-days 30 --format json
"""

import argparse
import dataclasses
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow running from users/linux/ or users/windows/ — add project root to path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from common.logger import get_logger
from common.config_loader import get_nested

logger = get_logger(__name__, log_dir=_PROJECT_ROOT / "logs")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class UserRecord:
    username: str
    uid: int | None            # Linux UID; None on Windows
    home_dir: str
    shell: str | None          # Linux login shell; None on Windows
    enabled: bool
    last_login: datetime | None
    days_since_login: int | None   # None = never logged in
    has_password: bool             # False = no/locked/empty password
    password_never_expires: bool
    is_admin: bool                 # sudo/wheel (Linux) or Administrators (Windows)
    groups: list[str]
    issues: list[str]              # populated by flag_issues()

    def flag_issues(self, inactive_threshold: int = 90) -> None:
        """Populate self.issues with detected problems."""
        self.issues = []
        if not self.enabled:
            return  # disabled accounts are not flagged

        if self.days_since_login is None:
            self.issues.append("Never logged in")
        elif self.days_since_login > inactive_threshold:
            self.issues.append(f"Inactive {self.days_since_login}d (threshold: {inactive_threshold}d)")

        if not self.has_password:
            self.issues.append("No password / locked")

        if self.password_never_expires and self.is_admin:
            self.issues.append("Admin with password-never-expires")

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["last_login"] = self.last_login.isoformat() if self.last_login else None
        return d


# ---------------------------------------------------------------------------
# Linux auditor
# ---------------------------------------------------------------------------

class LinuxAuditor:
    """Collect user data from Linux system files and commands."""

    # Minimum UID for regular users (system accounts below this are skipped
    # unless --include-system is passed)
    DEFAULT_MIN_UID = 1000
    # Groups that grant admin rights
    ADMIN_GROUPS = {"sudo", "wheel", "admin", "root"}

    def __init__(
        self,
        min_uid: int = DEFAULT_MIN_UID,
        include_system: bool = False,
    ) -> None:
        self._min_uid = 0 if include_system else min_uid
        self._include_system = include_system

    def collect(self) -> list[UserRecord]:
        passwd   = self._parse_passwd()
        shadow   = self._parse_shadow()
        groups   = self._parse_groups()
        logins   = self._get_last_logins()

        records: list[UserRecord] = []
        for username, pdata in passwd.items():
            uid = pdata["uid"]
            if uid < self._min_uid and not self._include_system:
                continue

            sdata     = shadow.get(username, {})
            user_grps = groups.get(username, [])
            login_dt  = logins.get(username)

            now = datetime.now()
            days = None
            if login_dt is not None:
                days = (now - login_dt).days

            has_pw = self._has_password(sdata)
            pw_never_exp = self._password_never_expires(sdata)
            is_admin = bool(set(user_grps) & self.ADMIN_GROUPS)

            record = UserRecord(
                username=username,
                uid=uid,
                home_dir=pdata["home"],
                shell=pdata["shell"],
                enabled=not self._is_locked(sdata),
                last_login=login_dt,
                days_since_login=days,
                has_password=has_pw,
                password_never_expires=pw_never_exp,
                is_admin=is_admin,
                groups=user_grps,
                issues=[],
            )
            records.append(record)

        logger.info("Linux audit collected %d user records", len(records))
        return records

    # ---- /etc/passwd -------------------------------------------------------

    def _parse_passwd(self) -> dict[str, dict]:
        result: dict[str, dict] = {}
        passwd_file = Path("/etc/passwd")
        if not passwd_file.exists():
            logger.warning("/etc/passwd not found")
            return result

        for line in passwd_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, _, uid_str, _, _, home, shell = parts[:7]
            try:
                uid = int(uid_str)
            except ValueError:
                continue
            result[username] = {
                "uid": uid,
                "home": home,
                "shell": shell,
            }
        return result

    # ---- /etc/shadow -------------------------------------------------------

    def _parse_shadow(self) -> dict[str, dict]:
        result: dict[str, dict] = {}
        shadow_file = Path("/etc/shadow")
        if not shadow_file.exists():
            return result
        try:
            text = shadow_file.read_text()
        except PermissionError:
            logger.warning(
                "/etc/shadow is not readable — run as root for full password data"
            )
            return result

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 8:
                continue
            username = parts[0]
            pw_hash  = parts[1]  # '!' or '!!' or '*' = locked/no-pw; '' = blank
            # Field 5 (index 4): max days; Field 7 (index 6): inactive; Field 8 (index 7): expire
            max_days  = parts[4] if len(parts) > 4 else ""
            result[username] = {
                "pw_hash": pw_hash,
                "max_days": max_days,
            }
        return result

    def _is_locked(self, sdata: dict) -> bool:
        if not sdata:
            return False
        ph = sdata.get("pw_hash", "")
        return ph.startswith("!") or ph == "*"

    def _has_password(self, sdata: dict) -> bool:
        if not sdata:
            return True   # no shadow data — assume password exists
        ph = sdata.get("pw_hash", "x")
        # '!' or '!!' = locked, '*' = no login, '' = empty
        return bool(ph) and not ph.startswith("!") and ph != "*"

    def _password_never_expires(self, sdata: dict) -> bool:
        if not sdata:
            return False
        max_days = sdata.get("max_days", "")
        return max_days in ("", "0", "99999")

    # ---- /etc/group --------------------------------------------------------

    def _parse_groups(self) -> dict[str, list[str]]:
        """Returns {username: [group1, group2, ...]}"""
        user_groups: dict[str, list[str]] = {}
        group_file = Path("/etc/group")
        if not group_file.exists():
            return user_groups

        for line in group_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            group_name = parts[0]
            members    = [m for m in parts[3].split(",") if m]
            for member in members:
                user_groups.setdefault(member, []).append(group_name)

        return user_groups

    # ---- lastlog -----------------------------------------------------------

    def _get_last_logins(self) -> dict[str, datetime | None]:
        """Run `lastlog` and parse the output."""
        result: dict[str, datetime | None] = {}
        try:
            output = subprocess.check_output(
                ["lastlog"], text=True, stderr=subprocess.DEVNULL
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            logger.warning("lastlog command not available — last login data unavailable")
            return result

        # Header line format:  Username  Port  From  Latest
        for line in output.splitlines()[1:]:   # skip header
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if not parts:
                continue
            username = parts[0]
            if "Never" in line:
                result[username] = None
                continue
            # Date portion: everything after the 3rd field (Port + From may be blank)
            # lastlog format: "username  pts/0  192.168.1.1  Mon Jan  1 12:00:00 +0000 2024"
            # or:             "username             **Never logged in**"
            # Date is last 5 tokens: Weekday Mon DD HH:MM:SS [TZ] YYYY
            parsed = None
            # Try formats from most to least specific
            for n_tokens, fmt in [
                (6, "%a %b %d %H:%M:%S %z %Y"),   # Mon Jan  6 14:23:00 +0000 2025
                (5, "%a %b %d %H:%M:%S %Y"),       # Mon Jan  6 14:23:00 2025
            ]:
                if len(parts) >= n_tokens:
                    try:
                        date_str = " ".join(parts[-n_tokens:])
                        dt = datetime.strptime(date_str, fmt)
                        parsed = dt.replace(tzinfo=None)
                        break
                    except ValueError:
                        continue
            if parsed:
                result[username] = parsed
            else:
                logger.debug("Could not parse lastlog date for %s: %s", username, line)

        return result


# ---------------------------------------------------------------------------
# Windows auditor
# ---------------------------------------------------------------------------

class WindowsAuditor:
    """Collect user data via PowerShell Get-LocalUser and Get-LocalGroupMember."""

    def collect(self) -> list[UserRecord]:
        users_json   = self._run_ps(
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon,"
            "PasswordLastSet,PasswordNeverExpires,PasswordRequired,SID "
            "| ConvertTo-Json -Depth 3"
        )
        admins_json  = self._run_ps(
            "Get-LocalGroupMember -Group Administrators "
            "| Select-Object Name | ConvertTo-Json -Depth 2"
        )
        all_groups_json = self._run_ps(
            "Get-LocalGroup | ForEach-Object { "
            "$g = $_.Name; "
            "try { Get-LocalGroupMember -Group $g | Select-Object @{N='Group';E={$g}}, Name } "
            "catch {} } | ConvertTo-Json -Depth 2"
        )

        users_data  = self._safe_json_list(users_json)
        admins_data = self._safe_json_list(admins_json)
        groups_data = self._safe_json_list(all_groups_json)

        admin_names = set()
        for entry in admins_data:
            raw = entry.get("Name", "")
            admin_names.add(raw.split("\\")[-1].lower())

        # Build {username: [groups]}
        user_groups: dict[str, list[str]] = {}
        for entry in groups_data:
            raw_name  = entry.get("Name", "")
            member    = raw_name.split("\\")[-1]
            grp_name  = entry.get("Group", "")
            if member and grp_name:
                user_groups.setdefault(member, []).append(grp_name)

        records: list[UserRecord] = []
        for u in users_data:
            username = u.get("Name", "").strip()
            if not username:
                continue

            enabled          = bool(u.get("Enabled", False))
            pw_never_expires = bool(u.get("PasswordNeverExpires", False))
            pw_required      = bool(u.get("PasswordRequired", True))
            is_admin         = username.lower() in admin_names

            last_logon_raw = u.get("LastLogon")
            last_login = self._parse_win_datetime(last_logon_raw)

            now  = datetime.now()
            days = (now - last_login).days if last_login else None

            sid  = u.get("SID", {})
            sid_value = sid.get("Value", "") if isinstance(sid, dict) else str(sid)

            record = UserRecord(
                username=username,
                uid=None,
                home_dir=f"C:\\Users\\{username}",
                shell=None,
                enabled=enabled,
                last_login=last_login,
                days_since_login=days,
                has_password=pw_required,
                password_never_expires=pw_never_expires,
                is_admin=is_admin,
                groups=user_groups.get(username, []),
                issues=[],
            )
            records.append(record)

        logger.info("Windows audit collected %d user records", len(records))
        return records

    def _run_ps(self, command: str) -> str:
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error("PowerShell execution failed: %s", exc)
            return "[]"

    def _safe_json_list(self, raw: str) -> list[dict]:
        if not raw or raw in ("null", ""):
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError as exc:
            logger.warning("Could not parse PowerShell JSON output: %s", exc)
        return []

    def _parse_win_datetime(self, raw: Any) -> datetime | None:
        """Parse Windows datetime from PowerShell JSON output."""
        if not raw:
            return None
        if isinstance(raw, str):
            for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(raw, fmt)
                except ValueError:
                    continue
        return None


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Account Audit Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #f0f2f5; color: #1a1a2e; }
    header { background: #1a1a2e; color: #fff; padding: 1.5rem 2rem; }
    header h1 { font-size: 1.4rem; font-weight: 600; }
    header p  { font-size: 0.85rem; opacity: 0.7; margin-top: 0.25rem; }
    main { max-width: 1300px; margin: 2rem auto; padding: 0 1rem; }

    /* Summary cards */
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card  { background: #fff; border-radius: 8px; padding: 1.25rem 1rem; text-align: center;
             box-shadow: 0 1px 4px rgba(0,0,0,.08); }
    .card .num { font-size: 2rem; font-weight: 700; }
    .card .lbl { font-size: 0.75rem; color: #666; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: .05em; }
    .card.danger .num { color: #dc3545; }
    .card.warn   .num { color: #fd7e14; }
    .card.ok     .num { color: #198754; }

    /* Tables */
    section { background: #fff; border-radius: 8px; padding: 1.5rem;
              box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 2rem; }
    section h2 { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: #1a1a2e; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: #f8f9fa; text-align: left; padding: .5rem .75rem;
         border-bottom: 2px solid #dee2e6; font-weight: 600; white-space: nowrap; }
    td { padding: .45rem .75rem; border-bottom: 1px solid #f0f2f5; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr.flagged td { background: #fff8f0; }
    tr.disabled td { color: #999; font-style: italic; }

    /* Badges */
    .badge { display: inline-block; padding: .15em .5em; border-radius: 4px;
             font-size: .75em; font-weight: 600; margin: .1em .1em 0 0; white-space: nowrap; }
    .badge-danger { background: #fde; color: #a00; }
    .badge-warn   { background: #fff3cd; color: #856404; }
    .badge-info   { background: #d1ecf1; color: #0c5460; }
    .badge-ok     { background: #d4edda; color: #155724; }
    .badge-muted  { background: #e9ecef; color: #495057; }

    .no-issues { color: #198754; font-weight: 500; }
  </style>
</head>
<body>
<header>
  <h1>User Account Audit Report</h1>
  <p>Generated: {{ generated_at }} &nbsp;|&nbsp; Platform: {{ platform }} &nbsp;|&nbsp; Hostname: {{ hostname }}</p>
</header>
<main>

  <div class="cards">
    <div class="card"><div class="num">{{ stats.total }}</div><div class="lbl">Total Users</div></div>
    <div class="card ok"><div class="num">{{ stats.enabled }}</div><div class="lbl">Enabled</div></div>
    <div class="card warn"><div class="num">{{ stats.disabled }}</div><div class="lbl">Disabled</div></div>
    <div class="card danger"><div class="num">{{ stats.flagged }}</div><div class="lbl">Flagged</div></div>
    <div class="card danger"><div class="num">{{ stats.inactive }}</div><div class="lbl">Inactive</div></div>
    <div class="card danger"><div class="num">{{ stats.no_password }}</div><div class="lbl">No Password</div></div>
    <div class="card warn"><div class="num">{{ stats.admins }}</div><div class="lbl">Admins</div></div>
    <div class="card warn"><div class="num">{{ stats.never_expires }}</div><div class="lbl">Pw Never Expires</div></div>
  </div>

  {% if flagged_users %}
  <section>
    <h2>&#9888; Flagged Accounts ({{ flagged_users | length }})</h2>
    <table>
      <tr>
        <th>Username</th><th>UID</th><th>Last Login</th><th>Admin</th><th>Issues</th>
      </tr>
      {% for u in flagged_users %}
      <tr class="flagged">
        <td><strong>{{ u.username }}</strong></td>
        <td>{{ u.uid if u.uid is not none else "-" }}</td>
        <td>{{ u.last_login.strftime('%Y-%m-%d') if u.last_login else "Never" }}</td>
        <td>{% if u.is_admin %}<span class="badge badge-danger">ADMIN</span>{% else %}-{% endif %}</td>
        <td>{% for issue in u.issues %}<span class="badge badge-danger">{{ issue }}</span>{% endfor %}</td>
      </tr>
      {% endfor %}
    </table>
  </section>
  {% endif %}

  <section>
    <h2>All User Accounts</h2>
    <table>
      <tr>
        <th>Username</th><th>UID</th><th>Status</th><th>Last Login</th>
        <th>Days Inactive</th><th>Has Password</th><th>Pw Expires</th>
        <th>Admin</th><th>Groups</th><th>Issues</th>
      </tr>
      {% for u in users %}
      <tr class="{{ 'flagged' if u.issues else ('disabled' if not u.enabled else '') }}">
        <td><strong>{{ u.username }}</strong></td>
        <td>{{ u.uid if u.uid is not none else "-" }}</td>
        <td>
          {% if u.enabled %}
            <span class="badge badge-ok">enabled</span>
          {% else %}
            <span class="badge badge-muted">disabled</span>
          {% endif %}
        </td>
        <td>{{ u.last_login.strftime('%Y-%m-%d') if u.last_login else "Never" }}</td>
        <td>{{ u.days_since_login if u.days_since_login is not none else "-" }}</td>
        <td>
          {% if u.has_password %}
            <span class="badge badge-ok">yes</span>
          {% else %}
            <span class="badge badge-danger">no</span>
          {% endif %}
        </td>
        <td>
          {% if u.password_never_expires %}
            <span class="badge badge-warn">never</span>
          {% else %}
            <span class="badge badge-ok">yes</span>
          {% endif %}
        </td>
        <td>
          {% if u.is_admin %}
            <span class="badge badge-danger">ADMIN</span>
          {% else %}
            -
          {% endif %}
        </td>
        <td>{{ u.groups | join(', ') if u.groups else '-' }}</td>
        <td>
          {% if u.issues %}
            {% for issue in u.issues %}
              <span class="badge badge-danger">{{ issue }}</span>
            {% endfor %}
          {% else %}
            <span class="no-issues">&#10003;</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </section>

</main>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class AuditReporter:
    def __init__(
        self,
        records: list[UserRecord],
        inactive_threshold: int = 90,
    ) -> None:
        self._records = records
        self._threshold = inactive_threshold
        for r in self._records:
            r.flag_issues(inactive_threshold)

    @property
    def flagged(self) -> list[UserRecord]:
        return [r for r in self._records if r.issues]

    def _stats(self) -> dict[str, int]:
        return {
            "total":         len(self._records),
            "enabled":       sum(1 for r in self._records if r.enabled),
            "disabled":      sum(1 for r in self._records if not r.enabled),
            "flagged":       len(self.flagged),
            "inactive":      sum(1 for r in self._records if r.issues and any("Inactive" in i for i in r.issues)),
            "no_password":   sum(1 for r in self._records if not r.has_password),
            "admins":        sum(1 for r in self._records if r.is_admin),
            "never_expires": sum(1 for r in self._records if r.password_never_expires),
        }

    def to_json(self, indent: int = 2) -> str:
        stats   = self._stats()
        payload = {
            "generated_at":       datetime.now().isoformat(),
            "platform":           platform.system(),
            "hostname":           platform.node(),
            "inactive_threshold": self._threshold,
            "stats":              stats,
            "flagged_users":      [r.to_dict() for r in self.flagged],
            "all_users":          [r.to_dict() for r in self._records],
        }
        return json.dumps(payload, indent=indent, default=str)

    def to_html(self) -> str:
        try:
            from jinja2 import Environment, BaseLoader
        except ImportError:
            raise ImportError(
                "jinja2 is required for HTML output. "
                "Install it: pip install jinja2"
            )
        env  = Environment(loader=BaseLoader())
        tmpl = env.from_string(_HTML_TEMPLATE)
        return tmpl.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            platform=platform.system(),
            hostname=platform.node(),
            stats=self._stats(),
            users=self._records,
            flagged_users=self.flagged,
        )

    def save(self, output_path: Path, fmt: str) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            output_path.write_text(self.to_json(), encoding="utf-8")
        elif fmt == "html":
            output_path.write_text(self.to_html(), encoding="utf-8")
        logger.info("Report saved: %s", output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit local user accounts and produce JSON/HTML reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--format", default="json,html",
        help='Output format(s), comma-separated: "json", "html", or "json,html" (default: json,html)',
    )
    parser.add_argument(
        "--output", default=None,
        help="Output file path (used when exactly one format is requested)",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (used when multiple formats are requested; default: current dir)",
    )
    parser.add_argument(
        "--inactive-days", type=int, default=90,
        help="Days of inactivity before an account is flagged (default: 90)",
    )
    parser.add_argument(
        "--include-system", action="store_true",
        help="Linux only: include system accounts (UID < 1000)",
    )
    parser.add_argument(
        "--min-uid", type=int, default=1000,
        help="Linux only: minimum UID for regular users (default: 1000)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Choose auditor based on platform
    system = platform.system()
    if system == "Linux":
        auditor = LinuxAuditor(
            min_uid=args.min_uid,
            include_system=args.include_system,
        )
    elif system == "Windows":
        auditor = WindowsAuditor()
    else:
        logger.error("Unsupported platform: %s (supported: Linux, Windows)", system)
        sys.exit(1)

    logger.info("Starting user audit on %s (%s)", platform.node(), system)
    records  = auditor.collect()
    reporter = AuditReporter(records, inactive_threshold=args.inactive_days)

    stats = reporter._stats()
    logger.info(
        "Audit complete: %d users, %d flagged, %d inactive, %d no-password, %d admins",
        stats["total"], stats["flagged"], stats["inactive"],
        stats["no_password"], stats["admins"],
    )

    formats = [f.strip().lower() for f in args.format.split(",")]
    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt in formats:
        if fmt not in ("json", "html"):
            logger.error("Unknown format '%s' — use 'json' or 'html'", fmt)
            continue

        if args.output and len(formats) == 1:
            out_path = Path(args.output)
        else:
            out_path = output_dir / f"user_audit_{ts}.{fmt}"

        reporter.save(out_path, fmt)
        print(f"Report written: {out_path}")

    if reporter.flagged:
        print(f"\n  {stats['flagged']} flagged account(s) found — review the report.")
        sys.exit(2)


if __name__ == "__main__":
    main()
