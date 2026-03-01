"""
tests/test_users.py
Unit tests for users/linux/audit_users.py

Tests cover:
  - UserRecord.flag_issues() logic
  - LinuxAuditor parsers (_parse_passwd, _parse_shadow, _parse_groups)
  - LinuxAuditor._get_last_logins() via mocked subprocess
  - WindowsAuditor._safe_json_list() and _parse_win_datetime()
  - AuditReporter statistics, JSON output, and HTML output
"""

import json
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Resolve project root so imports work regardless of cwd
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

# Import the module under test (use linux path; both copies are identical)
sys.path.insert(0, str(_ROOT / "users" / "linux"))
from audit_users import (
    AuditReporter,
    LinuxAuditor,
    UserRecord,
    WindowsAuditor,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_user(**overrides) -> UserRecord:
    defaults = dict(
        username="alice",
        uid=1001,
        home_dir="/home/alice",
        shell="/bin/bash",
        enabled=True,
        last_login=None,
        days_since_login=None,
        has_password=True,
        password_never_expires=False,
        is_admin=False,
        groups=["developers"],
        issues=[],
    )
    defaults.update(overrides)
    return UserRecord(**defaults)


# ---------------------------------------------------------------------------
# UserRecord.flag_issues()
# ---------------------------------------------------------------------------

class TestFlagIssues:
    def test_clean_user_has_no_issues(self):
        u = make_user(days_since_login=10)
        u.flag_issues()
        assert u.issues == []

    def test_inactive_user_flagged(self):
        u = make_user(days_since_login=91)
        u.flag_issues(inactive_threshold=90)
        assert any("Inactive" in i for i in u.issues)

    def test_inactive_at_threshold_not_flagged(self):
        u = make_user(days_since_login=90)
        u.flag_issues(inactive_threshold=90)
        assert not any("Inactive" in i for i in u.issues)

    def test_never_logged_in_flagged(self):
        u = make_user(days_since_login=None, last_login=None)
        u.flag_issues()
        assert any("Never" in i for i in u.issues)

    def test_no_password_flagged(self):
        u = make_user(days_since_login=5, has_password=False)
        u.flag_issues()
        assert any("password" in i.lower() for i in u.issues)

    def test_admin_password_never_expires_flagged(self):
        u = make_user(days_since_login=5, is_admin=True, password_never_expires=True)
        u.flag_issues()
        assert any("never-expires" in i.lower() or "never" in i.lower() for i in u.issues)

    def test_non_admin_password_never_expires_not_flagged(self):
        u = make_user(days_since_login=5, is_admin=False, password_never_expires=True)
        u.flag_issues()
        assert not any("never" in i.lower() for i in u.issues)

    def test_disabled_user_never_flagged(self):
        # Disabled accounts are intentionally excluded from flagging
        u = make_user(enabled=False, days_since_login=365, has_password=False)
        u.flag_issues()
        assert u.issues == []

    def test_multiple_issues(self):
        u = make_user(
            days_since_login=200,
            has_password=False,
            is_admin=True,
            password_never_expires=True,
        )
        u.flag_issues()
        assert len(u.issues) >= 3

    def test_custom_threshold(self):
        u = make_user(days_since_login=40)
        u.flag_issues(inactive_threshold=30)
        assert any("Inactive" in i for i in u.issues)


# ---------------------------------------------------------------------------
# LinuxAuditor — parser unit tests
# ---------------------------------------------------------------------------

class TestLinuxAuditorParsers:
    def _make_auditor(self, **kwargs) -> LinuxAuditor:
        return LinuxAuditor(**kwargs)

    # -- _parse_passwd --

    def test_parse_passwd_basic(self, tmp_path):
        (tmp_path / "passwd").write_text(textwrap.dedent("""\
            root:x:0:0:root:/root:/bin/bash
            alice:x:1001:1001::/home/alice:/bin/bash
            bob:x:1002:1002::/home/bob:/bin/zsh
        """))
        auditor = self._make_auditor()
        result  = auditor._parse_passwd.__func__(auditor)  # call via instance
        # monkey-patch the method to use our tmp file
        with patch("builtins.open", side_effect=lambda p, *a, **kw: open(str(tmp_path / "passwd"), *a, **kw)):
            pass  # test via direct file mock below

    def test_parse_passwd_via_mock(self, tmp_path):
        passwd_content = textwrap.dedent("""\
            root:x:0:0:root:/root:/bin/bash
            alice:x:1001:1001::/home/alice:/bin/bash
            nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin
        """)
        passwd_file = tmp_path / "passwd"
        passwd_file.write_text(passwd_content)

        auditor = self._make_auditor()
        with patch("audit_users.Path") as mock_path_cls:
            mock_path_obj = MagicMock()
            mock_path_obj.exists.return_value = True
            mock_path_obj.read_text.return_value = passwd_content
            mock_path_cls.return_value = mock_path_obj

            result = auditor._parse_passwd()

        assert "root" in result
        assert result["root"]["uid"] == 0
        assert "alice" in result
        assert result["alice"]["home"] == "/home/alice"
        assert result["alice"]["shell"] == "/bin/bash"

    def test_parse_passwd_skips_malformed_lines(self):
        content = "alice:x:1001:1001::/home/alice:/bin/bash\nbadline\n"
        auditor = self._make_auditor()
        with patch("audit_users.Path") as mock_path_cls:
            mock = MagicMock()
            mock.exists.return_value = True
            mock.read_text.return_value = content
            mock_path_cls.return_value = mock
            result = auditor._parse_passwd()
        assert "alice" in result

    # -- _parse_shadow --

    def test_has_password_normal(self):
        auditor = self._make_auditor()
        assert auditor._has_password({"pw_hash": "$6$salt$hash"}) is True

    def test_has_password_locked_exclamation(self):
        auditor = self._make_auditor()
        assert auditor._has_password({"pw_hash": "!"}) is False

    def test_has_password_double_exclamation(self):
        auditor = self._make_auditor()
        assert auditor._has_password({"pw_hash": "!!"}) is False

    def test_has_password_star(self):
        auditor = self._make_auditor()
        assert auditor._has_password({"pw_hash": "*"}) is False

    def test_has_password_empty(self):
        auditor = self._make_auditor()
        assert auditor._has_password({"pw_hash": ""}) is False

    def test_has_password_no_shadow_data(self):
        # When shadow is unavailable, assume password exists
        auditor = self._make_auditor()
        assert auditor._has_password({}) is True

    def test_is_locked(self):
        auditor = self._make_auditor()
        assert auditor._is_locked({"pw_hash": "!$6$hash"}) is True
        assert auditor._is_locked({"pw_hash": "$6$hash"}) is False
        assert auditor._is_locked({}) is False

    def test_password_never_expires_99999(self):
        auditor = self._make_auditor()
        assert auditor._password_never_expires({"max_days": "99999"}) is True

    def test_password_never_expires_normal(self):
        auditor = self._make_auditor()
        assert auditor._password_never_expires({"max_days": "90"}) is False

    # -- _parse_groups --

    def test_parse_groups(self):
        content = textwrap.dedent("""\
            sudo:x:27:alice,bob
            developers:x:1003:alice,carol
            qa:x:1004:bob
        """)
        auditor = self._make_auditor()
        with patch("audit_users.Path") as mock_path_cls:
            mock = MagicMock()
            mock.exists.return_value = True
            mock.read_text.return_value = content
            mock_path_cls.return_value = mock
            result = auditor._parse_groups()

        assert "sudo" in result.get("alice", [])
        assert "developers" in result.get("alice", [])
        assert "sudo" in result.get("bob", [])
        assert "qa" in result.get("bob", [])
        assert "developers" in result.get("carol", [])

    # -- _get_last_logins --

    def test_get_last_logins_never(self):
        lastlog_output = (
            "Username         Port     From             Latest\n"
            "alice                                      **Never logged in**\n"
        )
        auditor = self._make_auditor()
        with patch("subprocess.check_output", return_value=lastlog_output):
            result = auditor._get_last_logins()
        assert "alice" in result
        assert result["alice"] is None

    def test_get_last_logins_date(self):
        lastlog_output = (
            "Username         Port     From             Latest\n"
            "alice            pts/0                     Mon Jan  6 14:23:00 +0000 2025\n"
        )
        auditor = self._make_auditor()
        with patch("subprocess.check_output", return_value=lastlog_output):
            result = auditor._get_last_logins()
        assert "alice" in result
        assert result["alice"] is not None
        assert result["alice"].year == 2025

    def test_get_last_logins_command_missing(self):
        import subprocess as sp
        auditor = self._make_auditor()
        with patch("subprocess.check_output", side_effect=FileNotFoundError):
            result = auditor._get_last_logins()
        assert result == {}


# ---------------------------------------------------------------------------
# WindowsAuditor helpers
# ---------------------------------------------------------------------------

class TestWindowsAuditorHelpers:
    def _auditor(self):
        return WindowsAuditor()

    def test_safe_json_list_with_list(self):
        a = self._auditor()
        assert a._safe_json_list('[{"Name":"alice"}]') == [{"Name": "alice"}]

    def test_safe_json_list_with_single_object(self):
        a = self._auditor()
        result = a._safe_json_list('{"Name":"alice"}')
        assert result == [{"Name": "alice"}]

    def test_safe_json_list_empty(self):
        a = self._auditor()
        assert a._safe_json_list("") == []
        assert a._safe_json_list("null") == []

    def test_safe_json_list_invalid(self):
        a = self._auditor()
        assert a._safe_json_list("{bad json}") == []

    def test_parse_win_datetime_slash(self):
        a = self._auditor()
        dt = a._parse_win_datetime("01/06/2025 02:30:00 PM")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 1

    def test_parse_win_datetime_iso(self):
        a = self._auditor()
        dt = a._parse_win_datetime("2025-01-06T14:30:00")
        assert dt is not None
        assert dt.year == 2025

    def test_parse_win_datetime_none(self):
        a = self._auditor()
        assert a._parse_win_datetime(None) is None
        assert a._parse_win_datetime("") is None


# ---------------------------------------------------------------------------
# AuditReporter
# ---------------------------------------------------------------------------

class TestAuditReporter:
    def _sample_records(self) -> list[UserRecord]:
        now = datetime.now()
        return [
            make_user(username="alice", days_since_login=10,     is_admin=True),
            make_user(username="bob",   days_since_login=100,    enabled=True),   # inactive
            make_user(username="carol", days_since_login=5,      has_password=False),
            make_user(username="dave",  days_since_login=None,   enabled=False),  # disabled
            make_user(username="eve",   days_since_login=200,    is_admin=True, password_never_expires=True),
        ]

    def test_stats_total(self):
        r = AuditReporter(self._sample_records())
        assert r._stats()["total"] == 5

    def test_stats_enabled_disabled(self):
        r = AuditReporter(self._sample_records())
        stats = r._stats()
        assert stats["enabled"] == 4
        assert stats["disabled"] == 1

    def test_stats_flagged(self):
        r = AuditReporter(self._sample_records())
        # bob (inactive), carol (no password), eve (inactive + admin pw-never-expires)
        assert r._stats()["flagged"] >= 3

    def test_stats_no_password(self):
        r = AuditReporter(self._sample_records())
        assert r._stats()["no_password"] == 1

    def test_stats_admins(self):
        r = AuditReporter(self._sample_records())
        assert r._stats()["admins"] == 2

    def test_flagged_excludes_disabled(self):
        r = AuditReporter(self._sample_records())
        flagged_names = {u.username for u in r.flagged}
        assert "dave" not in flagged_names

    def test_to_json_valid(self):
        r = AuditReporter(self._sample_records())
        output = r.to_json()
        data = json.loads(output)
        assert "stats" in data
        assert "all_users" in data
        assert "flagged_users" in data
        assert data["stats"]["total"] == 5

    def test_to_json_datetime_serialized(self):
        records = [make_user(last_login=datetime(2025, 1, 1, 12, 0, 0), days_since_login=30)]
        r = AuditReporter(records)
        output = r.to_json()
        data   = json.loads(output)
        last   = data["all_users"][0]["last_login"]
        assert "2025-01-01" in last

    def test_to_html_contains_table(self):
        pytest.importorskip("jinja2")
        r    = AuditReporter(self._sample_records())
        html = r.to_html()
        assert "<table>" in html
        assert "alice" in html
        assert "bob" in html

    def test_to_html_shows_flagged_section(self):
        pytest.importorskip("jinja2")
        r    = AuditReporter(self._sample_records())
        html = r.to_html()
        assert "Flagged Accounts" in html

    def test_save_json(self, tmp_path):
        r = AuditReporter(self._sample_records())
        out = tmp_path / "report.json"
        r.save(out, "json")
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["stats"]["total"] == 5

    def test_save_html(self, tmp_path):
        pytest.importorskip("jinja2")
        r = AuditReporter(self._sample_records())
        out = tmp_path / "report.html"
        r.save(out, "html")
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text()

    def test_custom_inactive_threshold(self):
        records = [make_user(username="alice", days_since_login=45)]
        r = AuditReporter(records, inactive_threshold=30)
        assert any("Inactive" in i for u in r.flagged for i in u.issues)

    def test_flagged_property_returns_only_flagged(self):
        records = [
            make_user(username="alice", days_since_login=10),   # clean
            make_user(username="bob",   days_since_login=200),  # inactive
        ]
        r = AuditReporter(records)
        assert len(r.flagged) == 1
        assert r.flagged[0].username == "bob"
