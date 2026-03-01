# System Admin — Automation Scripts

A collection of Python and Bash scripts to automate system administration tasks across Linux and Windows, covering:

- **User Management** — batch create/delete users, group management, account auditing
- **Incremental Backups** — rsync-based (Linux) and robocopy/shutil-based (Windows) with retention and integrity checks
- **Network Service Monitoring** — ping, TCP, HTTP checks with alerting and a web dashboard

## Repository Structure

```
system-admin/
├── users/           # User management (Linux Bash + Windows PowerShell + audit Python)
├── backup/          # Incremental backups (Linux rsync + Windows robocopy)
├── monitoring/      # Service monitoring, alerting, dashboard
├── common/          # Shared utilities: logger, config loader, notifier
└── tests/           # pytest unit + integration tests
```

## Quick Start

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

Copy and edit the relevant config files:

```bash
cp backup/config/backup_config.yaml backup/config/backup_config.local.yaml
cp monitoring/config/services.yaml monitoring/config/services.local.yaml
```

### 3. Run monitoring

```bash
python monitoring/monitor_services.py --config monitoring/config/services.yaml
```

### 4. Run backup (Linux)

```bash
bash backup/linux/backup_incremental.sh
```

### 5. Audit users

```bash
python users/linux/audit_users.py --output report.html
```

## Modules

### common/logger.py
Unified logging with file rotation and console output. Used by all scripts.

### common/config_loader.py
Loads and validates YAML configuration files.

### common/notifier.py
Sends email (SMTP) and optional Slack/Telegram notifications.

## Requirements

- Python 3.10+
- Linux: bash, rsync, useradd/userdel
- Windows: PowerShell 5+, robocopy (built-in)

## Running Tests

```bash
pytest tests/ -v
```

## License

MIT — see [LICENSE](LICENSE)
