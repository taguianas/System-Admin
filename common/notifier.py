"""
common/notifier.py
Notification sender — SMTP email, Slack webhook, Telegram bot.

All channels are optional.  Configure them via the project's YAML config
or directly via environment variables (useful in CI/CD).

Environment variables (override YAML config):
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO
    SLACK_WEBHOOK_URL
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

Usage
-----
    from common.notifier import Notifier
    from common.config_loader import load_config

    cfg = load_config("monitoring/config/services.yaml")
    notifier = Notifier(cfg.get("notifications", {}))
    notifier.send("Backup failed on web-01", body="rsync exited with code 23")
"""

import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any
from urllib import request as urllib_request
from urllib.error import URLError
import json

from common.logger import get_logger

logger = get_logger(__name__)


class Notifier:
    """
    Sends notifications over one or more channels.

    Parameters
    ----------
    config : dict
        Notification section from the YAML config.  Shape::

            notifications:
              email:
                host: smtp.example.com
                port: 587
                user: alerts@example.com
                password: ${SMTP_PASSWORD}
                from: alerts@example.com
                to:
                  - admin@example.com
                tls: true
              slack:
                webhook_url: ${SLACK_WEBHOOK_URL}
              telegram:
                bot_token: ${TELEGRAM_BOT_TOKEN}
                chat_id: "12345678"
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._cfg = config or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, subject: str, body: str = "", html_body: str = "") -> None:
        """
        Send a notification to all configured channels.

        Parameters
        ----------
        subject:
            Short one-line summary (used as email subject / Slack/Telegram heading).
        body:
            Plain-text message body.
        html_body:
            Optional HTML body for email.  Falls back to plain ``body`` if empty.
        """
        sent_any = False

        if self._email_configured():
            try:
                self._send_email(subject, body, html_body)
                sent_any = True
            except Exception as exc:
                logger.error("Email notification failed: %s", exc)

        if self._slack_configured():
            try:
                self._send_slack(subject, body)
                sent_any = True
            except Exception as exc:
                logger.error("Slack notification failed: %s", exc)

        if self._telegram_configured():
            try:
                self._send_telegram(subject, body)
                sent_any = True
            except Exception as exc:
                logger.error("Telegram notification failed: %s", exc)

        if not sent_any:
            logger.warning(
                "No notification channels configured — alert not sent: %s", subject
            )

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    def _email_configured(self) -> bool:
        email_cfg = self._cfg.get("email", {})
        host = os.environ.get("SMTP_HOST") or email_cfg.get("host", "")
        recipients = os.environ.get("SMTP_TO") or email_cfg.get("to", [])
        return bool(host and recipients)

    def _send_email(self, subject: str, body: str, html_body: str) -> None:
        email_cfg = self._cfg.get("email", {})

        host = os.environ.get("SMTP_HOST") or email_cfg.get("host")
        port = int(os.environ.get("SMTP_PORT") or email_cfg.get("port", 587))
        user = os.environ.get("SMTP_USER") or email_cfg.get("user", "")
        password = os.environ.get("SMTP_PASSWORD") or email_cfg.get("password", "")
        sender = os.environ.get("SMTP_FROM") or email_cfg.get("from", user)
        use_tls = email_cfg.get("tls", True)

        raw_to = os.environ.get("SMTP_TO") or email_cfg.get("to", [])
        recipients: list[str] = (
            [r.strip() for r in raw_to.split(",")] if isinstance(raw_to, str) else raw_to
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)

        msg.attach(MIMEText(body, "plain", "utf-8"))
        if html_body:
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        context = ssl.create_default_context()

        logger.info("Sending email to %s via %s:%d", recipients, host, port)

        if use_tls:
            with smtplib.SMTP(host, port) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                if user and password:
                    smtp.login(user, password)
                smtp.sendmail(sender, recipients, msg.as_string())
        else:
            with smtplib.SMTP(host, port) as smtp:
                if user and password:
                    smtp.login(user, password)
                smtp.sendmail(sender, recipients, msg.as_string())

        logger.info("Email sent: %s", subject)

    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------

    def _slack_configured(self) -> bool:
        slack_cfg = self._cfg.get("slack", {})
        webhook = os.environ.get("SLACK_WEBHOOK_URL") or slack_cfg.get("webhook_url", "")
        return bool(webhook)

    def _send_slack(self, subject: str, body: str) -> None:
        slack_cfg = self._cfg.get("slack", {})
        webhook = os.environ.get("SLACK_WEBHOOK_URL") or slack_cfg.get("webhook_url")

        text = f"*{subject}*"
        if body:
            text += f"\n{body}"

        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib_request.Request(
            webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=10) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Slack returned HTTP {resp.status}")
        except URLError as exc:
            raise RuntimeError(f"Slack webhook request failed: {exc}") from exc

        logger.info("Slack notification sent: %s", subject)

    # ------------------------------------------------------------------
    # Telegram
    # ------------------------------------------------------------------

    def _telegram_configured(self) -> bool:
        tg_cfg = self._cfg.get("telegram", {})
        token = os.environ.get("TELEGRAM_BOT_TOKEN") or tg_cfg.get("bot_token", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID") or tg_cfg.get("chat_id", "")
        return bool(token and chat_id)

    def _send_telegram(self, subject: str, body: str) -> None:
        tg_cfg = self._cfg.get("telegram", {})
        token = os.environ.get("TELEGRAM_BOT_TOKEN") or tg_cfg.get("bot_token")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID") or tg_cfg.get("chat_id")

        text = f"<b>{subject}</b>"
        if body:
            text += f"\n{body}"

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
        }).encode("utf-8")

        req = urllib_request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=10) as resp:
                response_data = json.loads(resp.read())
                if not response_data.get("ok"):
                    raise RuntimeError(f"Telegram API error: {response_data}")
        except URLError as exc:
            raise RuntimeError(f"Telegram request failed: {exc}") from exc

        logger.info("Telegram notification sent: %s", subject)
