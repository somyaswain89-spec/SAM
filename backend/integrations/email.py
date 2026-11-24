from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from backend.core.config import SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_USERNAME


class EmailDeliveryNotConfigured(RuntimeError):
    pass


def send_password_reset(recipient: str, reset_url: str) -> None:
    if not SMTP_HOST or not SMTP_FROM:
        raise EmailDeliveryNotConfigured(
            "SMTP_HOST and SMTP_FROM must be configured to deliver reset links"
        )
    message = EmailMessage()
    message["Subject"] = "Reset your SAM password"
    message["From"] = SMTP_FROM
    message["To"] = recipient
    message.set_content(
        "A password reset was requested for your SAM account.\n\n"
        f"Use this one-time link within 30 minutes: {reset_url}\n\n"
        "If you did not request this, ignore this message."
    )
    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=8, context=context) as client:
            if SMTP_USERNAME:
                client.login(SMTP_USERNAME, SMTP_PASSWORD)
            client.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as client:
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
            if SMTP_USERNAME:
                client.login(SMTP_USERNAME, SMTP_PASSWORD)
            client.send_message(message)
