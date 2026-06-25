import os
import smtplib
from email.message import EmailMessage


class EmailSendError(Exception):
    pass


def send_smtp_email(to: str, subject: str, body: str) -> dict:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("SMTP_FROM_EMAIL", smtp_username)
    if not all([smtp_host, smtp_username, smtp_password, from_email]):
        raise EmailSendError("SMTP configuration is incomplete.")
    message = EmailMessage()
    message["From"] = from_email
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(message)
    return {"status": "sent", "to": to, "subject": subject}
