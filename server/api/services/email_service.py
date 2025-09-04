# server/api/services/email_service.py
import ssl, smtplib, os
from email.message import EmailMessage
from ..core.config import settings

def send_email(to_email: str, subject: str, html: str, text: str | None = None):
    # If SMTP not configured -> print to console (dev mode)
    if not (settings.SMTP_HOST and settings.SMTP_PORT):
        print("\n--- ConsoleEmail (SMTP not configured) ---")
        print("To:", to_email)
        print("Subject:", subject)
        print("Body(HTML):", html)
        print("--- /ConsoleEmail ---\n")
        return

    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text or "Open with an HTML mail client.")
    msg.add_alternative(html, subtype="html")

    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(settings.SMTP_HOST, int(settings.SMTP_PORT), context=ctx) as s:
        if settings.SMTP_USER:
            s.login(settings.SMTP_USER, settings.SMTP_PASS)
        s.send_message(msg)
