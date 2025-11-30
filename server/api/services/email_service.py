import ssl, smtplib
from email.message import EmailMessage
from ..core.config import settings

def send_email(to_email: str, subject: str, html: str, text: str | None = None):
    # SMTP 미설정 → 콘솔 출력(개발 모드)
    if not settings.SMTP_HOST or not settings.SMTP_PORT:
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

    # STARTTLS (예: 포트 587) vs SSL (예: 포트 465)
    if settings.SMTP_STARTTLS:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=ctx) as s:
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASS)
            s.send_message(msg)
