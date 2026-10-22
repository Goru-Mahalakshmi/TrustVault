import asyncio, logging, smtplib
from email.message import EmailMessage
from src.core.config import settings

log = logging.getLogger("trustvault.email")
OUTBOX: list[dict] = []          # used only by the "memory" backend (tests)

def _smtp_send(msg: EmailMessage):
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as s:
        s.starttls()
        if settings.SMTP_USER:
            s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        s.send_message(msg)

async def send_email(to: str, subject: str, body: str) -> None:
    """Never raises: a mail failure must not change the HTTP response (that would be an enumeration oracle)."""
    try:
        if settings.EMAIL_BACKEND == "memory":
            OUTBOX.append({"to": to, "subject": subject, "body": body})
        elif settings.EMAIL_BACKEND == "smtp" and settings.SMTP_HOST:
            msg = EmailMessage(); msg["From"], msg["To"], msg["Subject"] = settings.SMTP_FROM, to, subject
            msg.set_content(body)
            await asyncio.to_thread(_smtp_send, msg)
        else:   # console: DEV ONLY, prints the link so you can click it locally
            print(f"\n--- EMAIL to {to} ---\n{subject}\n{body}\n---------------------\n")
    except Exception:
        log.exception("email delivery failed")

async def send_reset_email(to: str, raw_token: str):
    await send_email(to, "TrustVault password reset",
                     f"Use this link within 15 minutes (single use):\n{settings.APP_BASE_URL}/#reset={raw_token}\n"
                     "If you did not ask for this, ignore this email.")

async def send_email_change_email(old_email: str, raw_token: str, new_email: str):
    await send_email(old_email, "Confirm your TrustVault email change",
                     f"A change of your login email to {new_email} was requested.\n"
                     f"Confirm within 15 minutes:\n{settings.APP_BASE_URL}/#confirm-email={raw_token}\n"
                     "If this was not you, change your password now.")
