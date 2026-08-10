"""Exercise SimpleLogin forwarding and reply delivery through Mailpit."""

import json
import os
import smtplib
import time
import urllib.request
from email.message import EmailMessage


SMTP_HOST = os.environ.get("SIMPLELOGIN_SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.environ.get("SIMPLELOGIN_SMTP_PORT", "20381"))
MAILPIT_URL = os.environ.get("SIMPLELOGIN_MAILPIT_URL", "http://127.0.0.1:18025")
ALIAS = os.environ["SIMPLELOGIN_MAIL_ALIAS"]
MAILBOX = os.environ["SIMPLELOGIN_MAILBOX"]
CONTACT = os.environ["SIMPLELOGIN_MAIL_CONTACT"]
REVERSE_ALIAS = os.environ["SIMPLELOGIN_REVERSE_ALIAS"]


def send(sender: str, recipient: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.send_message(message, from_addr=sender, to_addrs=[recipient])


def wait_for_mail(subject: str, recipient: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with urllib.request.urlopen(
            f"{MAILPIT_URL}/api/v1/messages?limit=100", timeout=5
        ) as response:
            payload = json.load(response)
        for message in payload.get("messages", []):
            if message.get("Subject") != subject:
                continue
            if recipient.lower() in json.dumps(message).lower():
                return
        time.sleep(0.5)
    raise AssertionError(f"Mailpit did not receive {subject!r} for {recipient!r}")


nonce = str(time.time_ns())
forward_subject = f"simplelogin-forward-{nonce}"
send(CONTACT, ALIAS, forward_subject, "forward lifecycle")
wait_for_mail(forward_subject, MAILBOX)

reply_subject = f"simplelogin-reply-{nonce}"
send(MAILBOX, REVERSE_ALIAS, reply_subject, "reply lifecycle")
wait_for_mail(reply_subject, CONTACT)

print("mail forwarding and reverse-alias reply: ok")
