"""Exercise SimpleLogin forwarding and reply delivery through Mailpit."""

import json
import os
import smtplib
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from urllib.parse import urlsplit


SMTP_HOST = os.environ.get("SIMPLELOGIN_SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.environ.get("SIMPLELOGIN_SMTP_PORT", "20381"))
MAILPIT_URL = os.environ.get("SIMPLELOGIN_MAILPIT_URL", "http://127.0.0.1:18025")
ALIAS = os.environ["SIMPLELOGIN_MAIL_ALIAS"]
MAILBOX = os.environ["SIMPLELOGIN_MAILBOX"]
CONTACT = os.environ["SIMPLELOGIN_MAIL_CONTACT"]
REVERSE_ALIAS = os.environ["SIMPLELOGIN_REVERSE_ALIAS"]
MAX_RESPONSE_BYTES = 1_048_576


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, url):
        raise urllib.error.HTTPError(
            request.full_url, code, "redirect refused", headers, file_pointer
        )


parsed_mailpit_url = urlsplit(MAILPIT_URL)
if (
    parsed_mailpit_url.scheme != "http"
    or parsed_mailpit_url.hostname not in {"127.0.0.1", "localhost", "::1"}
    or parsed_mailpit_url.username is not None
    or parsed_mailpit_url.password is not None
    or parsed_mailpit_url.query
    or parsed_mailpit_url.fragment
):
    raise ValueError(
        "SIMPLELOGIN_MAILPIT_URL must be a credential-free loopback HTTP URL"
    )
if SMTP_HOST not in {"127.0.0.1", "localhost", "::1"}:
    raise ValueError("SIMPLELOGIN_SMTP_HOST must be loopback")

http = urllib.request.build_opener(NoRedirects)


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
        with http.open(f"{MAILPIT_URL}/api/v1/messages?limit=100", timeout=5) as response:
            encoded = response.read(MAX_RESPONSE_BYTES + 1)
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise ValueError("Mailpit response exceeded the 1 MiB test limit")
        payload = json.loads(encoded)
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
