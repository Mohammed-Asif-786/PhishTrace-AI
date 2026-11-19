from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from datetime import datetime, timezone
import pytest


FIXTURES = Path(__file__).parent / "fixtures"
FIXTURES.mkdir(parents=True, exist_ok=True)


def write_eml(name: str, msg: EmailMessage) -> Path:
    path = FIXTURES / name
    path.write_bytes(msg.as_bytes())
    return path


@pytest.fixture(scope="session", autouse=True)
def generate_fixtures():
    classic = EmailMessage()
    classic["From"] = "PayPal Security <service@paypa1.com>"
    classic["Return-Path"] = "<bounce@mailer.example.net>"
    classic["Reply-To"] = "support@paypa1-security.example"
    classic["To"] = "customer@example.org"
    classic["Subject"] = "Urgent: account suspended"
    classic["Message-ID"] = "<classic@example.net>"
    classic["Date"] = format_datetime(datetime.now(timezone.utc))
    classic["Authentication-Results"] = "mx.example; spf=fail; dkim=fail; dmarc=fail"
    classic["Received"] = "from mail.paypa1.com ([203.0.113.10]) by mx.example; Thu, 19 Nov 2026 12:00:00 +0000"
    classic["Received"] = "from relay.example ([8.8.8.8]) by mail.paypa1.com; Thu, 19 Nov 2026 13:00:00 +0000"
    classic.set_content("URGENT: verify your password immediately or your account will be suspended.")
    write_eml("classic-phish.eml", classic)

    legit = EmailMessage()
    legit["From"] = "Support <support@example.com>"
    legit["Return-Path"] = "<support@example.com>"
    legit["Reply-To"] = "support@example.com"
    legit["To"] = "customer@example.org"
    legit["Subject"] = "Your monthly statement"
    legit["Authentication-Results"] = "mx.example; spf=pass; dkim=pass; dmarc=pass"
    legit["Received"] = "from mail.example ([10.0.0.1]) by mx.example; Thu, 19 Nov 2026 12:00:00 +0000"
    legit.set_content("Hello, your monthly statement is attached.")
    write_eml("legit.eml", legit)

    no_hops = EmailMessage()
    no_hops["From"] = "PayPal <service@paypal-security.example>"
    no_hops["Return-Path"] = "<bounce@attacker.example>"
    no_hops["Authentication-Results"] = "mx.example; spf=fail; dmarc=fail"
    no_hops["Subject"] = "Verify now"
    no_hops.set_content("Your account is suspended. Enter your password now.")
    write_eml("no-hops.eml", no_hops)

    single = EmailMessage()
    single["From"] = "Sender <sender@example.com>"
    single["To"] = "receiver@example.com"
    single["Subject"] = "One hop"
    single["Authentication-Results"] = "mx.example; spf=pass"
    single["Received"] = "from mail.example ([8.8.8.8]) by mx.example; Thu, 19 Nov 2026 12:00:00 +0000"
    single.set_content("Normal message.")
    write_eml("single-hop.eml", single)

    ipv6 = EmailMessage()
    ipv6["From"] = "Sender <sender@example.com>"
    ipv6["Subject"] = "IPv6"
    ipv6["Received"] = "from mail.example ([2001:4860:4860::8888]) by mx.example; Thu, 19 Nov 2026 12:00:00 +0000"
    ipv6.set_content("Normal message.")
    write_eml("ipv6.eml", ipv6)

    html_only = EmailMessage()
    html_only["From"] = "sender@example.com"
    html_only["Subject"] = "HTML"
    html_only.set_content("<p>Hello</p>", subtype="html")
    write_eml("html-only.eml", html_only)

    encoded = EmailMessage()
    encoded["From"] = "sender@example.com"
    encoded["Subject"] = "Encoded"
    encoded.set_content("Normal encoded body.")
    encoded.set_payload(encoded.get_payload(), charset="utf-8")
    write_eml("encoded.eml", encoded)

    empty = EmailMessage()
    empty["Subject"] = "Empty"
    empty.set_content("")
    write_eml("empty.eml", empty)
    write_eml("binary.eml", type("M", (), {"as_bytes": lambda self: b"\xff\xfe\x00\x80garbage"})())

    reply_spoof = EmailMessage()
    reply_spoof["From"] = "Microsoft Security <security@example.com>"
    reply_spoof["Reply-To"] = "reply@microsoft-support.example"
    reply_spoof["Received"] = "from mail.example ([8.8.8.8]) by mx.example; Thu, 19 Nov 2026 12:00:00 +0000"
    reply_spoof.set_content("Here is the requested document.")
    write_eml("reply-spoof.eml", reply_spoof)

    long_subject = "A" * 400
    non_utf = b"From: sender@example.com\r\nSubject: " + "caf\xc3\xa9".encode("latin1") + b"\r\n\r\nBody\r\n"
    (FIXTURES / "non-utf8.eml").write_bytes(non_utf)
