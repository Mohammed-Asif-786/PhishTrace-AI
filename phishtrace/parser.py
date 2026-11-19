from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from typing import Iterable

try:
    import dns.resolver
except ImportError:
    dns = None

from .config import DNS_TIMEOUT

LOGGER = logging.getLogger(__name__)


@dataclass
class Hop:
    index: int
    from_host: str
    by_host: str
    ip: str | None
    timestamp: str | None


@dataclass
class AuthStatus:
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"
    spf_header: str = "missing"
    dkim_header: str = "missing"
    dmarc_header: str = "missing"
    spf_dns: str = "unknown"
    dkim_dns: str = "unknown"
    dmarc_dns: str = "unknown"


@dataclass
class ParsedEmail:
    from_name: str
    from_address: str
    from_domain: str
    return_path: str
    reply_to: str
    to: list[str]
    subject: str
    message_id: str
    date: str
    plain_text: str
    stripped_html: str
    urls: list[str]
    attachment_names: list[str]
    attachment_hashes: list[str]
    hops: list[Hop]
    auth: AuthStatus
    identity_checks: dict[str, object] = field(default_factory=dict)
    routing_anomalies: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])")
SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                   "buff.ly", "rebrand.ly", "cutt.ly"}


def _decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    chunks = []
    for text, encoding in decode_header(value):
        if isinstance(text, bytes):
            try:
                chunks.append(text.decode(encoding or "utf-8", errors="replace"))
            except LookupError:
                chunks.append(text.decode("utf-8", errors="replace"))
        else:
            chunks.append(text)
    return "".join(chunks).strip()


def _domain(address: str) -> str:
    address = address.strip().strip("<>")
    parsed = parseaddr(address)[1]
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[1].lower().strip(".")


def _public_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip("[]() ")
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if parsed.is_global:
        return str(parsed)
    return None


def _extract_received(value: str, index: int) -> Hop:
    from_match = re.search(r"\bfrom\s+([^\s;]+)", value, re.I)
    by_match = re.search(r"\bby\s+([^\s;]+)", value, re.I)
    ip_match = re.search(r"\[([^\]]+)\]", value)
    ip = None
    if ip_match:
        ip = _public_ip(ip_match.group(1))
    if ip is None:
        for token in re.findall(r"[^\s;]+", value):
            ip = _public_ip(token.strip("[](),"))
            if ip:
                break
    timestamp_match = re.search(r";\s*(.+)$", value)
    timestamp = timestamp_match.group(1).strip() if timestamp_match else None
    if timestamp:
        try:
            parsed = parsedate_to_datetime(timestamp)
            timestamp = parsed.isoformat() if parsed else timestamp
        except (TypeError, ValueError, OverflowError):
            pass
    return Hop(index, from_match.group(1).strip("[]") if from_match else "",
               by_match.group(1).strip("[]") if by_match else "", ip, timestamp)


def _parse_auth_headers(msg) -> AuthStatus:
    status = AuthStatus()
    allowed = {"pass", "fail", "softfail", "none", "neutral", "missing", "unknown"}
    ar = _decode_header_value(msg.get("Authentication-Results"))
    spf = _decode_header_value(msg.get("Received-SPF"))

    def auth_result(text: str, mechanism: str) -> str:
        match = re.search(rf"\b{mechanism}\s*=\s*(\w+)", text, re.I)
        if not match:
            return "missing"
        result = match.group(1).lower()
        if result in {"pass", "fail", "softfail", "none", "neutral"}:
            return result
        return "missing"

    status.spf_header = auth_result(spf, "spf")
    if not ar:
        status.spf_header = auth_result(spf, "none") if spf and "=" not in spf else status.spf_header
    else:
        status.spf_header = auth_result(ar, "spf")
        status.dkim_header = auth_result(ar, "dkim")
        status.dmarc_header = auth_result(ar, "dmarc")
    if "spf=" not in (spf or "").lower() and spf:
        first = re.match(r"\s*(\w+)", spf)
        if first and first.group(1).lower() in allowed:
            status.spf_header = first.group(1).lower()

    for field_name, header_name in (
        ("spf", "spf"), ("dkim", "dkim"), ("dmarc", "dmarc")
    ):
        result = getattr(status, f"{field_name}_header")
        setattr(status, field_name, result if result != "missing" else "missing")
    return status


def _dns_auth(sender_domain: str) -> AuthStatus:
    result = AuthStatus()
    if not sender_domain or dns is None:
        return result
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    try:
        resolver.resolve(sender_domain, "MX")
        result.dkim_dns = "none"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    try:
        resolver.resolve("_dmarc." + sender_domain, "TXT")
        result.dmarc_dns = "pass"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    try:
        texts = resolver.resolve(sender_domain, "TXT")
        found_spf = any("spf1" in str(record).lower() for record in texts)
        result.spf_dns = "pass" if found_spf else "none"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    return result


def _levenshtein(left: str, right: str) -> int:
    if len(left) < len(right):
        return _levenshtein(right, left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, 1):
        current = [i]
        for j, right_char in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[j] + 1,
                               previous[j - 1] + (left_char != right_char)))
        previous = current
    return previous[-1]


def _identity_checks(from_name: str, from_address: str, return_path: str,
                     reply_to: str) -> dict[str, object]:
    from_domain = _domain(from_address)
    return_domain = _domain(return_path)
    reply_domain = _domain(reply_to)
    name_addresses = [address.lower() for _, address in getaddresses([from_name])]
    name_domains = [_domain(address) for address in name_addresses if address]
    spoofed = any(address and address != from_address.lower() for address in name_addresses)
    if spoofed and not name_domains:
        name_domains = name_domains

    homoglyph = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a"})
    lookalikes = []
    candidate = re.sub(r"[^a-z]", "", from_domain.lower().split(".")[0].translate(homoglyph))
    for brand in __import__("phishtrace.config", fromlist=["KNOWN_BRANDS"]).KNOWN_BRANDS:
        if candidate != brand and (_levenshtein(candidate, brand) <= 2):
            lookalikes.append(brand)

    return {
        "from_return_path_mismatch": bool(return_domain and from_domain and return_domain != from_domain),
        "reply_to_mismatch": bool(reply_domain and from_domain and reply_domain != from_domain),
        "display_name_spoofing": spoofed,
        "lookalike_domains": lookalikes,
        "from_domain": from_domain,
        "return_path_domain": return_domain,
        "reply_to_domain": reply_domain,
    }


def parse_email(file_bytes: bytes) -> ParsedEmail:
    warnings: list[str] = []
    if not file_bytes:
        return ParsedEmail(
            from_name="", from_address="", from_domain="", return_path="", reply_to="",
            to=[], subject="", message_id="", date="", plain_text="", stripped_html="",
            urls=[], attachment_names=[], attachment_hashes=[], hops=[], auth=AuthStatus(),
            identity_checks={}, routing_anomalies=["No Received headers (possible hop stripping)"],
            warnings=["Empty file"],
        )
    try:
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
    except Exception as exc:
        LOGGER.exception("Email parsing failed")
        warnings.append("Could not fully parse the email: " + type(exc).__name__)
        msg = BytesParser(policy=policy.default).parsebytes(b"")

    def header(name: str) -> str:
        return _decode_header_value(msg.get(name))

    from_name, from_address = parseaddr(header("From"))
    from_name = _decode_header_value(from_name)
    from_address = from_address.lower()
    return_path = header("Return-Path")
    reply_to = header("Reply-To")
    to_addresses = [address for _, address in getaddresses(msg.get_all("To", []))]
    subject = header("Subject")
    if not subject:
        subject = ""
    if len(file_bytes) > 50_000_000:
        warnings.append("File is unusually large")

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachment_names: list[str] = []
    attachment_hashes: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachment_names.append(_decode_header_value(filename))
            payload = part.get_payload(decode=True)
            if payload:
                attachment_hashes.append(hashlib.sha256(payload).hexdigest())
        try:
            content = part.get_payload(decode=True)
            if content is not None:
                charset = part.get_content_charset() or "utf-8"
                decoded = content.decode(charset, errors="replace")
            else:
                decoded = str(part.get_payload() or "")
        except (LookupError, UnicodeDecodeError):
            payload = part.get_payload(decode=True)
            decoded = payload.decode("utf-8", errors="replace") if payload else ""
            warnings.append("A body part used an unknown encoding")
        if part.get_content_type() == "text/html":
            html_parts.append(decoded)
        elif part.get_content_type() == "text/plain":
            text_parts.append(decoded)

    html = "\n".join(html_parts)
    extractor = _TextExtractor()
    try:
        extractor.feed(unescape(html))
    except Exception:
        warnings.append("HTML body could not be fully stripped")
    stripped_html = " ".join(" ".join(extractor.parts).split())
    plain_text = "\n".join(text_parts).strip()
    if not plain_text and stripped_html:
        plain_text = stripped_html

    urls = list(dict.fromkeys(URL_RE.findall(html + "\n" + plain_text)))
    received = msg.get_all("Received", [])
    newest_to_oldest = [_extract_received(_decode_header_value(item), i + 1)
                        for i, item in enumerate(received)]
    hops = list(reversed(newest_to_oldest))
    for i, hop in enumerate(hops, 1):
        hop.index = i

    auth = _parse_auth_headers(msg)
    sender_domain = _domain(from_address)
    dns_result = _dns_auth(sender_domain)
    auth.spf_dns = dns_result.spf_dns
    auth.dkim_dns = dns_result.dkim_dns
    auth.dmarc_dns = dns_result.dmarc_dns
    for field_name in ("spf", "dkim", "dmarc"):
        if getattr(auth, field_name) == "missing":
            dns_value = getattr(auth, f"{field_name}_dns")
            setattr(auth, field_name, dns_value if dns_value != "unknown" else "missing")

    identity = _identity_checks(from_name, from_address, return_path, reply_to)
    anomalies: list[str] = []
    if not received:
        anomalies.append("No Received headers (possible hop stripping)")
    elif len(hops) == 1:
        anomalies.append("Only one Received hop")
    if len(hops) > 10:
        anomalies.append("Unusually high hop count")

    timestamps = []
    for hop in hops:
        if hop.timestamp:
            try:
                timestamps.append(parsedate_to_datetime(hop.timestamp))
            except (TypeError, ValueError, OverflowError):
                pass
    for earlier, later in zip(timestamps, timestamps[1:]):
        if earlier and later and later < earlier:
            anomalies.append("Received timestamps go backwards")
            break
    for hop in hops:
        combined = (hop.from_host + " " + hop.by_host).lower()
        if hop.ip and ("localhost" in combined or re.search(r"\b(?:helo|ehlo)\b", combined)):
            anomalies.append("Localhost or HELO IP-literal routing with a public IP")
            break

    raw_headers = {name: header(name) for name in
                   ("From", "Return-Path", "Reply-To", "To", "Subject",
                    "Message-ID", "Date", "Authentication-Results", "Received-SPF")
                   if msg.get(name) is not None}
    return ParsedEmail(
        from_name=from_name,
        from_address=from_address,
        from_domain=sender_domain,
        return_path=return_path,
        reply_to=reply_to,
        to=to_addresses,
        subject=subject,
        message_id=header("Message-ID"),
        date=header("Date"),
        plain_text=plain_text,
        stripped_html=stripped_html,
        urls=urls,
        attachment_names=attachment_names,
        attachment_hashes=attachment_hashes,
        hops=hops,
        auth=auth,
        identity_checks=identity,
        routing_anomalies=anomalies,
        warnings=warnings,
        raw_headers=raw_headers,
    )
