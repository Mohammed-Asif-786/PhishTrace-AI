from pathlib import Path

from phishtrace.parser import parse_email


FIXTURES = Path(__file__).parent / "fixtures"


def read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_classic_parser_extracts_identity_auth_and_hops():
    email = parse_email(read("classic-phish.eml"))
    assert email.from_domain == "paypa1.com"
    assert email.auth.spf_header == "fail"
    assert email.auth.dmarc_header == "fail"
    assert email.identity_checks["from_return_path_mismatch"]
    assert len(email.hops) >= 1
    assert all(hop.ip is None or hop.ip.startswith(("8.", "2001:", "203.")) for hop in email.hops)


def test_legit_parser_passes_authentication():
    email = parse_email(read("legit.eml"))
    assert email.auth.spf_header == "pass"
    assert email.auth.dkim_header == "pass"
    assert email.auth.dmarc_header == "pass"
    assert not email.identity_checks["from_return_path_mismatch"]


def test_no_received_headers_flags_hop_stripping():
    email = parse_email(read("no-hops.eml"))
    assert not email.hops
    assert any("hop stripping" in anomaly.lower() for anomaly in email.routing_anomalies)


def test_one_received_hop_is_reported():
    email = parse_email(read("single-hop.eml"))
    assert len(email.hops) == 1
    assert any("one Received hop" in anomaly for anomaly in email.routing_anomalies)


def test_private_only_hops_are_removed():
    email = parse_email(read("legit.eml"))
    assert all(hop.ip is None or not hop.ip.startswith("10.") for hop in email.hops)


def test_ipv6_public_hop_is_kept():
    email = parse_email(read("ipv6.eml"))
    assert email.hops
    assert email.hops[0].ip == "2001:4860:4860::8888"


def test_html_only_and_encoded_bodies_parse():
    html_mail = parse_email(read("html-only.eml"))
    encoded_mail = parse_email(read("encoded.eml"))
    assert "Hello" in html_mail.plain_text
    assert "Normal" in encoded_mail.plain_text


def test_empty_and_binary_files_do_not_raise():
    assert parse_email(b"").warnings
    binary = parse_email(read("binary.eml"))
    assert binary.warnings or binary.subject == ""


def test_non_utf8_and_long_subject_parse():
    email = parse_email(read("non-utf8.eml"))
    assert isinstance(email.subject, str)
