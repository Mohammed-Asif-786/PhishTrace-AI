from pathlib import Path

from phishtrace.parser import parse_email
from phishtrace.classifier import ClassificationResult
from phishtrace.scoring import score_email
from phishtrace.report import build_report_data, report_to_html, report_to_json, defang_url
from phishtrace.geo import GeoResult


FIXTURES = Path(__file__).parent / "fixtures"


def test_report_sections_and_exports():
    data = (FIXTURES / "classic-phish.eml").read_bytes()
    email = parse_email(data)
    classification = ClassificationResult("available", 0.9, "phishing", "test", "test", [])
    score, verdict, findings, unavailable = score_email(email, classification)
    report = build_report_data("classic.eml", data, email, classification, score, verdict,
                               findings, [GeoResult("8.8.8.8", False)], unavailable)
    assert report["summary"]["verdict"] == verdict
    assert "file_metadata" in report
    assert "findings" in report
    assert "<html>" in report_to_html(report)
    assert '"score"' in report_to_json(report)


def test_urls_are_defanged():
    assert defang_url("https://example.com/login") == "hxxps://example[.]com/login"
