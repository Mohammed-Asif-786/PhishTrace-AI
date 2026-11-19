from pathlib import Path

from phishtrace.parser import parse_email
from phishtrace.classifier import ClassificationResult
from phishtrace.scoring import score_email


FIXTURES = Path(__file__).parent / "fixtures"


def classify(email, probability):
    signals = []
    if "URGENT" in email.plain_text.upper():
        from phishtrace.classifier import BodySignal
        signals = [BodySignal("urgency", "urgent", 5)]
    return ClassificationResult("available", probability, "phishing",
                                "test-model", "model test", signals)


def test_classic_phish_is_high():
    email = parse_email((FIXTURES / "classic-phish.eml").read_bytes())
    score, verdict, findings, unavailable = score_email(email, classify(email, 0.95))
    assert verdict == "High"
    assert score >= 60
    assert not unavailable


def test_legit_is_low():
    email = parse_email((FIXTURES / "legit.eml").read_bytes())
    score, verdict, findings, unavailable = score_email(
        email, ClassificationResult("available", 0.02, "ham", "test", "test", [])
    )
    assert verdict == "Low"
    assert score < 30


def test_reply_to_and_spoof_only_is_suspicious():
    email = parse_email((FIXTURES / "reply-spoof.eml").read_bytes())
    result = ClassificationResult("available", 0.1, "ham", "test", "test", [])
    score, verdict, findings, unavailable = score_email(email, result)
    assert verdict == "Suspicious"


def test_ai_only_cannot_exceed_suspicious():
    email = parse_email((FIXTURES / "legit.eml").read_bytes())
    score, verdict, findings, unavailable = score_email(
        email, ClassificationResult("available", 1.0, "phishing", "test", "test", [])
    )
    assert verdict == "Suspicious"


def test_model_unavailable_is_visible_and_renormalized():
    email = parse_email((FIXTURES / "classic-phish.eml").read_bytes())
    unavailable = ClassificationResult("unavailable", None, "unknown", "test", "failed", [])
    score, verdict, findings, renormalized = score_email(email, unavailable)
    assert renormalized
    assert 0 <= score <= 100
