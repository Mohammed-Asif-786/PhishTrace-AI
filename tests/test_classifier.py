from pathlib import Path
from unittest.mock import patch

from phishtrace.classifier import classify_email
from phishtrace.parser import parse_email
from phishtrace.classifier import ClassificationResult


FIXTURES = Path(__file__).parent / "fixtures"


def test_urgency_and_credentials_are_rule_signals():
    email = parse_email((FIXTURES / "classic-phish.eml").read_bytes())
    with patch("phishtrace.classifier.load_classifier", return_value=(None, "mock unavailable")):
        result = classify_email(email)
    ids = {signal.id for signal in result.body_signals}
    assert {"urgency", "credential_request", "suspension_threat"} <= ids
    assert result.status == "unavailable"


def test_model_id2label_is_mapped_without_label_one_hack():
    email = parse_email((FIXTURES / "classic-phish.eml").read_bytes())
    classifier = (lambda text, truncation=True, max_length=512: [{"label": "spam", "score": 0.91}], {"spam": "phishing"})
    with patch("phishtrace.classifier.load_classifier", return_value=(classifier, None)):
        result = classify_email(email)
    assert result.status == "available"
    assert result.probability == 0.91


def test_empty_body_is_unavailable():
    email = parse_email((FIXTURES / "empty.eml").read_bytes())
    result = classify_email(email)
    assert result.status == "unavailable"


def test_local_classifier_marks_phishing_content_available():
    email = parse_email((FIXTURES / "classic-phish.eml").read_bytes())
    result = classify_email(email)
    assert result.status == "available"
    assert result.model_name == "PhishTrace-Local-ML-v1"
    assert result.probability is not None
    assert result.probability >= 0.8


def test_local_classifier_marks_legitimate_content_available():
    email = parse_email((FIXTURES / "legit.eml").read_bytes())
    result = classify_email(email)
    assert result.status == "available"
    assert result.probability is not None
    assert result.probability < 0.5
