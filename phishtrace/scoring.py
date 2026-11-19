from __future__ import annotations

from dataclasses import dataclass

from .classifier import ClassificationResult
from .config import HIGH_THRESHOLD, SUSPICIOUS_THRESHOLD, WEIGHTS
from .parser import ParsedEmail


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    points: int
    evidence: str


def _severity(points: int) -> str:
    if points >= 15:
        return "high"
    if points >= 8:
        return "medium"
    return "low"


def score_email(email: ParsedEmail, classification: ClassificationResult) -> tuple[int, str, list[Finding], bool]:
    findings: list[Finding] = []
    auth_failures = [name for name in ("spf", "dkim", "dmarc")
                     if getattr(email.auth, name) in {"fail", "softfail", "missing"}]
    if auth_failures:
        names = ", ".join(auth_failures)
        findings.append(Finding("auth_failures", "authentication",
                                _severity(WEIGHTS.auth_failure),
                                WEIGHTS.auth_failure,
                                f"Authentication result: {names} is not passing"))

    identity = email.identity_checks
    if identity.get("from_return_path_mismatch"):
        evidence = f"From domain '{email.from_domain}' differs from Return-Path '{identity['return_path_domain']}'"
        findings.append(Finding("from_return_path_mismatch", "identity", "medium",
                                WEIGHTS.identity_mismatch, evidence))
    if identity.get("reply_to_mismatch"):
        evidence = f"Reply-To domain '{identity['reply_to_domain']}' differs from From domain '{email.from_domain}'"
        findings.append(Finding("reply_to_mismatch", "identity", "medium",
                                WEIGHTS.identity_mismatch, evidence))
    if identity.get("display_name_spoofing"):
        evidence = f"Display name '{email.from_name}' contains an email address unlike From <{email.from_address}>"
        findings.append(Finding("display_name_spoofing", "identity", "medium",
                                WEIGHTS.identity_mismatch, evidence))
    lookalikes = identity.get("lookalike_domains") or []
    if lookalikes:
        evidence = f"Sender domain '{email.from_domain}' resembles {', '.join(lookalikes)}"
        findings.append(Finding("lookalike_domain", "identity", "medium",
                                WEIGHTS.identity_mismatch, evidence))

    if email.routing_anomalies:
        evidence = "; ".join(email.routing_anomalies)
        findings.append(Finding("routing_anomaly", "routing",
                                _severity(WEIGHTS.routing_anomaly),
                                WEIGHTS.routing_anomaly, evidence))

    if classification.status == "available" and classification.probability is not None:
        ai_points = round(classification.probability * WEIGHTS.ai_phishing)
        if ai_points:
            findings.append(Finding("ai_body_score", "body",
                                    _severity(ai_points),
                                    ai_points,
                                    f"Model {classification.model_name} classified the body as phishing with "
                                    f"{classification.probability:.1%} probability"))
    for signal in classification.body_signals:
        findings.append(Finding(signal.id, "body", _severity(signal.points),
                                signal.points, signal.evidence))

    raw_score = sum(finding.points for finding in findings)
    score = max(0, min(100, raw_score))
    has_header_finding = any(f.category in {"authentication", "identity", "routing"} for f in findings)
    if classification.status == "available" and not has_header_finding:
        ai_only_score = sum(f.points for f in findings if f.category == "body")
        if ai_only_score and ai_only_score >= SUSPICIOUS_THRESHOLD:
            score = SUSPICIOUS_THRESHOLD - 1

    if score >= HIGH_THRESHOLD:
        verdict = "High"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "Suspicious"
    else:
        verdict = "Low"

    renormalize = classification.status == "unavailable"
    if renormalize:
        header_body_score = sum(f.points for f in findings)
        score = max(0, min(100, round(header_body_score * 100 / 45))) if findings else 0
        if classification.body_signals:
            score = max(score, min(59, sum(f.points for f in findings)))
        if score >= HIGH_THRESHOLD:
            verdict = "High"
        elif score >= SUSPICIOUS_THRESHOLD:
            verdict = "Suspicious"
        else:
            verdict = "Low"
    return score, verdict, findings, renormalize
