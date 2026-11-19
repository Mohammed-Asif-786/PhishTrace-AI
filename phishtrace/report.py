from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone

from .classifier import ClassificationResult
from .geo import GeoResult
from .parser import ParsedEmail
from .scoring import Finding


def defang_url(url: str) -> str:
    return url.replace("http", "hxxp").replace(".", "[.]")


def generate_reasoning(email: ParsedEmail, score: int, verdict: str,
                       findings: list[Finding]) -> str:
    if not findings:
        return f"This message received a {verdict.lower()} assessment with a score of {score}. "
    evidence = "; ".join(finding.evidence for finding in findings[:3])
    return (f"This message received a {verdict.lower()} assessment with a score of {score}. "
            f"The main reasons are: {evidence}.")


def recommended_actions(verdict: str) -> list[str]:
    if verdict == "High":
        return ["Quarantine the message.", "Block or review the sender domain.",
                "Reset exposed credentials and investigate affected accounts."]
    if verdict == "Suspicious":
        return ["Keep the message for review.", "Verify the sender through a trusted channel.",
                "Do not open links or attachments until confirmed."]
    return ["No immediate containment appears necessary.",
            "Retain normal monitoring and report any unexpected follow-up."]


def build_report_data(file_name: str, file_bytes: bytes, email: ParsedEmail,
                      classification: ClassificationResult, score: int, verdict: str,
                      findings: list[Finding], geo_results: list[GeoResult],
                      ai_unavailable: bool) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "summary": {
            "verdict": verdict,
            "score": score,
            "reasoning": generate_reasoning(email, score, verdict, findings),
            "ai_unavailable": ai_unavailable,
        },
        "file_metadata": {
            "name": file_name,
            "sha256": __import__("hashlib").sha256(file_bytes).hexdigest(),
            "analysis_time": now,
            "size_bytes": len(file_bytes),
        },
        "authentication": asdict(email.auth),
        "identity_checks": email.identity_checks,
        "hops": [asdict(hop) for hop in email.hops],
        "geo": [asdict(result) for result in geo_results],
        "body_analysis": {
            "status": classification.status,
            "probability": classification.probability,
            "model_name": classification.model_name,
            "reason": classification.reason,
            "signals": [asdict(signal) for signal in classification.body_signals],
        },
        "urls": [defang_url(url) for url in email.urls],
        "attachments": [
            {"name": name, "sha256": digest}
            for name, digest in zip(email.attachment_names, email.attachment_hashes)
        ],
        "findings": [asdict(finding) for finding in findings],
        "recommended_actions": recommended_actions(verdict),
    }


def report_to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def report_to_html(report: dict) -> str:
    summary = report["summary"]
    meta = report["file_metadata"]
    findings = "".join(
        f"<tr><td>{html.escape(str(f['id']))}</td><td>{html.escape(str(f['category']))}</td>"
        f"<td>{html.escape(str(f['severity']))}</td><td>{f['points']}</td>"
        f"<td>{html.escape(str(f['evidence']))}</td></tr>"
        for f in report["findings"]
    )
    auth_rows = "".join(
        f"<tr><td>{html.escape(key)}</td><td>{html.escape(str(value))}</td></tr>"
        for key, value in report["authentication"].items()
    )
    hop_rows = "".join(
        f"<tr><td>{h['index']}</td><td>{html.escape(str(h['from_host']))}</td>"
        f"<td>{html.escape(str(h['by_host']))}</td><td>{html.escape(str(h['ip']))}</td>"
        f"<td>{html.escape(str(h['timestamp']))}</td></tr>"
        for h in report["hops"]
    )
    actions = "".join(f"<li>{html.escape(action)}</li>"
                      for action in report["recommended_actions"])
    body = report["body_analysis"]
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>PhishTrace AI Admin Report</title>
<style>body{{font-family:Arial,sans-serif;max-width:1000px;margin:auto;color:#172033}}
table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid #cbd5e1;padding:7px;text-align:left}}
th{{background:#f1f5f9}}.high{{color:#b91c1c}}.suspicious{{color:#b45309}}.low{{color:#166534}}</style>
</head><body>
<h1>PhishTrace AI Admin Report</h1>
<h2>Summary</h2><p><strong>Verdict:</strong> <span class="{summary['verdict'].lower()}">{summary['verdict']}</span>
<strong>Score:</strong> {summary['score']}/100</p><p>{html.escape(summary['reasoning'])}</p>
<h2>File metadata</h2><p>Name: {html.escape(meta['name'])}<br>SHA-256: {meta['sha256']}<br>
Analysis time: {meta['analysis_time']}<br>Size: {meta['size_bytes']} bytes</p>
<h2>Authentication</h2><table><tr><th>Check</th><th>Result</th></tr>{auth_rows}</table>
<h2>Identity checks</h2><pre>{html.escape(json.dumps(report['identity_checks'], indent=2))}</pre>
<h2>Hop table</h2><table><tr><th>Hop</th><th>From</th><th>By</th><th>IP</th><th>Timestamp</th></tr>{hop_rows}</table>
<h2>Body analysis</h2><pre>{html.escape(json.dumps(body, indent=2))}</pre>
<h2>Full findings</h2><table><tr><th>ID</th><th>Category</th><th>Severity</th><th>Points</th><th>Evidence</th></tr>{findings}</table>
<h2>URLs</h2><p>{html.escape('<br>'.join(report['urls']))}</p>
<h2>Recommended actions</h2><ul>{actions}</ul>
</body></html>"""
