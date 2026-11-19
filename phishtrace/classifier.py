from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

import streamlit as st

from .config import MODEL_NAME
from .parser import ParsedEmail

LOGGER = logging.getLogger(__name__)


@dataclass
class BodySignal:
    id: str
    evidence: str
    points: int


@dataclass
class ClassificationResult:
    status: str
    probability: float | None
    label: str
    model_name: str
    reason: str
    body_signals: list[BodySignal] = field(default_factory=list)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.current_href = ""
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self.current_href = dict(attrs).get("href") or ""
            self.text = []

    def handle_data(self, data: str) -> None:
        if self.current_href:
            self.text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a":
            self.links.append((self.current_href, " ".join(self.text).strip()))
            self.current_href = ""
            self.text = []


@st.cache_resource
def load_classifier():
    try:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
    except ImportError as exc:
        return None, f"transformers is not installed: {exc}"
    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
        labels = getattr(model.config, "id2label", {}) or {}
        text_pipeline = pipeline("text-classification", model=model, tokenizer=tokenizer,
                                 truncation=True, max_length=512)
        return (text_pipeline, labels), None
    except (OSError, RuntimeError, ValueError) as exc:
        LOGGER.exception("Phishing model could not be loaded")
        return None, f"model could not be loaded: {type(exc).__name__}"


def rule_signals(email: ParsedEmail) -> list[BodySignal]:
    text = " ".join((email.subject, email.plain_text)).lower()
    signals: list[BodySignal] = []
    if re.search(r"\b(urgent|immediately|within \d+ (hour|minute)|act now|expires? soon)\b", text):
        sample = re.search(r"\b(urgent|immediately|within \d+ (hour|minute)|act now|expires? soon)\b", text)
        signals.append(BodySignal("urgency", sample.group(0) if sample else "urgency language",
                                  5))
    if re.search(r"\b(password|login|credential|bank account|social security|credit card)\b", text):
        sample = re.search(r"\b(password|login|credential|bank account|social security|credit card)\b", text)
        signals.append(BodySignal("credential_request", sample.group(0) if sample else "credential request",
                                  8))
    if re.search(r"\b(?:account.{0,30}(?:suspend(?:ed|ion)?|blocked)|(?:suspend(?:ed|ion)?|blocked).{0,30}account|closed|terminated)\b", text):
        signals.append(BodySignal("suspension_threat", "account suspension or termination threat", 7))

    parser = _LinkParser()
    try:
        parser.feed(email.stripped_html or "")
    except Exception:
        LOGGER.exception("Could not inspect HTML links")
    for href, link_text in parser.links:
        if link_text and href:
            destination = urlparse(href).hostname or ""
            text_words = re.findall(r"https?://([^\s/]+)", link_text.lower())
            if text_words and destination.lower() not in text_words:
                signals.append(BodySignal("link_mismatch",
                                          f"link text '{link_text}' points to '{href}'", 8))
        if urlparse(href).hostname in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                                       "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}:
            signals.append(BodySignal("shortened_url", f"shortened URL '{href}'", 5))
    for url in email.urls:
        host = urlparse(url).hostname
        if host in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                    "buff.ly", "rebrand.ly", "cutt.ly"}:
            signals.append(BodySignal("shortened_url", f"shortened URL '{url}'", 5))
    return list({signal.id: signal for signal in signals}.values())


def classify_email(email: ParsedEmail) -> ClassificationResult:
    signals = rule_signals(email)
    content = " ".join((email.subject, email.plain_text)).strip()
    if not content:
        return ClassificationResult("unavailable", None, "unknown", MODEL_NAME,
                                    "body is empty", signals)
    loaded, error = load_classifier()
    if loaded is None:
        return ClassificationResult("unavailable", None, "unknown", MODEL_NAME,
                                    error or "model unavailable", signals)
    text_pipeline, labels = loaded
    try:
        result = text_pipeline(content[:10000], truncation=True, max_length=512)[0]
    except (RuntimeError, ValueError, IndexError) as exc:
        LOGGER.exception("Model inference failed")
        return ClassificationResult("unavailable", None, "unknown", MODEL_NAME,
                                    f"inference failed: {type(exc).__name__}", signals)
    raw_label = str(result.get("label", ""))
    label = labels.get(raw_label, raw_label) if isinstance(labels, dict) else raw_label
    label_text = str(label).lower()
    score = float(result.get("score", 0.0))
    if "phish" in label_text or "spam" in label_text or "malicious" in label_text:
        probability = score
    elif "legit" in label_text or "ham" in label_text or "safe" in label_text:
        probability = 1.0 - score
    else:
        probability = score if "1" in raw_label else 1.0 - score
    probability = max(0.0, min(1.0, probability))
    return ClassificationResult("available", probability,
                                str(result.get("label", "")), MODEL_NAME, "model classification", signals)
