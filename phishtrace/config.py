from dataclasses import dataclass


MODEL_NAME = "spotproject/spot-distilbert-phishing"
GEOLOCATION_URL = "https://ipwho.is/{ip}"
GEOLOCATION_TIMEOUT = 3.0
GEOLOCATION_RETRIES = 1
DNS_TIMEOUT = 3.0

KNOWN_BRANDS = ("paypal", "microsoft", "google", "apple", "amazon", "netflix",
                "bankofamerica", "chase", "dropbox", "icloud", "outlook")


@dataclass(frozen=True)
class ScoreWeights:
    auth_failure: int = 15
    identity_mismatch: int = 12
    routing_anomaly: int = 8
    ai_phishing: int = 20
    body_signal: int = 10


WEIGHTS = ScoreWeights()
SUSPICIOUS_THRESHOLD = 30
HIGH_THRESHOLD = 60
LONG_SUBJECT_THRESHOLD = 250
