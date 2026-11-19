# PhishTrace AI

I built this as a Streamlit application for reviewing uploaded `.eml` files. Analysis stays local. Optional public-IP geolocation uses ipwho.is. The deployment build does not bundle the large Hugging Face/PyTorch model; in environments where those packages are not installed, rule-based and deterministic analysis remains available.

## Setup

Use Python 3.10 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

For local Hugging Face inference, also install `transformers` and `torch`:

```bash
python -m pip install transformers==4.46.3 torch==2.5.1
```

Linux Mint users may need `python3-venv` and `python3-pip` installed through their package manager.

## Run tests

```bash
pytest -q
```

## Architecture

`parser.py` extracts standard-library email headers and bodies, normalizes the Received chain, removes private IPs, and returns typed dataclasses. `classifier.py` optionally loads the configured transformers model and separately evaluates urgency, credential requests, suspension threats, shortened links, and link mismatches. `scoring.py` combines deterministic finding weights. `geo.py` caches ipwho.is responses on disk and handles failures as unresolved hops. `report.py` creates the HTML and JSON administrative report.

## Scoring

| Finding | Weight |
|---|---:|
| Authentication failure | 15 |
| Identity mismatch, including lookalike or spoofing | 12 |
| Routing anomaly | 8 |
| AI phishing probability | up to 20 |
| Body signal | 5-8 |

Scores run from 0 to 100: Low 0-29, Suspicious 30-59, and High 60-100. The AI score cannot by itself create a High verdict or raise a message above Suspicious. If the AI stage is unavailable, available findings are renormalized for a 0-100 score.
