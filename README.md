# ClearShield — Scam Message Detector

A rule-based, explainable scam detection web app that helps everyday users
identify phishing emails and suspicious text messages. Built as a CSUB
Computer Science senior project with a focus on Information Security.

**Live demo:** *(deployed URL — see Deployment section)*
**Author:** Christian Schmiedel
**Project type:** CSUB Senior Project (CMPS) + CSUB CEI Accelerator venture

---

## Table of Contents

1. [Overview](#overview)
2. [Why Explainability](#why-explainability)
3. [Features](#features)
4. [Architecture](#architecture)
5. [Detection Categories](#detection-categories)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Running Tests](#running-tests)
9. [Project Structure](#project-structure)
10. [Design Decisions](#design-decisions)
11. [Limitations](#limitations)
12. [Roadmap](#roadmap)

---

## Overview

ClearShield is a web application that scans a pasted email or text message
and returns:

- A **risk score** between 0 and 100
- A **classification label**: `Likely Scam`, `Unsure`, or `Likely Legit`
- A list of **reasons** explaining why the message was flagged
- **Evidence**: the specific phrases and links that triggered each flag

The project's central design principle is **explainability**. Most existing
spam and antivirus tools tell users *what* is suspicious without explaining
*why*. ClearShield is designed for the people most vulnerable to scams —
particularly older adults and other less tech-savvy users — and treats every
scan as a teaching opportunity.

---

## Why Explainability

Black-box scam classifiers create a dependency: the user learns nothing and
must trust the tool every time. ClearShield takes the opposite approach. By
exposing the specific patterns that triggered a flag ("urgent language,"
"asks for password," "uses a URL shortener"), the user gradually internalizes
the patterns that scammers use, and over time becomes less reliant on any
detection tool at all.

This decision shapes the entire architecture: rule-based matching is used
instead of an opaque machine learning model, even though ML would likely be
more accurate on edge cases, because rules are inherently inspectable and
teachable.

---

## Features

- **Paste-and-scan interface** — no signup, no accounts, no friction
- **Color-coded results** — red, yellow, or green at a glance
- **Highlighted suspicious phrases** — see exactly what flagged the message
- **Plain-English reasons** — each flag has a one-line explanation
- **Demo presets** — three preloaded sample messages (obvious scam, subtle
  scam, legitimate) for instant demos
- **Evidence panel** — full transparency into what the engine matched

---

## Architecture

ClearShield is intentionally simple. It has two main components:

```
+----------------------+         +-----------------------+
|   app.py             |  calls  |   scanner.py          |
|   (Streamlit UI)     |-------->|   (Detection engine)  |
|                      |<--------|                       |
|   - Text input       |  result |   - Pattern matching  |
|   - Scan button      |         |   - Scoring logic     |
|   - Result display   |         |   - URL extraction    |
+----------------------+         +-----------------------+
```

- **`scanner.py`** — Pure-Python detection engine with no UI dependencies.
  Exports `scan_text(message) -> dict`. Can be imported and used from any
  Python context (CLI, web app, batch processing).
- **`app.py`** — Streamlit web interface. Handles user input, calls the
  scanner, and renders results.

This separation means the detection logic is independently testable and
reusable. The full test suite (`tests.py`) runs against `scanner.py` directly
without needing a browser or Streamlit server.

---

## Detection Categories

ClearShield checks each message against five categories of red flags:

| Category | Max Points | What It Catches |
|---|---|---|
| **Urgency** | 30 | "Act now", "final notice", "within 24 hours", "account locked" |
| **Credentials** | 40 | "Verify your account", "confirm your password", "SSN" |
| **Money** | 30 | "Wire transfer", "gift card", "bitcoin", "refund processing fee" |
| **Pushy CTAs** | 10 | "Click here", "tap here", "follow this link" |
| **Links** | 15 + bonuses | URL presence, plus +20 for URL shorteners, +10 for suspicious TLDs |

### Scoring Logic

Within each category, hits use **diminishing returns**:

- 1 hit → 60% of the category's max
- 2 hits → 85% of the category's max
- 3+ hits → 100% of the category's max

This prevents any single common word from dominating the score while still
escalating risk for messages packed with red flags. The final score is
clamped to 0–100.

### Label Thresholds

| Score Range | Label |
|---|---|
| 0 – 29 | Likely Legit |
| 30 – 59 | Unsure |
| 60 – 100 | Likely Scam |

---

## Installation

### Requirements

- Python 3.9 or later
- pip

### Setup

```bash
# Clone the repo
git clone https://github.com/SchmiedelBeetle/scam-email-detector.git
cd scam-email-detector

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate     # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Running the Web App

```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`.

### Using the Scanner from Python

```python
from scanner import scan_text

result = scan_text("URGENT: Verify your account immediately to avoid suspension.")
print(result["score"])       # 70
print(result["label"])       # "Likely Scam"
print(result["reasons"])     # ["Urgent or threatening language detected...", ...]
print(result["evidence"])    # {"urgency_phrases": [...], "credential_phrases": [...]}
```

---

## Running Tests

The project includes a comprehensive unit test suite covering known scam
patterns, legitimate messages, edge cases, and component-level behavior.

```bash
python3 tests.py
```

All 28 tests should pass. The suite includes:

- 7 known-scam classification tests (phishing, gift card, lottery, IRS, crypto)
- 4 legitimate-message tests (meeting reminders, family texts, newsletters)
- 4 edge-case tests (empty input, whitespace, ambiguous urgency)
- 5 URL extraction tests
- 4 word-boundary matching tests
- 2 highlighting tests
- 2 scoring calibration tests

---

## Project Structure

```
scam-email-detector/
├── app.py              # Streamlit web interface
├── scanner.py          # Detection engine (no UI dependencies)
├── tests.py            # Unit test suite (28 tests)
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── .gitignore          # Standard Python gitignore
└── Scam Ai proposal.docx   # Original fall-semester project proposal
```

---

## Design Decisions

### Why rule-based instead of machine learning?

ML models would likely catch a wider range of scams, but they sacrifice
**explainability** — the project's central feature. A user who is told
"this is 92% likely a scam" by a neural network has no way to learn from
that result. A user who is told "this message uses urgency language and
asks you to verify your password, both common phishing patterns" can
internalize those rules. Phase 2 of the roadmap layers ML on top of the
rule engine while preserving the explainability layer.

### Why Streamlit?

Streamlit lets a single developer build a credible web UI in pure Python
without writing HTML, CSS, or JavaScript. For an early-stage prototype
where iteration speed matters more than UI polish, this was the right
trade-off. The detection engine is decoupled from Streamlit, so migration
to a more flexible frontend (React, Flask + templates) is straightforward.

### Why diminishing returns on category scoring?

Without diminishing returns, a message saying "urgent urgent urgent urgent"
would score the same as a message with one urgency phrase plus credential
requests plus a shortener — clearly the second is more dangerous. Diminishing
returns ensure that **breadth** of red flags matters more than **depth**.

### Why no database in V1?

The current MVP is stateless by design — every scan is independent, and no
user data is stored. A future version will add SQLite-based scan logging for
analytics and history, but the stateless V1 was chosen to keep the privacy
surface area minimal and the deployment simple.

---

## Limitations

Known limitations of the current rule-based detection:

- **Subtle social-engineering scams** that avoid obvious red-flag phrases
  may slip through. (Phase 2 ML layer is intended to address this.)
- **Legitimate urgent messages** (e.g. "URGENT: deadline tomorrow") can be
  classified as `Unsure` due to genuine urgency language. The diminishing
  returns scoring is designed to keep these out of `Likely Scam` unless
  combined with other red flags.
- **Non-English messages** are not currently supported.
- **Sender verification** (SPF, DKIM, DMARC) is not yet performed — only
  message content is analyzed.

These limitations are documented in the test suite as "Unsure" expected
outcomes rather than "Likely Scam" or "Likely Legit".

---

## Roadmap

### Phase 1 (current)
- Rule-based detection across 5 categories
- Streamlit web UI with color-coded results
- Explainability layer with reasons + evidence
- Comprehensive test suite

### Phase 2 (Summer 2026)
- SQLite scan-history database
- Machine learning model layered on top of rules
- File upload (.txt, .eml screenshots)
- Browser extension for inline scanning
- First B2B pilot with senior centers and credit unions

### Phase 3 (2027+)
- Mobile app
- Family-shared accounts (the "tech-savvy family member" use case)
- Enterprise API for banks and large institutions
- Multi-language support

---

## License

This is a personal/academic project. License terms TBD.

## Contact

Christian Schmiedel — christians.schmiedel@gmail.com
GitHub: [@SchmiedelBeetle](https://github.com/SchmiedelBeetle)
