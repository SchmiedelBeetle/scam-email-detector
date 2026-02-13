# Scam Email Detector (V1 Prototype)
Overview

This project is a simple web-based scam detection tool.
Users paste an email or text message into the app, click “Scan,” and receive:

A risk score (0–100)

A classification label (Likely Scam / Unsure / Likely Legit)

A list of detected red flags

Evidence showing which phrases triggered the result

This version is a rule-based baseline designed to be explainable and easy to improve.

How It Works

The system consists of two components:

1. Scanning Engine (scanner.py)

The scanner checks the message for common scam indicators:

Urgency language (e.g., “urgent”, “act now”)

Credential requests (e.g., “password”, “verify account”)

Money-related language (e.g., “wire”, “gift card”)

Suspicious links or URL shorteners

Each category contributes points to a risk score.
The final score determines the classification label.

2. Web Interface (app.py)

Built using Streamlit.
Provides a simple interface for users to paste text and view results.

Installation

Create a virtual environment (recommended):

python3 -m venv .venv
source .venv/bin/activate


Install dependencies:

pip install -r requirements.txt


Run the app:

streamlit run app.py


Then open:

http://localhost:8501
