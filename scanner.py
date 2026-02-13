# scanner.py
import re

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "final notice", "limited time",
    "suspend", "suspended", "verify", "warning", "alert"
]

CREDENTIAL_WORDS = [
    "password", "login", "sign in", "verify your account", "confirm your identity",
    "ssn", "social security", "bank account", "routing number"
]

MONEY_WORDS = [
    "wire", "gift card", "bitcoin", "crypto", "payment", "refund",
    "invoice", "transfer", "send money"
]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]


def extract_urls(text: str) -> list[str]:
    # Very basic URL pattern for V1 (good enough to start)
    return re.findall(r"https?://\S+|www\.\S+", text.lower())


def contains_any(text: str, phrases: list[str]) -> list[str]:
    found = []
    lower = text.lower()
    for p in phrases:
        if p in lower:
            found.append(p)
    return found


def scan_text(text: str) -> dict:
    """
    Returns:
      score: 0-100
      label: Likely Scam / Unsure / Likely Legit
      reasons: list of strings explaining why
      evidence: small details you can show in the UI
    """
    score = 0
    reasons = []
    evidence = {}

    if not text or len(text.strip()) < 20:
        return {
            "score": 0,
            "label": "Unsure",
            "reasons": ["Message is too short to evaluate."],
            "evidence": {}
        }

    # 1) Urgency language
    urg_found = contains_any(text, URGENCY_WORDS)
    if urg_found:
        score += 25
        reasons.append("Urgent / threatening language detected.")
        evidence["urgency_words"] = urg_found[:5]

    # 2) Credential / personal info requests
    cred_found = contains_any(text, CREDENTIAL_WORDS)
    if cred_found:
        score += 35
        reasons.append("Possible request for personal or login information.")
        evidence["credential_words"] = cred_found[:5]

    # 3) Money pressure / payment language
    money_found = contains_any(text, MONEY_WORDS)
    if money_found:
        score += 25
        reasons.append("Mentions payments, refunds, or money transfer.")
        evidence["money_words"] = money_found[:5]

    # 4) Link checks
    urls = extract_urls(text)
    if urls:
        score += 10
        reasons.append("Contains one or more links.")
        evidence["urls"] = urls[:3]

        # Short link / URL shortener
        if any(sd in u for u in urls for sd in SHORTENER_DOMAINS):
            score += 15
            reasons.append("Uses a link shortener (common in scams).")

    # 5) Extra simple red flags (optional)
    if "click here" in text.lower():
        score += 10
        reasons.append("Pushy call-to-action like 'click here' detected.")

    # Clamp score to 0-100
    score = max(0, min(100, score))

    # Label decision
    if score >= 70:
        label = "Likely Scam"
    elif score >= 40:
        label = "Unsure"
    else:
        label = "Likely Legit"

    if not reasons:
        reasons.append("No common scam indicators were detected in this message.")

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "evidence": evidence
    }
