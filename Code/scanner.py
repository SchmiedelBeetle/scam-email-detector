"""
ClearShield Scam Detection Engine

A rule-based scam message detection engine that uses pattern matching across
multiple risk categories to produce an explainable risk score.

Author: Christian Schmiedel
Project: CSUB Senior Project — Information Security
"""

import random
import re
from typing import Optional


# =============================================================================
# DETECTION RULE LISTS
# =============================================================================
# Each list contains phrases commonly found in scam messages. Phrases are
# matched case-insensitively against the input message using word-boundary
# regex so that "urgent" does not falsely match inside "urgently" — but
# multi-word phrases still match correctly.
#
# Lists were built from a combination of:
#   - Anti-Phishing Working Group (APWG) trend reports
#   - FTC Consumer Sentinel scam pattern documentation
#   - Personal observation of phishing samples
# =============================================================================

URGENCY_PHRASES = [
    # Time pressure
    "urgent", "urgently", "immediately", "right away", "right now",
    "act now", "act fast", "act immediately", "act today",
    "final notice", "final warning", "last chance", "last warning",
    "limited time", "time sensitive", "time is running out",
    "expires soon", "expires today", "expires in 24 hours",
    "within 24 hours", "within 48 hours", "before it's too late",
    "do not delay", "don't delay", "respond now", "reply immediately",
    # Threat/consequence language
    "account suspended", "account locked", "account has been locked",
    "account will be suspended", "account will be deleted",
    "permanently deleted", "permanently disabled", "permanently closed",
    "service will be terminated", "access will be denied",
    "your account is at risk", "suspicious activity detected",
    "unauthorized access", "unusual activity",
    # Alert framing
    "warning", "alert", "important notice", "security alert",
    "attention required", "action required", "verification required",
]

CREDENTIAL_PHRASES = [
    # Direct credential requests
    "password", "your password", "confirm your password",
    "login", "log in", "sign in", "your login",
    "username and password", "credentials",
    # Identity verification (very common phishing pattern)
    "verify your account", "verify your identity", "verify your information",
    "verify your details", "verify your address", "confirm your identity",
    "confirm your account", "confirm your information", "validate your account",
    "re-verify", "reverify",
    # Personal information requests
    "social security", "social security number", "ssn",
    "date of birth", "mother's maiden name",
    "bank account", "bank account number", "routing number",
    "credit card", "credit card number", "card number",
    "cvv", "security code", "pin number", "pin code",
    "account number",
    # Account access patterns
    "update your account", "update your information",
    "update your billing", "update your payment",
    "click here to verify", "click here to login",
    "click below to verify", "click the link below",
]

MONEY_PHRASES = [
    # Payment methods favored by scammers
    "wire transfer", "wire money", "send money", "transfer funds",
    "gift card", "gift cards", "itunes card", "google play card",
    "amazon gift card", "steam card", "vanilla gift",
    "bitcoin", "btc", "crypto", "cryptocurrency", "ethereum",
    "moneygram", "western union", "zelle",
    # Refund / payment scams
    "refund", "your refund", "claim your refund", "process your refund",
    "tax refund", "irs refund",
    "payment failed", "payment declined", "payment pending",
    "invoice attached", "invoice overdue", "outstanding balance",
    "billing problem", "billing issue",
    # Prize / lottery scams
    "you have won", "you've won", "you are a winner", "congratulations you",
    "claim your prize", "claim your reward", "lottery winner",
    "selected as winner", "prize winnings",
    # Inheritance / advance-fee
    "inheritance", "beneficiary", "deceased relative",
    "transfer fee", "processing fee", "release fee",
]

LINK_RED_FLAGS = [
    "click here", "click the link", "click below",
    "click this link", "tap here", "follow this link",
]

# URL shortener domains commonly used to mask malicious links
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorturl.at", "rb.gy",
    "cutt.ly", "t.ly", "tiny.cc", "shorte.st",
]

# Suspicious top-level domains (commonly abused by phishing campaigns)
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".zip"]


# =============================================================================
# CATEGORY WEIGHTS
# =============================================================================
# Each category contributes a maximum number of points to the total risk
# score. Within a category, repeated hits add diminishing returns so that
# a single phrase doesn't dominate but multiple hits still escalate risk.
# =============================================================================

CATEGORY_WEIGHTS = {
    "urgency": 30,        # Urgency alone is suspicious but not conclusive
    "credentials": 40,    # Credential requests are the strongest single signal
    "money": 30,          # Money requests are a strong signal
    "links": 15,          # Generic link presence is weak; shorteners are stronger
    "pushy_cta": 10,      # "Click here" style pressure
}

HIGHLIGHT_COLORS = {
    "urgency": "red",
    "credentials": "red",
    "money": "orange",
    "pushy_cta": "yellow",
    "url": "yellow",
    "suspicious_url": "red",
}

_PHRASE_TO_CATEGORY = {
    **{phrase: "urgency" for phrase in URGENCY_PHRASES},
    **{phrase: "credentials" for phrase in CREDENTIAL_PHRASES},
    **{phrase: "money" for phrase in MONEY_PHRASES},
    **{phrase: "pushy_cta" for phrase in LINK_RED_FLAGS},
}


# =============================================================================
# CORE MATCHING FUNCTIONS
# =============================================================================

def _find_phrases(text: str, phrases: list[str]) -> list[str]:
    """
    Return all phrases from `phrases` that appear in `text`, case-insensitively,
    respecting word boundaries.

    Uses a left word-boundary but allows the phrase to be followed by 's' or 'es'
    (handles plurals: "gift card" matches "gift cards"). Multi-word phrases
    still match correctly. Whitespace is normalized so that line breaks in
    pasted emails don't break multi-word phrase matches.
    """
    found = []
    # Normalize whitespace: collapse newlines/tabs/multiple spaces into single spaces
    normalized = re.sub(r'\s+', ' ', text.lower())
    for phrase in phrases:
        # Left boundary, escaped phrase, optional plural suffix, right boundary
        pattern = r'\b' + re.escape(phrase.lower()) + r'(?:s|es)?\b'
        if re.search(pattern, normalized):
            found.append(phrase)
    return found


def extract_urls(text: str) -> list[str]:
    """
    Extract all URLs from the input text. Catches:
      - Full URLs (http://..., https://...)
      - Bare www domains (www.example.com)
      - Bare shortener-style domains (bit.ly/xyz, t.co/abc)
      - Common-TLD bare domains (example.com, site.org)
    """
    # Multiple patterns combined: explicit protocol, www prefix, or bare common-TLD domain
    url_pattern = (
        r'https?://\S+'
        r'|www\.\S+'
        r'|\b[a-zA-Z0-9-]+\.(?:ly|co|com|net|org|io|app|gov|edu|tk|ml|ga|cf|gq|top|click|zip|gd|cc)(?:/\S*)?'
    )
    matches = re.findall(url_pattern, text.lower())
    seen = set()
    unique = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


def _category_score(hits: int, max_points: int) -> int:
    """
    Compute the score contribution for a category given the number of hits.

    Uses diminishing returns: 1 hit gets 60% of max, 2 hits get 85%, 3+ hits
    get 100%. This prevents a single common word from dominating the score
    while still escalating risk for messages packed with red flags.
    """
    if hits == 0:
        return 0
    elif hits == 1:
        return int(max_points * 0.6)
    elif hits == 2:
        return int(max_points * 0.85)
    else:
        return max_points


# =============================================================================
# MAIN SCAN FUNCTION
# =============================================================================

def scan_text(text: str) -> dict:
    """
    Scan a message for scam indicators and return a structured analysis.

    Returns a dict with:
        score   (int)   : 0-100 risk score
        label   (str)   : "Likely Scam" | "Unsure" | "Likely Legit"
        reasons (list)  : Human-readable explanations of each flag
        evidence (dict) : Specific phrases / URLs matched, for transparency
    """
    # Input guard
    if not text or len(text.strip()) < 20:
        return {
            "score": 0,
            "label": "Unsure",
            "reasons": ["Message is too short to evaluate reliably."],
            "evidence": {},
        }

    score = 0
    reasons = []
    evidence = {}

    # --- Urgency ---
    urgency_hits = _find_phrases(text, URGENCY_PHRASES)
    if urgency_hits:
        pts = _category_score(len(urgency_hits), CATEGORY_WEIGHTS["urgency"])
        score += pts
        reasons.append(
            f"Urgent or threatening language detected ({len(urgency_hits)} phrase{'s' if len(urgency_hits) > 1 else ''})."
        )
        evidence["urgency_phrases"] = urgency_hits[:8]

    # --- Credentials ---
    cred_hits = _find_phrases(text, CREDENTIAL_PHRASES)
    if cred_hits:
        pts = _category_score(len(cred_hits), CATEGORY_WEIGHTS["credentials"])
        score += pts
        reasons.append(
            f"Requests for personal or login information detected ({len(cred_hits)} phrase{'s' if len(cred_hits) > 1 else ''})."
        )
        evidence["credential_phrases"] = cred_hits[:8]

    # --- Money ---
    money_hits = _find_phrases(text, MONEY_PHRASES)
    if money_hits:
        pts = _category_score(len(money_hits), CATEGORY_WEIGHTS["money"])
        score += pts
        reasons.append(
            f"Mentions of payments, refunds, or money transfer detected ({len(money_hits)} phrase{'s' if len(money_hits) > 1 else ''})."
        )
        evidence["money_phrases"] = money_hits[:8]

    # --- Pushy CTAs ---
    cta_hits = _find_phrases(text, LINK_RED_FLAGS)
    if cta_hits:
        pts = _category_score(len(cta_hits), CATEGORY_WEIGHTS["pushy_cta"])
        score += pts
        reasons.append("Pushy call-to-action detected (e.g. 'click here').")
        evidence["pushy_cta_phrases"] = cta_hits

    # --- Links ---
    urls = extract_urls(text)
    if urls:
        base_link_points = _category_score(1, CATEGORY_WEIGHTS["links"])
        score += base_link_points
        reasons.append(f"Message contains {len(urls)} link{'s' if len(urls) > 1 else ''}.")
        evidence["urls"] = urls[:5]

        # Shortener bonus — strong signal of phishing
        shorteners_found = [
            url for url in urls
            if any(shortener in url for shortener in SHORTENER_DOMAINS)
        ]
        if shorteners_found:
            score += 20
            reasons.append(
                "URL shortener detected — commonly used to disguise malicious links."
            )
            evidence["url_shorteners"] = shorteners_found[:3]

        # Suspicious TLD bonus
        sus_tld_hits = [
            url for url in urls
            if any(url.endswith(tld) or tld + "/" in url for tld in SUSPICIOUS_TLDS)
        ]
        if sus_tld_hits:
            score += 10
            reasons.append(
                "Link uses a suspicious top-level domain frequently abused by phishing."
            )
            evidence["suspicious_tld_urls"] = sus_tld_hits[:3]

    # --- Final scoring and label ---
    score = max(0, min(100, score))

    if score >= 60:
        label = "Likely Scam"
    elif score >= 30:
        label = "Unsure"
    else:
        label = "Likely Legit"

    if not reasons:
        reasons.append("No common scam indicators were detected in this message.")

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "evidence": evidence,
    }


def generate_scam_email() -> str:
    """Create a realistic-looking scam email using the same red-flag patterns."""
    subject = random.choice([
        "Urgent: Account Security Alert",
        "Important: Verify Your Account Now",
        "Action Required: Suspicious Activity Detected",
        "Immediate Response Needed: Account Verification",
    ])

    greeting = random.choice([
        "Dear Customer,",
        "Hello,",
        "Hi there,",
        "Dear User,",
    ])

    body_lines = [
        "We noticed suspicious activity on your account.",
        "To protect your information, please {} {}.".format(
            random.choice(['verify your account', 'confirm your identity', 'update your billing information']),
            random.choice(['within 24 hours', 'immediately', 'right away'])
        ),
        "This may require you to {}.".format(
            random.choice(['confirm your password', 'verify your password', 'submit your social security number'])
        ),
        "{}:".format(
            random.choice(['Click here to verify', 'Follow this link to confirm', 'Please click the link below'])
        ),
        _generate_scam_link(),
        random.choice([
            'Failure to respond may result in account suspension.',
            'Do not delay. Your account may be locked.',
            'This is an important security alert.',
        ]),
        random.choice([
            'Thank you for your prompt attention.',
            'Sincerely,\nSecurity Team',
            'Regards,\nAccount Support Team',
        ]),
    ]

    if random.choice([True, False]):
        body_lines.insert(3, random.choice([
            'Please confirm your password and social security number.',
            'Verify your account details before your account is suspended.',
            'Confirm your login credentials now to avoid service interruption.',
        ]))

    if random.choice([True, False]):
        body_lines.insert(2, random.choice([
            'We may also need your bank account number for verification.',
            'Please submit your credit card information if requested.',
            'A small processing fee may be required to release the hold on your account.',
        ]))

    return f"Subject: {subject}\n{greeting}\n\n" + "\n".join(body_lines)


def _generate_scam_link() -> str:
    if random.random() < 0.65:
        domain = random.choice(SHORTENER_DOMAINS)
        return f"https://{domain}/{random.randint(1000, 9999)}"

    suspicious_domain = random.choice(["secure-update", "account-verify", "payment-alert", "support-login"])
    tld = random.choice([".tk", ".top", ".click", ".net", ".com"])
    return f"https://{suspicious_domain}{tld}/{random.randint(100, 999)}"


# =============================================================================
# HIGHLIGHT HELPER — used by the UI to mark suspicious phrases in the message
# =============================================================================

def get_all_suspicious_phrases() -> list[str]:
    """Return a flat list of all suspicious phrases across all categories."""
    return (
        URGENCY_PHRASES
        + CREDENTIAL_PHRASES
        + MONEY_PHRASES
        + LINK_RED_FLAGS
    )


def _highlight_color_for_phrase(phrase: str) -> str:
    category = _PHRASE_TO_CATEGORY.get(phrase, "money")
    return HIGHLIGHT_COLORS.get(category, "yellow")


def _url_highlight_color(url: str) -> str:
    if any(shortener in url for shortener in SHORTENER_DOMAINS):
        return HIGHLIGHT_COLORS["suspicious_url"]
    if any(url.endswith(tld) or tld + "/" in url for tld in SUSPICIOUS_TLDS):
        return HIGHLIGHT_COLORS["suspicious_url"]
    return HIGHLIGHT_COLORS["url"]


def highlight_suspicious(text: str) -> str:
    """
    Return the input text with suspicious phrases wrapped in Streamlit color
    markup so that the UI can render them by likelihood category.
    """
    all_phrases = get_all_suspicious_phrases()
    # Sort longest-first so multi-word phrases match before single words
    all_phrases.sort(key=len, reverse=True)

    highlighted = text
    seen_spans = []  # avoid double-wrapping
    spans = []

    for phrase in all_phrases:
        pattern = r'\b' + re.escape(phrase) + r'(?:s|es)?\b'
        for match in re.finditer(pattern, highlighted, flags=re.IGNORECASE):
            start, end = match.span()
            if any(s <= start < e or s < end <= e for s, e in seen_spans):
                continue
            seen_spans.append((start, end))
            spans.append((start, end, _highlight_color_for_phrase(phrase)))

    for url in extract_urls(text):
        for match in re.finditer(re.escape(url), highlighted, flags=re.IGNORECASE):
            start, end = match.span()
            if any(s <= start < e or s < end <= e for s, e in seen_spans):
                continue
            seen_spans.append((start, end))
            spans.append((start, end, _url_highlight_color(url)))

    spans.sort(key=lambda s: s[0], reverse=True)
    for start, end, color in spans:
        original = highlighted[start:end]
        highlighted = highlighted[:start] + f"**:{color}[{original}]**" + highlighted[end:]

    return highlighted