"""
ClearShield — Streamlit Web Interface

Author: Christian Schmiedel
Project: CSUB Senior Project (CMPS) — Information Security
"""

import streamlit as st
from scanner import scan_text, highlight_suspicious, generate_scam_email


# =============================================================================
# PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="ClearShield — Scam Message Detector",
    page_icon="🛡️",
    layout="centered",
)


# =============================================================================
# DEMO PRESET MESSAGES
# =============================================================================

DEMO_OBVIOUS_SCAM = (
    "Subject: Urgent: Your Account Has Been Locked\n"
    "Dear Customer,\n\n"
    "We noticed suspicious activity on your account. For your protection, "
    "your account has been temporarily locked. Please click here to verify "
    "your identity and unlock your account within 24 hours, or your account "
    "will be permanently deleted.\n\n"
    "Verify Account: bit.ly/account-unlock\n\n"
    "Thanks,\nThe Security Team"
)

DEMO_SUBTLE_SCAM = (
    "Hi! I hope you're doing well. I'm in a bit of a bind and need a small "
    "favor. I'm traveling and can't get to my bank. Could you pick up a "
    "couple of Amazon gift cards (about $200 total) and send me the codes? "
    "I'll pay you back as soon as I'm home. Please don't tell anyone — "
    "it's a surprise for the family."
)

DEMO_LEGIT = (
    "Hey Christian, just a reminder that our team meeting is scheduled for "
    "Thursday at 2pm in the conference room. Please let me know if you "
    "can't make it. Looking forward to seeing you there.\n\nBest,\nSarah"
)


# =============================================================================
# HEADER
# =============================================================================

st.title("🛡️ ClearShield")
st.caption("Scam Message Detector — paste a message to see what's suspicious and why.")

st.divider()


# =============================================================================
# DEMO PRESET BUTTONS
# =============================================================================

st.markdown("**Try a demo message:**")
col1, col2, col3, col4 = st.columns(4)

if "message_text_area" not in st.session_state:
    st.session_state.message_text_area = ""

with col1:
    if st.button("🚨 Obvious scam", use_container_width=True):
        st.session_state.message_text_area = DEMO_OBVIOUS_SCAM
with col2:
    if st.button("⚠️ Subtle scam", use_container_width=True):
        st.session_state.message_text_area = DEMO_SUBTLE_SCAM
with col3:
    if st.button("✅ Legitimate", use_container_width=True):
        st.session_state.message_text_area = DEMO_LEGIT
with col4:
    if st.button("🎲 Generate scam email", use_container_width=True):
        st.session_state.message_text_area = generate_scam_email()


# =============================================================================
# MESSAGE INPUT
# =============================================================================

text = st.text_area(
    "Or paste your own message:",
    height=220,
    placeholder="Paste an email or text message here...",
    key="message_text_area",
)

scan_clicked = st.button("🔍 Scan Message", type="primary", use_container_width=True)


# =============================================================================
# RESULT DISPLAY
# =============================================================================

def render_result(result: dict, original_text: str):
    """Render the scan result with color-coded status and details."""

    score = result["score"]
    label = result["label"]
    reasons = result["reasons"]
    evidence = result["evidence"]

    # --- Color-coded status banner ---
    if label == "Likely Scam":
        st.error(f"### 🚨 {label} — Risk Score: {score}/100")
    elif label == "Unsure":
        st.warning(f"### ⚠️ {label} — Risk Score: {score}/100")
    else:
        st.success(f"### ✅ {label} — Risk Score: {score}/100")

    # --- Risk score progress bar ---
    st.progress(score / 100)

    # --- Reasons ---
    st.subheader("Why this was flagged")
    if reasons:
        for reason in reasons:
            st.markdown(f"- {reason}")
    else:
        st.markdown("- No suspicious patterns detected.")

    # --- Highlighted message ---
    if evidence and label != "Likely Legit":
        st.subheader("Suspicious phrases highlighted")
        st.markdown(
            "**Legend:** :red[High-risk] • :orange[Medium-risk] • :yellow[Lower-risk]"
        )
        highlighted = highlight_suspicious(original_text)
        st.markdown(highlighted)

    # --- Evidence (technical detail, collapsible) ---
    if evidence:
        with st.expander("🔬 Detection evidence (technical detail)"):
            st.json(evidence)

    # --- Educational note (for scams only) ---
    if label == "Likely Scam":
        with st.expander("💡 Why does this work? Learn the pattern."):
            st.markdown(
                """
                Scammers use these patterns because they bypass careful thinking:

                - **Urgency language** ("act now", "within 24 hours") triggers
                  fear and makes you skip verification steps.
                - **Credential requests** mimic legitimate companies but real
                  organizations almost never ask for passwords or SSN by email.
                - **URL shorteners** hide the true destination of a link, so
                  you can't tell where you're being sent.

                When in doubt: do not click, do not reply, and contact the
                supposed sender through a known-good channel (their website,
                phone number on the back of your card, etc.) to verify.
                """
            )


if scan_clicked:
    if not text.strip():
        st.warning("Please paste a message to scan, or pick a demo above.")
    else:
        result = scan_text(text)
        render_result(result, text)


# =============================================================================
# FOOTER
# =============================================================================

st.divider()
st.caption(
    "ClearShield is a CSUB Senior Project by Christian Schmiedel. "
    "Detection is rule-based and explainable — designed to teach you the "
    "patterns scammers use so you can spot them yourself."
)