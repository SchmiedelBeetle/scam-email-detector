"""
ClearShield — Streamlit Web Interface

A polished, explainable scam message detector built for everyday users.

Author: Christian Schmiedel
Project: CSUB Senior Project (CMPS) — Information Security
"""

import streamlit as st
from scanner import scan_text, highlight_suspicious


# =============================================================================
# PAGE CONFIG
# =============================================================================

st.set_page_config(
    page_title="ClearShield — Scam Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# =============================================================================
# THEME OPTIONS
# =============================================================================

dark_mode = st.sidebar.checkbox(
    "Dark mode",
    value=False,
    help="Enable a dark theme for the ClearShield interface.",
)


# =============================================================================
# CUSTOM STYLING
# =============================================================================
# Streamlit's defaults look like "demo." A bit of CSS makes it look like
# "product." Keeps brand colors consistent with the pitch deck.

page_bg = "#020617" if dark_mode else "#ffffff"
block_bg = "#0f172a" if dark_mode else "#ffffff"
panel_bg = "#111827" if dark_mode else "#f8fafc"
card_scam_bg = "linear-gradient(135deg, #7F1D1D 0%, #B91C1C 100%)" if dark_mode else "linear-gradient(135deg, #FEE2E2 0%, #FECACA 100%)"
card_unsure_bg = "linear-gradient(135deg, #78350F 0%, #D97706 100%)" if dark_mode else "linear-gradient(135deg, #FEF3C7 0%, #FDE68A 100%)"
card_legit_bg = "linear-gradient(135deg, #14532D 0%, #22C55E 100%)" if dark_mode else "linear-gradient(135deg, #DCFCE7 0%, #BBF7D0 100%)"
text_color = "#E2E8F0" if dark_mode else "#0F172A"
tagline_color = "#94A3B8" if dark_mode else "#64748B"
border_color = "#334155" if dark_mode else "#E2E8F0"
button_bg = "#1F2937" if dark_mode else "#ffffff"
button_text = "#E2E8F0" if dark_mode else "#0F172A"

st.markdown(
    f"""
    <style>
    /* Force the full page to dark theme when enabled */
    html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stMainContent"], [data-testid="stSidebar"] {{
        background-color: {block_bg} !important;
        color: {text_color} !important;
    }}

    .block-container {{
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1300px;
        background-color: {block_bg} !important;
        color: {text_color} !important;
    }}

    html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stMainContent"], [data-testid="stSidebar"], [data-testid="stToolbar"] {{
        background-color: {block_bg} !important;
        color: {text_color} !important;
    }}

    .css-18e3th9, .css-1d391kg, .css-1y4p8pa, .css-5omu6h, .css-hi6a2p, .css-17lntkn {{
        background-color: {block_bg} !important;
        color: {text_color} !important;
    }}

    /* Brand header */
    .clearshield-header {{
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 0.25rem;
    }}
    .clearshield-logo {{
        font-size: 2.5rem;
    }}
    .clearshield-title {{
        font-size: 2.2rem;
        font-weight: 700;
        color: #0F766E;
        margin: 0;
        line-height: 1;
    }}
    .clearshield-tagline {{
        color: {tagline_color};
        font-size: 1rem;
        margin: 0.25rem 0 1rem 0;
    }}

    /* Result cards */
    .result-card {{
        padding: 1.25rem;
        border-radius: 0.75rem;
        margin-bottom: 1rem;
    }}
    .result-scam {{
        background: {card_scam_bg};
        border-left: 6px solid #DC2626;
    }}
    .result-unsure {{
        background: {card_unsure_bg};
        border-left: 6px solid #EAB308;
    }}
    .result-legit {{
        background: {card_legit_bg};
        border-left: 6px solid #16A34A;
    }}
    .result-label {{
        font-size: 1.5rem;
        font-weight: 700;
        margin: 0;
    }}
    .result-score {{
        font-size: 3rem;
        font-weight: 800;
        margin: 0.5rem 0;
        line-height: 1;
    }}

    /* Widget theme */
    .stTextArea textarea,
    .stSelectbox select,
    .stButton button,
    .stTextInput input,
    .stMarkdown p,
    .stMarkdown h1,
    .stMarkdown h2,
    .stMarkdown h3,
    .stMarkdown h4,
    .stMarkdown h5,
    .stMarkdown h6 {{
        background-color: {button_bg} !important;
        color: {button_text} !important;
        border-color: {border_color} !important;
    }}

    .stButton button {{
        border-radius: 0.5rem;
        font-weight: 500;
    }}

    .footer-text {{
        color: {tagline_color};
        font-size: 0.85rem;
        text-align: center;
        margin-top: 2rem;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# =============================================================================
# TEST MESSAGE LIBRARY
# =============================================================================
# A curated set of example messages covering the major scam categories
# documented by the FTC, Anti-Phishing Working Group, and AARP. Each entry
# pairs a label with a sample message representative of that real-world
# pattern. These same messages double as the test corpus for the calibration
# study documented in the project report.

EXAMPLE_MESSAGES = {
    # --- Scam examples ---
    "🚨 Bank account locked (phishing)": (
        "Subject: Urgent: Your Account Has Been Locked\n\n"
        "Dear Customer,\n\n"
        "We noticed suspicious activity on your account. For your protection, "
        "your account has been temporarily locked. Please click here to verify "
        "your identity and unlock your account within 24 hours, or your account "
        "will be permanently deleted.\n\n"
        "Verify Account: bit.ly/account-unlock\n\n"
        "Thanks,\nThe Security Team"
    ),
    "💳 Gift card scam (urgent favor)": (
        "Hi! I hope you're doing well. I'm in a bit of a bind and need a "
        "small favor. I'm traveling and can't get to my bank. Could you pick "
        "up a couple of Amazon gift cards (about $200 total) and send me the "
        "codes? I'll pay you back as soon as I'm home. Please don't tell "
        "anyone — it's a surprise for the family. Time sensitive."
    ),
    "🏆 Lottery / prize scam": (
        "CONGRATULATIONS! You have been selected as the winner of the "
        "International Email Lottery! Your prize amount is $1,500,000 USD. "
        "To claim your prize, please confirm your bank account number, "
        "routing number, and a small processing fee via wire transfer. "
        "Reply immediately — this offer expires in 48 hours."
    ),
    "📦 Package delivery (smishing)": (
        "USPS NOTICE: Your package delivery is on hold due to an incomplete "
        "address. Action required: please verify your address at "
        "bit.ly/usps-track-pkg2024 within 24 hours or your package will be "
        "returned to the sender."
    ),
    "💼 Fake job offer": (
        "Hello, we found your resume online and you have been pre-selected "
        "for a remote position at our company. The salary is $5,000/week. "
        "To begin onboarding, please confirm your social security number "
        "and bank account details for direct deposit setup. Reply within "
        "24 hours to secure this position."
    ),
    "🪙 Crypto / investment scam": (
        "Final notice — claim your free bitcoin reward today! You have been "
        "selected for an exclusive crypto giveaway. To verify your account "
        "and receive your $5,000 in BTC, send your wallet credentials and "
        "a small verification fee immediately before this limited time offer "
        "expires."
    ),
    "🏛️ IRS / tax refund scam": (
        "IRS Notice: Our records show you are eligible for a tax refund of "
        "$1,840. To process your refund, please verify your social security "
        "number and bank routing number within 48 hours by clicking the "
        "secure link below. Failure to respond will result in forfeiture "
        "of your refund."
    ),

    # --- Legit examples ---
    "✅ Meeting reminder (legit)": (
        "Hey Christian, just a reminder that our team meeting is scheduled "
        "for Thursday at 2pm in the conference room. Please let me know if "
        "you can't make it. Looking forward to seeing you there.\n\n"
        "Best,\nSarah"
    ),
    "✅ Family text (legit)": (
        "Hey, dinner at mom's tomorrow at 6? She made lasagna and wants "
        "the whole family there. Let me know if you can make it. Love you."
    ),
    "✅ Order confirmation (legit)": (
        "Thanks for your order! Your shipment from BookHaven is on its way. "
        "Tracking number: BH-2026-58291. Estimated delivery: May 18. You "
        "can view your full order details by signing in to your account at "
        "bookhaven.com. Thank you for shopping with us."
    ),
    "⚠️ Urgent legit (deadline)": (
        "Hi team, this is urgent — the deadline for the quarterly report "
        "has moved up to Friday. Please prioritize accordingly and let me "
        "know if you need any help. We need to act fast on this one."
    ),
    "✅ Newsletter (legit)": (
        "This month's CSUB Computer Science newsletter: read about the "
        "latest student research projects, faculty publications, and "
        "upcoming events at csub.edu/cs/news. Thanks for subscribing!"
    ),
}


# =============================================================================
# SESSION STATE
# =============================================================================

if "message_input" not in st.session_state:
    st.session_state.message_input = ""
if "last_example" not in st.session_state:
    st.session_state.last_example = None


# =============================================================================
# HEADER
# =============================================================================

st.markdown(
    """
    <div class="clearshield-header">
        <div class="clearshield-logo">🛡️</div>
        <h1 class="clearshield-title">ClearShield</h1>
    </div>
    <p class="clearshield-tagline">
        Paste any suspicious email or text message. See if it's a scam — and why.
    </p>
    """,
    unsafe_allow_html=True,
)

st.divider()


# =============================================================================
# MAIN LAYOUT — SIDE BY SIDE (no scrolling to see results)
# =============================================================================

left_col, right_col = st.columns([1, 1], gap="large")


# -----------------------------------------------------------------------------
# LEFT: INPUT
# -----------------------------------------------------------------------------

with left_col:
    st.markdown("### 📥 Message to scan")

    # Example library dropdown — much more compact than 3 buttons
    example_key = st.selectbox(
        "Try an example from our test library",
        options=["— Select an example —"] + list(EXAMPLE_MESSAGES.keys()),
        index=0,
        help="A curated library of 12 example messages — 7 scam patterns and "
             "5 legitimate messages — used in our calibration study.",
    )

    if example_key != "— Select an example —":
        if st.session_state.last_example != example_key:
            st.session_state.message_input = EXAMPLE_MESSAGES[example_key]
            st.session_state.last_example = example_key

    text = st.text_area(
        "Or paste your own message",
        value=st.session_state.message_input,
        height=280,
        placeholder="Paste an email or text message here...",
        key="message_input",
        label_visibility="visible",
    )

    scan_clicked = st.button(
        "🔍  Scan Message",
        type="primary",
        use_container_width=True,
    )


# -----------------------------------------------------------------------------
# RIGHT: RESULT
# -----------------------------------------------------------------------------

with right_col:
    st.markdown("### 📊 Result")

    # Trigger scan only when the user clicks the scan button
    should_scan = scan_clicked
    if should_scan and text.strip():
        result = scan_text(text)
        score = result["score"]
        label = result["label"]
        reasons = result["reasons"]
        evidence = result["evidence"]

        # --- Color-coded result card ---
        if label == "Likely Scam":
            css_class = "result-scam"
            icon = "🚨"
            color = "#DC2626"
        elif label == "Unsure":
            css_class = "result-unsure"
            icon = "⚠️"
            color = "#B45309"
        else:
            css_class = "result-legit"
            icon = "✅"
            color = "#15803D"

        st.markdown(
            f"""
            <div class="result-card {css_class}">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <p class="result-label" style="color:{color};">{icon} {label}</p>
                        <p style="margin:0.25rem 0 0 0; color:#475569;">Risk Score</p>
                        <p class="result-score" style="color:{color};">{score}<span style="font-size:1.2rem; color:#64748B;"> / 100</span></p>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # --- Reasons ---
        st.markdown("**Why this was flagged:**")
        if reasons:
            for reason in reasons:
                st.markdown(f"- {reason}")

        # --- Highlighted phrases (only show if Scam or Unsure) ---
        if evidence and label != "Likely Legit":
            with st.expander("🔍 See suspicious phrases highlighted", expanded=False):
                highlighted = highlight_suspicious(text)
                st.markdown(highlighted)

        # --- Evidence (technical detail) ---
        if evidence:
            with st.expander("🔬 Detection evidence (technical detail)"):
                st.json(evidence)

        # --- Educational explainer (scams only) ---
        if label == "Likely Scam":
            with st.expander("💡 Why does this scam pattern work?"):
                st.markdown(
                    """
                    Scammers use these patterns because they bypass careful thinking:

                    - **Urgency language** triggers fear and short-circuits verification.
                    - **Credential requests** mimic real companies, but legitimate
                      organizations almost never ask for passwords or SSN by email or text.
                    - **URL shorteners** hide the true destination of a link — so you
                      can't see where you'd really be sent.

                    **When in doubt:** do not click, do not reply. Contact the supposed
                    sender through a known-good channel (their website, the phone number
                    on the back of your card) to verify.
                    """
                )

    elif should_scan and not text.strip():
        st.warning("⚠️ Please paste a message or choose an example first.")
    else:
        # Empty state
        st.markdown(
            """
            <div style="padding:2rem; text-align:center; color:#94A3B8; border:2px dashed #E2E8F0; border-radius:0.75rem;">
                <div style="font-size:3rem; margin-bottom:0.5rem;">📭</div>
                <p style="margin:0; font-weight:500;">No message scanned yet</p>
                <p style="margin:0.25rem 0 0 0; font-size:0.9rem;">
                    Paste a message on the left, or select an example to see how it works.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# =============================================================================
# FOOTER
# =============================================================================

st.divider()
st.markdown(
    """
    <p class="footer-text">
        ClearShield • CSUB Senior Project by Christian Schmiedel •
        Rule-based, explainable scam detection.
    </p>
    """,
    unsafe_allow_html=True,
)
