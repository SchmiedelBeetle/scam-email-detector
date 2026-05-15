"""
Test suite for ClearShield scam detection engine.

Tests cover:
  - Known-scam patterns (should classify as Likely Scam)
  - Legitimate messages (should classify as Likely Legit)
  - Edge cases (empty input, very short input, ambiguous messages)
  - Specific feature behavior (URL extraction, shortener detection,
    word-boundary matching, diminishing returns scoring)

Run with: pytest tests.py -v
Or:       python3 tests.py
"""

import unittest
from scanner import scan_text, extract_urls, _find_phrases, highlight_suspicious, generate_scam_email


# =============================================================================
# CLASSIFICATION TESTS — Known scam patterns
# =============================================================================

class TestKnownScams(unittest.TestCase):
    """Messages that real scammers send. Should classify as Likely Scam."""

    def test_account_locked_phishing(self):
        """The classic 'your account is locked' phishing pattern."""
        msg = """Subject: Urgent: Your Account Has Been Locked
        We noticed suspicious activity. Please click here to verify your
        identity within 24 hours or your account will be permanently deleted."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Scam",
                         f"Expected Likely Scam, got {result['label']} with score {result['score']}")
        self.assertGreaterEqual(result["score"], 60)

    def test_bank_credential_phishing(self):
        """A bank impersonation phishing attempt."""
        msg = """URGENT: Unusual activity detected on your bank account.
        Please verify your account immediately by confirming your password,
        social security number, and bank account number. Act now to avoid
        suspension."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Scam")
        self.assertGreaterEqual(result["score"], 60)

    def test_gift_card_scam(self):
        """The 'buy gift cards' scam — common against older adults."""
        msg = """Hello, this is urgent. I need you to purchase 5 Amazon gift
        cards immediately and send me the codes. This is for an emergency
        situation. Do not delay. Time sensitive."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Scam")

    def test_lottery_scam(self):
        """Classic lottery/prize scam."""
        msg = """Congratulations! You have won the international lottery!
        To claim your prize, please send the processing fee via wire transfer
        and confirm your bank account details immediately."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Scam")

    def test_irs_refund_scam(self):
        """Fake IRS refund — common tax-season scam."""
        msg = """IRS Notice: You are eligible for a tax refund of $1,840.
        To process your refund, please verify your social security number
        and bank routing number within 48 hours."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Scam")

    def test_phishing_with_shortener(self):
        """Phishing with a bit.ly link — extra suspicious."""
        msg = """Your package delivery is on hold. Action required:
        verify your address at bit.ly/track-pkg2024 within 24 hours."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Scam")
        self.assertIn("url_shorteners", result["evidence"])

    def test_crypto_scam(self):
        """Crypto investment scam pattern."""
        msg = """Final notice — claim your bitcoin reward today!
        Send your wallet credentials to verify your account immediately
        before this limited time offer expires."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Scam")

    def test_generated_scam_email_is_scary(self):
        """Generated scam emails should be classified as Likely Scam."""
        generated = generate_scam_email()
        result = scan_text(generated)
        self.assertEqual(result["label"], "Likely Scam")
        self.assertGreaterEqual(result["score"], 60)
        self.assertIn("Subject:", generated)


# =============================================================================
# CLASSIFICATION TESTS — Legitimate messages
# =============================================================================

class TestLegitimateMessages(unittest.TestCase):
    """Real, ordinary messages. Should NOT classify as scams."""

    def test_friendly_meeting_reminder(self):
        """A normal work message."""
        msg = """Hi Christian, just a reminder that our team meeting is
        scheduled for Thursday at 2pm in the conference room. Let me know
        if you can't make it. Best, Sarah."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Legit")

    def test_family_text(self):
        """A casual family message."""
        msg = """Hey, dinner at mom's tomorrow at 6? She made lasagna and
        wants the whole family there. Let me know if you can make it."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Legit")

    def test_legit_newsletter(self):
        """A legitimate newsletter — has a link but no scam patterns."""
        msg = """This month's tech newsletter: read about the latest
        developments in cybersecurity research at example.com/news.
        Thanks for subscribing!"""
        result = scan_text(msg)
        # A link alone shouldn't flag this as a scam
        self.assertNotEqual(result["label"], "Likely Scam")

    def test_appointment_confirmation(self):
        """A dentist appointment reminder."""
        msg = """Your dental appointment is confirmed for May 20 at 10am.
        Please arrive 10 minutes early to complete paperwork."""
        result = scan_text(msg)
        self.assertEqual(result["label"], "Likely Legit")


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases(unittest.TestCase):
    """Inputs that test the boundaries of the detection logic."""

    def test_empty_string(self):
        """Empty input should return Unsure with explanation."""
        result = scan_text("")
        self.assertEqual(result["label"], "Unsure")
        self.assertEqual(result["score"], 0)

    def test_whitespace_only(self):
        """Whitespace-only input should be treated as empty."""
        result = scan_text("    \n\n   ")
        self.assertEqual(result["label"], "Unsure")

    def test_very_short_message(self):
        """Too-short messages should not be classified."""
        result = scan_text("Hi")
        self.assertEqual(result["label"], "Unsure")
        self.assertIn("too short", result["reasons"][0].lower())

    def test_ambiguous_urgent_legit(self):
        """An urgent but legit message — should likely be Unsure, not Scam."""
        msg = """Hi team, this is urgent — the deadline for the quarterly
        report has moved up to Friday. Please prioritize accordingly."""
        result = scan_text(msg)
        # One urgency word alone shouldn't trigger Likely Scam
        self.assertNotEqual(result["label"], "Likely Scam")


# =============================================================================
# COMPONENT TESTS — URL extraction
# =============================================================================

class TestURLExtraction(unittest.TestCase):
    def test_full_https_url(self):
        urls = extract_urls("Visit https://example.com/page for details.")
        self.assertEqual(len(urls), 1)
        self.assertIn("example.com", urls[0])

    def test_bare_www_url(self):
        urls = extract_urls("Go to www.example.com today.")
        self.assertEqual(len(urls), 1)

    def test_multiple_urls(self):
        urls = extract_urls("Try https://a.com or https://b.com")
        self.assertEqual(len(urls), 2)

    def test_no_urls(self):
        urls = extract_urls("No links here, just plain text.")
        self.assertEqual(urls, [])

    def test_shortener_detected(self):
        msg = "Click bit.ly/abc123 to verify."
        result = scan_text(msg + " Please verify your account immediately to avoid suspension.")
        self.assertIn("url_shorteners", result["evidence"])


# =============================================================================
# COMPONENT TESTS — Word boundary matching
# =============================================================================

class TestWordBoundaryMatching(unittest.TestCase):
    """Ensure 'urgent' doesn't falsely match inside 'urgently' etc."""

    def test_phrase_match_basic(self):
        """Exact word should match."""
        hits = _find_phrases("This is urgent business.", ["urgent"])
        self.assertIn("urgent", hits)

    def test_phrase_does_not_match_substring(self):
        """The word 'verify' should not match inside 'verifying' or 'verification'."""
        hits = _find_phrases("The verification process is ongoing.", ["verify"])
        self.assertEqual(hits, [])

    def test_multiword_phrase_matches(self):
        """Multi-word phrases should still match correctly."""
        hits = _find_phrases(
            "Please verify your account today.",
            ["verify your account"]
        )
        self.assertIn("verify your account", hits)

    def test_case_insensitive(self):
        """Matching should be case-insensitive."""
        hits = _find_phrases("URGENT! Act NOW!", ["urgent", "act now"])
        self.assertIn("urgent", hits)
        self.assertIn("act now", hits)


# =============================================================================
# COMPONENT TESTS — Highlighting
# =============================================================================

class TestHighlighting(unittest.TestCase):
    """The UI's highlight feature should wrap suspicious phrases."""

    def test_highlights_urgent(self):
        result = highlight_suspicious("This is urgent. Please act now.")
        self.assertIn(":red[", result)
        self.assertIn("urgent", result.lower())

    def test_highlight_color_coding(self):
        result = highlight_suspicious("Urgent! Please click here and send a gift card.")
        self.assertIn(":red[Urgent]", result)
        self.assertTrue(
            ":yellow[click here]" in result or ":orange[gift card]" in result,
            "Expected medium or lower-risk highlights for click here/gift card"
        )

    def test_leaves_clean_text_alone(self):
        """No suspicious phrases means no highlights."""
        clean = "Looking forward to seeing you at the meeting tomorrow."
        result = highlight_suspicious(clean)
        self.assertNotIn(":red[", result)


# =============================================================================
# SCORING CALIBRATION TESTS
# =============================================================================

class TestScoringCalibration(unittest.TestCase):
    """Verify the score boundaries between labels are sensible."""

    def test_score_range(self):
        """Score must always be 0 <= score <= 100."""
        # Try a message packed with every kind of red flag
        kitchen_sink = ("URGENT! Act now! Final notice! Your account has been locked. "
                        "Verify your identity, confirm your password, and submit your "
                        "social security number. Send a gift card or wire transfer "
                        "immediately. Click here: bit.ly/abc")
        result = scan_text(kitchen_sink)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_label_thresholds(self):
        """Scores at/above 60 should be Scam; 30-59 Unsure; below 30 Legit."""
        # We're not testing the boundary inputs directly because score
        # generation is non-linear, but we can verify the label logic
        # by trying inputs we know produce different categories of risk.
        clean = "Hi, hope you're well. Let's catch up next week."
        scam = ("URGENT: Verify your account password immediately. "
                "Click here to confirm your social security number "
                "or your account will be permanently deleted within 24 hours.")
        self.assertEqual(scan_text(clean)["label"], "Likely Legit")
        self.assertEqual(scan_text(scam)["label"], "Likely Scam")


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
