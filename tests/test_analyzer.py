"""End-to-end tests for the MailGuard API and scoring engine."""

import pytest
from fastapi.testclient import TestClient

from backend.main import API_KEY, MAX_REQUEST_BYTES, app

AUTH = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def analyze(client: TestClient, payload: dict) -> dict:
    response = client.post("/analyze", json=payload, headers=AUTH)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Detection scenarios
# ---------------------------------------------------------------------------


def test_clean_email_is_low_risk(client):
    result = analyze(client, {
        "sender_name": "Alice Cohen",
        "sender_email": "alice@company.com",
        "subject": "Lunch tomorrow?",
        "body_plain": "Want to grab lunch at noon? Here is the place: https://maps.google.com/place",
    })

    assert result["verdict"] == "Low"
    assert result["score"] < 20
    assert result["attack_type"] == "None Detected"
    assert result["findings"] == []


def test_credential_phishing_with_link_mismatch(client):
    result = analyze(client, {
        "sender_name": "PayPal Support",
        "sender_email": "service@paypa1-security.xyz",
        "reply_to": "collect@gmail.com",
        "subject": "URGENT: your account is suspended",
        "body_html": (
            "<p>Your account has been suspended. Verify your account and password "
            "within 24 hours.</p>"
            '<a href="http://198.51.100.7/login">www.paypal.com</a>'
            '<a href="https://paypal.com@evil.top/x">Log in to PayPal</a>'
        ),
    })

    assert result["verdict"] in {"High", "Critical"}
    assert result["attack_type"] == "Credential Phishing"
    assert result["category_scores"]["links"] == 40
    assert any("Link text shows one domain" in f and "198.51.100.7" in f for f in result["findings"])
    assert any("user@host" in f for f in result["findings"])


def test_malware_attachment_triggers_critical_override(client):
    result = analyze(client, {
        "sender_email": "hr@corp-mail.com",
        "subject": "Salary update",
        "body_plain": "Please review the attached document.",
        "attachment_names": ["salary_update.pdf.exe"],
    })

    # The content category is still capped, but the override lifts the total.
    assert result["category_scores"]["content"] <= 25
    assert result["score"] >= 75
    assert result["verdict"] == "Critical"
    assert result["attack_type"] == "Malware Delivery"
    assert "overrides the weighted score" in result["explanation"]
    assert "dangerous executable file type (.exe)" in result["findings"][0]
    # The untrusted attachment name is never echoed back.
    assert not any("salary_update" in f for f in result["findings"])


def test_bec_wire_transfer_request(client):
    result = analyze(client, {
        "sender_name": "David Levi (CEO)",
        "sender_email": "david@acme.com",
        "reply_to": "david.acme.ceo@outlook.com",
        "subject": "Urgent wire transfer",
        "body_plain": (
            "I need you to process a wire transfer urgently and immediately. "
            "I will send the bank details. This is confidential."
        ),
    })

    assert result["verdict"] in {"Medium", "High"}
    assert result["attack_type"] == "Business Email Compromise (BEC)"
    assert result["category_scores"]["sender"] >= 20
    assert any("Replies would go to a different domain" in f for f in result["findings"])


def test_macro_document_does_not_trigger_override(client):
    result = analyze(client, {
        "sender_email": "billing@vendor.com",
        "subject": "Report",
        "attachment_names": ["report.xlsm"],
    })

    assert result["verdict"] != "Critical"
    assert result["score"] < 75


# ---------------------------------------------------------------------------
# Security controls
# ---------------------------------------------------------------------------

MINIMAL = {"sender_email": "a@b.com", "subject": "hi"}


def test_health_needs_no_auth(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_missing_api_key_is_rejected(client):
    assert client.post("/analyze", json=MINIMAL).status_code == 401


def test_wrong_api_key_is_rejected(client):
    response = client.post("/analyze", json=MINIMAL, headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 401


def test_oversized_payload_is_rejected(client):
    payload = {**MINIMAL, "body_plain": "A" * (MAX_REQUEST_BYTES + 1)}
    response = client.post("/analyze", json=payload, headers=AUTH)
    assert response.status_code == 413


def test_oversized_chunked_payload_without_content_length_is_rejected(client):
    def chunks():
        for _ in range(20):
            yield b"A" * 100_000  # 2 MB in total, streamed with no Content-Length

    response = client.post(
        "/analyze", content=chunks(),
        headers={**AUTH, "Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_unknown_fields_are_rejected(client):
    response = client.post("/analyze", json={**MINIMAL, "evil": "x"}, headers=AUTH)
    assert response.status_code == 422


def test_field_length_limits_are_enforced(client):
    response = client.post("/analyze", json={**MINIMAL, "subject": "x" * 5_000}, headers=AUTH)
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Hardening fixes (from the Interview Defense review)
# ---------------------------------------------------------------------------


def test_padding_past_scanner_limit_is_flagged(client):
    result = analyze(client, {
        **MINIMAL,
        "body_html": "<!--" + "x" * 100_000 + '--><a href="https://evil.top/login">Sign in</a>',
    })

    assert result["category_scores"]["evasion"] == 40
    assert result["verdict"] in {"Medium", "High", "Critical"}
    assert any("100,000 characters" in f for f in result["findings"])


def test_padding_flag_fires_at_the_addon_truncation_cap(client):
    # The add-on cuts plain bodies to exactly 100,000 characters.
    result = analyze(client, {**MINIMAL, "body_plain": "a " * 50_000})
    assert result["category_scores"]["evasion"] == 40
    assert result["attack_type"] == "Detection Evasion"


def test_normal_sized_body_is_not_flagged(client):
    result = analyze(client, {**MINIMAL, "body_plain": "Lunch at noon? " * 100})
    assert result["category_scores"]["evasion"] == 0


def test_multiple_reply_to_addresses_are_detected(client):
    # Previously strict parseaddr returned nothing and the check was skipped (score 3).
    result = analyze(client, {
        "sender_email": "ceo@acme.com",
        "reply_to": "ceo@acme.com, attacker@evil.com",
        "subject": "Wire transfer today",
        "body_plain": "Please process the wire transfer.",
    })

    assert result["category_scores"]["evasion"] == 40
    assert any("lists 2 addresses" in f for f in result["findings"])
    assert any("evil.com" in f and "different domain" in f for f in result["findings"])
    assert result["verdict"] in {"High", "Critical"}
    assert result["attack_type"] == "Business Email Compromise (BEC)"


def test_malformed_reply_to_is_a_signal_not_ignored(client):
    result = analyze(client, {**MINIMAL, "reply_to": "<<<not an address"})
    assert any("Reply-To header is malformed" in f for f in result["findings"])


def test_backslash_url_trick_reports_the_real_host(client):
    result = analyze(client, {
        **MINIMAL,
        "body_html": r'<a href="https://evil.com\@paypal.com/login">paypal.com</a>',
    })

    findings = " ".join(result["findings"])
    assert result["category_scores"]["evasion"] == 40
    assert "backslash trick" in findings
    # Analyzed as the browser resolves it: the real destination is evil.com.
    assert "paypal.com -> evil.com" in findings
    assert result["verdict"] in {"High", "Critical"}
    assert result["attack_type"] == "Credential Phishing"


def test_encrypted_archive_with_password_in_body(client):
    result = analyze(client, {
        **MINIMAL,
        "subject": "Invoice 4471",
        "body_plain": "Please see the attached invoice. Archive password: 4471",
        "attachment_names": ["invoice.zip"],
    })

    assert result["category_scores"]["evasion"] == 40
    assert result["verdict"] in {"High", "Critical"}
    assert result["attack_type"] == "Malware Delivery"


def test_archive_without_password_is_not_escalated(client):
    result = analyze(client, {
        **MINIMAL,
        "body_plain": "Photos from the offsite are attached.",
        "attachment_names": ["photos.zip"],
    })
    assert result["category_scores"]["evasion"] == 0


def test_api_docs_are_not_exposed(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_validation_errors_do_not_echo_email_content(client):
    secret_subject = "CONFIDENTIAL-MERGER-" + "x" * 5_000
    response = client.post("/analyze", json={**MINIMAL, "subject": secret_subject}, headers=AUTH)

    assert response.status_code == 422
    assert "CONFIDENTIAL-MERGER" not in response.text
    error = response.json()["detail"][0]
    assert set(error) == {"loc", "type"}
    assert error["loc"] == ["body", "subject"]


# ---------------------------------------------------------------------------
# Startup configuration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "   "])
def test_server_refuses_to_start_without_api_key(value):
    import os
    import subprocess
    import sys
    from pathlib import Path

    env = {k: v for k, v in os.environ.items() if k != "MAILGUARD_API_KEY"}
    if value is not None:
        env["MAILGUARD_API_KEY"] = value

    result = subprocess.run(
        [sys.executable, "-c", "import backend.main"],
        cwd=Path(__file__).resolve().parent.parent,
        env=env, capture_output=True, text=True, timeout=60,
    )

    assert result.returncode != 0
    assert "MAILGUARD_API_KEY is not set" in result.stderr
