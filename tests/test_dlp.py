import pytest
from fastapi.testclient import TestClient
from main import app, inspect_payload, redact_payload, luhn_valid, _is_upload

client = TestClient(app)


def test_luhn_valid_synthetic_card():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")


def test_labelled_id_detected_and_redacted():
    text = "Customer identity number: 123456789012"
    findings = inspect_payload(text)
    assert any(f["type"] == "NATIONAL_ID" for f in findings)
    assert "123456789012" not in redact_payload(text, findings)


def test_ambiguous_number_is_not_strong_match():
    findings = inspect_payload("Sample batch reference: 123456789012")
    assert any(f["type"] == "AMBIGUOUS_12_DIGIT" for f in findings)
    assert not any(f["type"] == "NATIONAL_ID" for f in findings)


def test_plain_text_allowed():
    response = client.post("/api/inspect", json={"payload": "Hello there"})
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_id_redacted():
    response = client.post("/api/inspect", json={"payload": "Aadhaar: 123456789012"})
    assert response.status_code == 200
    assert response.json()["decision"] == "REDACT"
    assert "123456789012" not in response.json()["payload"]


def test_upload_detector():
    assert _is_upload("POST", "multipart/form-data; boundary=x", "/upload", {})
    assert _is_upload("PUT", "application/octet-stream", "/files", {})
    assert not _is_upload("GET", "", "/", {})


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
