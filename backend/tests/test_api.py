import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from app.models import CheckStatus

client = TestClient(app, headers={"X-API-Key": "test-api-key"})

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    print("PASS: /health")

def test_api_key_required_and_health_remains_public(monkeypatch):
    anonymous_client = TestClient(app)
    payload = {"domain": "invalid_domain"}

    assert anonymous_client.get("/health").status_code == 200
    preflight = anonymous_client.options(
        "/api/scan",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert preflight.status_code == 200
    assert anonymous_client.post("/api/scan", json=payload).status_code == 401
    assert TestClient(app, headers={"X-API-Key": "wrong-key"}).post(
        "/api/scan", json=payload
    ).status_code == 401
    assert client.post("/api/scan", json=payload).status_code == 422

    monkeypatch.delenv("AEGIS_API_KEY")
    assert client.post("/api/scan", json=payload).status_code == 503

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "aegiscrypta-api" in response.json()["service"] or "securemailscope-api" in response.json()["service"]
    print("PASS: /")

def test_invalid_domain_format():
    response = client.post("/api/scan", json={"domain": "invalid_domain_with_no_tld"})
    assert response.status_code == 422  # Pydantic validation error
    print("PASS: Invalid domain format rejected")

def test_unresolvable_domain():
    response = client.post("/api/scan", json={"domain": "nonexistent-domain-xyz-123456789.com"})
    assert response.status_code in [200, 400]
    if response.status_code == 200:
        data = response.json()
        assert data["score"] <= 50  # Should evaluate to low score/F grade (40-50)
    print("PASS: Nonexistent domain handled safely")

def test_scan_google():
    response = client.post("/api/scan", json={"domain": "google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "google.com"
    assert "score" in data
    assert 0 <= data["score"] <= 100
    assert len(data["checks"]) >= 4
    
    check_names = {c["name"] for c in data["checks"]}
    assert "SPF" in check_names
    assert "DMARC" in check_names
    
    # Google should have passing SPF
    spf_check = next(c for c in data["checks"] if c["name"] == "SPF")
    assert spf_check["status"] == CheckStatus.PASS.value
    
    dmarc_check = next(c for c in data["checks"] if c["name"] == "DMARC")
    assert dmarc_check["status"] in [CheckStatus.PASS.value, CheckStatus.WARN.value]

    print(f"PASS: google.com scan passed with score {data['score']}/100")

def test_scan_pdf_google():
    response = client.post("/api/scan/pdf", json={"domain": "google.com"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    content = response.content
    assert content.startswith(b"%PDF-")
    assert len(content) > 1000
    print(f"PASS: google.com PDF generation successful ({len(content)} bytes)")

if __name__ == "__main__":
    test_health()
    test_root()
    test_invalid_domain_format()
    test_unresolvable_domain()
    test_scan_google()
    test_scan_pdf_google()
    print("\nALL VERIFICATION TESTS PASSED SUCCESSFULLY!")
