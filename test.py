import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "API is running"}

def test_scan_valid_input():
    response = client.post("/scan", json={
        "scan_name": "Test_Example_2025",
        "target": "example.com",
        "modules": "sfp_dnsresolve,sfp_whois"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["scan_name"] == "Test_Example_2025"
    assert response.json()["target"] == "example.com"

def test_scan_missing_input():
    response = client.post("/scan", json={"scan_name": "", "target": ""})
    assert response.status_code == 400
    assert "required" in response.json()["detail"]