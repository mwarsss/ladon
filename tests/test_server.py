"""
Unit tests for the FastAPI Server API endpoints (agentwall/server.py).
"""

import pytest
from fastapi.testclient import TestClient

from agentwall.server import app

client = TestClient(app)


def test_index_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "AGENTWALL" in response.text


def test_get_scenarios():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert "scenarios" in data
    scenario_ids = [s["id"] for s in data["scenarios"]]
    assert "a_attack_email" in scenario_ids
    assert "b_protected_defense" in scenario_ids
    assert "c_benign_inbox" in scenario_ids
    assert "d_verify_bank_change" in scenario_ids
    assert "e_tamper_evident" in scenario_ids


def test_get_status():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "is_running" in data
    assert "mode" in data


def test_verify_log_endpoint():
    response = client.post("/api/verify-log")
    assert response.status_code == 200
    data = response.json()
    assert "valid" in data
    assert "message" in data


def test_system_reset():
    response = client.post("/api/reset")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "reset"
