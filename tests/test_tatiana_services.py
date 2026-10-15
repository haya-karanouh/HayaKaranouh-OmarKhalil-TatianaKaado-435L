"""Focused service contract tests. Author: Tatiana Kaado."""
from types import SimpleNamespace
import pytest
import requests
from common.auth import create_token
from common.constants import ADMIN
from common.db import db
from common.errors import ValidationError
from common.models import Asset, User
from services.threats.app import create_app as threats_app
from services.vulnerabilities.app import create_app as vulnerabilities_app
from services.reports.app import create_app as reports_app


@pytest.fixture
def services(monkeypatch, tmp_path):
    import common.config
    from services.threats import service as threats
    from services.vulnerabilities import service as vulnerabilities
    monkeypatch.setattr(common.config, "DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    apps = {"threats": threats_app(), "vulnerabilities": vulnerabilities_app()}
    events, notifications, calls = [], [], []

    def call(method, source, path, **kwargs):
        calls.append((method, source, path, kwargs))
        if source == "users":
            assert kwargs["params"] == {"role": ADMIN}
            data = {"users": [{"id": 1}, {"id": 2}]}
        elif source == "assets":
            assert path == "/assets"
            data = {"assets": [{"id": 1, "name": "Test asset", "status": "Active"}]}
        else:
            raise AssertionError(source)
        return SimpleNamespace(status_code=200, json=lambda: {"data": data})

    for module in [threats, vulnerabilities]:
        monkeypatch.setattr(module, "call_service", call)
        monkeypatch.setattr(module, "log_event", lambda *args: events.append(args))
        monkeypatch.setattr(module, "notify", lambda *args: notifications.append(args))
    with apps["threats"].app_context():
        db.create_all()
        db.session.add(User(id=1, full_name="Test", username="test", email="test@example.com", password_hash="unused", department="Security", role=ADMIN))
        db.session.commit()
        db.session.add(Asset(id=1, name="Test asset", asset_type="Server", owner_id=1, department="Security", location="Test", criticality="Low"))
        db.session.commit()
    token = create_token({"id": 1, "username": "test", "role": ADMIN})
    headers = {"Authorization": "Bearer " + token}
    yield apps, headers, events, notifications, calls


def test_critical_threat_alerts_every_admin_and_normalizes_duplicates(services):
    apps, headers, events, notifications, _ = services
    client = apps["threats"].test_client()
    body = dict(threat_type="Domain", threat_value="Threat.Example.", description="Test", severity="Critical", source="Tests")
    response = client.post("/threats", json=body, headers=headers)
    assert response.status_code == 201
    assert response.json["data"]["threat_value"] == "threat.example"
    assert [item[0] for item in notifications] == [1, 2]
    assert all(item[3] == "Threat Alert" for item in notifications)
    assert events[0][1] == "DATA_CREATED"
    response = client.post("/threats", json={**body, "threat_value": "threat.example"}, headers=headers)
    assert response.status_code == 409
    assert len(notifications) == 2


@pytest.mark.parametrize("length", [32, 40, 64])
def test_supported_hash_algorithms(services, length):
    apps, headers, *_ = services
    response = apps["threats"].test_client().post("/threats", headers=headers, json=dict(threat_type="File Hash", threat_value="A" * length, description="Test", severity="Low", source="Tests"))
    assert response.status_code == 201
    assert response.json["data"]["threat_value"] == "a" * length


@pytest.mark.parametrize("score,severity", [(0, "Low"), (0.1, "Low"), (3.9, "Low"), (4, "Medium"), (6.9, "Medium"), (7, "High"), (8.9, "High"), (9, "Critical"), (10, "Critical")])
def test_cvss_band_boundaries(score, severity):
    from services.vulnerabilities.service import VulnerabilitiesService
    VulnerabilitiesService.validate({"cvss_score": score, "severity": severity})
    with pytest.raises(ValidationError):
        VulnerabilitiesService.validate({"cvss_score": score, "severity": "High" if severity != "High" else "Low"})


def test_vulnerability_notifications_and_strict_lifecycle(services):
    apps, headers, events, notifications, calls = services
    client = apps["vulnerabilities"].test_client()
    body = dict(title="Test", description="Test", cve_id="CVE-2026-1234", cvss_score=9.1, severity="Critical", asset_id=1, discovery_source="Tests")
    response = client.post("/vulnerabilities", json=body, headers=headers)
    assert response.status_code == 201
    path = f'/vulnerabilities/{response.json["data"]["id"]}'
    assert [item[0] for item in notifications] == [1, 2]
    assert all(item[3] == "Vulnerability Alert" for item in notifications)
    assert client.put(path, json={"status": "Open"}, headers=headers).status_code == 422
    assert client.put(path, json={"status": "Resolved"}, headers=headers).status_code == 422
    for status in ["Under Investigation", "In Progress", "Resolved", "Closed"]:
        response = client.put(path, json={"status": status}, headers=headers)
        assert response.status_code == 200
        assert response.json["data"]["status"] == status
    assert response.json["data"]["resolved_at"]
    assert client.put(path, json={"status": "Closed"}, headers=headers).status_code == 422
    assert client.put(path, json={"resolved_at": "2099-01-01"}, headers=headers).status_code == 422
    assert client.put(path, json={"cvss_score": 2}, headers=headers).status_code == 422
    assert sum(event[1] == "STATUS_CHANGED" for event in events) == 4


@pytest.mark.parametrize("failure", ["timeout", "http", "payload"])
def test_report_source_failures_return_503(monkeypatch, failure):
    from services.reports import service
    def call(*args, **kwargs):
        if failure == "timeout":
            raise requests.Timeout("test outage")
        return SimpleNamespace(status_code=503 if failure == "http" else 200, json=lambda: {"data": {"assets": "invalid"}})
    monkeypatch.setattr(service, "call_service", call)
    token = create_token({"id": 1, "username": "test", "role": ADMIN})
    response = reports_app().test_client().get("/reports/assets", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 503
    assert "Assets" in response.json["message"]
