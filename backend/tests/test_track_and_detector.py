from typing import Any, Dict, List

import app as app_module
from honeypot.vuln_detector import VulnerabilityDetector


class _StubBlobLogger:
    def __init__(self) -> None:
        self.logged: List[Dict[str, Any]] = []

    def log(self, data: Dict[str, Any]) -> None:
        self.logged.append(data)

    def get_all_logs(self, limit: int = 1000) -> List[Dict[str, Any]]:
        return self.logged[-limit:]


class _StubVulnDetector:
    def __init__(self, findings: List[Dict[str, Any]]) -> None:
        self._findings = findings

    def detect(self, _data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return list(self._findings)


class _StubWebModel:
    def __init__(self, label: str = "benign", confidence: float = 0.0) -> None:
        self.label = label
        self.confidence = confidence

    def predict(self, _payload: str) -> Dict[str, Any]:
        return {"label": self.label, "confidence": self.confidence}


class _StubBehaviorDetector:
    def __init__(self, is_attack: bool = False, risk_level: str = "low", confidence: float = 0.0) -> None:
        self.is_attack = is_attack
        self.risk_level = risk_level
        self.confidence = confidence

    def predict(self, _data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "is_attack": self.is_attack,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
        }


class _StubCVSSCalculator:
    def __init__(self, score: float = 8.3) -> None:
        self.score = score

    def calculate_cvss(self, attack_type: str, payload: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "cvss_score": self.score,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "attack_type": attack_type,
            "payload": payload,
            "context": context,
        }


class _StubNVD:
    def fetch_cves(self, _keyword: str, limit: int = 3) -> List[str]:
        return ["CVE-2000-1233"][:limit]


class _StubAIEngine:
    def analyze(self, _detection: Dict[str, Any]) -> str:
        return "stub ai analysis"


def _patch_common_for_track(monkeypatch, *, vulnerabilities: List[Dict[str, Any]]) -> _StubBlobLogger:
    logger = _StubBlobLogger()
    monkeypatch.setattr(app_module, "blob_logger", logger)
    monkeypatch.setattr(app_module, "vuln_detector", _StubVulnDetector(vulnerabilities))
    monkeypatch.setattr(app_module, "network_model", None)
    monkeypatch.setattr(app_module, "risk_engine", None)
    monkeypatch.setattr(app_module, "deception_engine", None)
    monkeypatch.setattr(app_module, "learning_engine", None)
    return logger


def test_track_endpoint_detects_sql_injection(monkeypatch):
    vulnerabilities = [
        {
            "id": "SQLI",
            "attack_type": "sql_injection",
            "name": "SQL Injection",
            "owasp": "A03:2021 Injection",
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            "severity": "HIGH",
            "keyword": "SQL Injection",
            "remediation": "Use parameterized queries.",
            "evidence": {"field": "email", "match": "' OR 1=1--", "value": "admin' OR 1=1--"},
        }
    ]
    logger = _patch_common_for_track(monkeypatch, vulnerabilities=vulnerabilities)

    monkeypatch.setattr(app_module, "web_model", _StubWebModel(label="benign", confidence=0.0))
    monkeypatch.setattr(app_module, "behavior_detector", _StubBehaviorDetector(is_attack=False))
    monkeypatch.setattr(app_module, "cvss_calculator", _StubCVSSCalculator(score=8.3))
    monkeypatch.setattr(app_module, "nvd", _StubNVD())
    monkeypatch.setattr(app_module, "ai_engine", _StubAIEngine())

    client = app_module.app.test_client()
    payload = {
        "session_id": "test-session-1",
        "email": "admin' OR 1=1--",
        "password": "secret",
        "mouse_movements": 80,
        "keystrokes": 20,
        "time_to_submit": 3.1,
        "rapid_submission": 0,
        "honeypot_filled": 0,
    }
    response = client.post("/api/track", json=payload)

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["is_attack"] is True
    assert data["attack_type"] == "sql_injection"
    assert data["severity"] == "HIGH"
    assert data["cvss_score"] == 8.3
    assert data["owasp"] == "A03:2021 Injection"
    assert data["cve_references"] == ["CVE-2000-1233"]
    assert data["ai_analysis"] == "stub ai analysis"
    assert len(data["vulnerabilities"]) == 1

    assert len(logger.logged) == 1
    assert logger.logged[0]["password"] == "[REDACTED]"


def test_track_endpoint_returns_legitimate_for_benign_payload(monkeypatch):
    logger = _patch_common_for_track(monkeypatch, vulnerabilities=[])

    monkeypatch.setattr(app_module, "web_model", _StubWebModel(label="benign", confidence=0.0))
    monkeypatch.setattr(app_module, "behavior_detector", _StubBehaviorDetector(is_attack=False))
    monkeypatch.setattr(app_module, "cvss_calculator", _StubCVSSCalculator(score=8.3))
    monkeypatch.setattr(app_module, "nvd", None)
    monkeypatch.setattr(app_module, "ai_engine", None)

    client = app_module.app.test_client()
    payload = {
        "session_id": "test-session-2",
        "email": "user@example.com",
        "password": "GoodPass123!",
        "mouse_movements": 120,
        "keystrokes": 45,
        "time_to_submit": 6.8,
        "rapid_submission": 0,
        "honeypot_filled": 0,
    }
    response = client.post("/api/track", json=payload)

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["is_attack"] is False
    assert data["attack_type"] == "legitimate"
    assert data["severity"] == "INFO"
    assert data["cvss_score"] == 0.0
    assert data["cve_references"] == []
    assert data["ai_analysis"] is None
    assert data["vulnerabilities"] == []

    assert len(logger.logged) == 1
    assert logger.logged[0]["password"] == "[REDACTED]"


def test_vulnerability_detector_detects_sql_injection():
    detector = VulnerabilityDetector()
    findings = detector.detect({"email": "admin' OR 1=1--"})

    assert len(findings) >= 1
    first = findings[0]
    assert first["attack_type"] == "sql_injection"
    assert float(first["cvss_score"]) > 0.0
    assert first["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert "cvss_vector" in first


def test_vulnerability_detector_ignores_benign_input():
    detector = VulnerabilityDetector()
    findings = detector.detect({"email": "user@example.com", "password": "GoodPass123!"})

    assert findings == []


def test_stats_ignores_analyze_events(monkeypatch):
    logger = _StubBlobLogger()
    logger.logged = [
        {
            "session_id": "test-session-3",
            "timestamp": "2026-02-14T12:00:00",
            "is_attack": True,
            "severity": "HIGH",
            "cvss_score": 8.3,
            "attack_type": "sql_injection",
            "cve_references": ["CVE-2000-1233"],
            "mouse_movements": 24,
            "keystrokes": 11,
            "time_to_submit": 2.2,
            "paste_events": 0,
            "rapid_submission": 1,
            "honeypot_filled": 0,
        },
        {
            "session_id": "test-session-3",
            "timestamp": "2026-02-14T12:00:01",
            "attack_type": "sql_injection",
            "severity": "HIGH",
            "cvss_score": 8.3,
            "network": {"label": 1, "confidence": 90},
            "web": {"label": "sqli", "confidence": 95},
            "risk_score": 88,
            "event_timestamp": "2026-02-14T12:00:00",
        },
    ]

    monkeypatch.setattr(app_module, "blob_logger", logger)
    client = app_module.app.test_client()
    response = client.get("/api/stats")

    assert response.status_code == 200
    data = response.get_json()
    assert data["total_events"] == 1
    assert data["total_attacks"] == 1
    assert data["severity_distribution"]["HIGH"] == 1
