import os
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

from ai.claude_engine import ClaudeEngine
from deception.deception_engine import DeceptionEngine
from fusion.risk_engine import RiskEngine
from honeypot.behavior_detector import AttackDetector
from honeypot.blob_logger import BlobLogger
from honeypot.vuln_detector import VulnerabilityDetector
from intel.nvd_lookup import NVDLookup
from ml.network_model import NetworkModel
from ml.web_model import WebAttackModel

app = Flask(__name__)
CORS(app)


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0.0:
        return "LOW"
    return "INFO"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _event_is_attack(event: Dict[str, Any]) -> bool:
    if isinstance(event.get("is_attack"), bool):
        return bool(event["is_attack"])
    if event.get("vulnerabilities"):
        return True
    return _safe_float(event.get("cvss_score")) > 0.0


def _compute_is_bot(payload: Dict[str, Any], behavior_result: Dict[str, Any]) -> bool:
    # Heuristic: rapid + low interaction OR honeypot field filled.
    rapid = _safe_int(payload.get("rapid_submission")) == 1
    honeypot_filled = _safe_int(payload.get("honeypot_filled")) == 1
    low_mouse = _safe_int(payload.get("mouse_movements")) <= 3
    low_keys = _safe_int(payload.get("keystrokes")) <= 3

    if honeypot_filled:
        return True
    if rapid and (low_mouse or low_keys):
        return True
    if bool(behavior_result.get("is_attack")) and behavior_result.get("risk_level") in ("medium", "high"):
        return True
    return False


def _redact_for_logging(event: Dict[str, Any]) -> Dict[str, Any]:
    log_sensitive = os.getenv("LOG_SENSITIVE_FIELDS", "false").strip().lower() == "true"
    out = dict(event)
    if "password" in out and not log_sensitive:
        out["password"] = "[REDACTED]"
    return out


def _top_vuln(vulns: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not vulns:
        return None
    return max(vulns, key=lambda v: _safe_float(v.get("cvss_score")))


print("[INFO] Initializing engines...")

try:
    blob_logger = BlobLogger()
    print("[OK] Blob Logger initialized")
except Exception as e:
    print(f"[ERR] Blob Logger failed: {e}")
    blob_logger = None

try:
    vuln_detector = VulnerabilityDetector()
    print("[OK] Vulnerability Detector initialized")
except Exception as e:
    print(f"[ERR] Vulnerability Detector failed: {e}")
    vuln_detector = None

try:
    behavior_detector = AttackDetector()
    print("[OK] Behavior Detector initialized")
except Exception as e:
    print(f"[ERR] Behavior Detector failed: {e}")
    behavior_detector = None

try:
    network_model = NetworkModel()
    print("[OK] Network Model initialized")
except Exception as e:
    print(f"[WARN] Network Model unavailable: {e}")
    network_model = None

try:
    web_model = WebAttackModel()
    print("[OK] Web Attack Model initialized")
except Exception as e:
    print(f"[WARN] Web Attack Model unavailable: {e}")
    web_model = None

try:
    claude = ClaudeEngine()
    print("[OK] Claude Engine initialized")
except Exception as e:
    print(f"[WARN] Claude Engine unavailable: {e}")
    claude = None

try:
    nvd = NVDLookup()
    print("[OK] NVD Lookup initialized")
except Exception as e:
    print(f"[WARN] NVD Lookup unavailable: {e}")
    nvd = None

try:
    risk_engine = RiskEngine()
    print("[OK] Risk Engine initialized")
except Exception as e:
    print(f"[WARN] Risk Engine unavailable: {e}")
    risk_engine = None

try:
    deception_engine = DeceptionEngine()
    print("[OK] Deception Engine initialized")
except Exception as e:
    print(f"[WARN] Deception Engine unavailable: {e}")
    deception_engine = None

print("[INFO] Engine init complete.\n")


@app.route("/api/track", methods=["POST"])
def track():
    try:
        data = request.get_json(force=True, silent=True) or {}
        if not isinstance(data, dict):
            data = {}

        session_id = str(data.get("session_id") or f"session-{int(datetime.now().timestamp())}")
        timestamp = datetime.now().isoformat()

        # Run detectors on the raw payload.
        data["session_id"] = session_id
        vulnerabilities: List[Dict[str, Any]] = []
        if vuln_detector:
            vulnerabilities = vuln_detector.detect(data)

        behavior_result: Dict[str, Any] = {"is_attack": False, "risk_level": "low", "confidence": 0.0}
        if behavior_detector:
            behavior_result = behavior_detector.predict(data)

        is_bot = _compute_is_bot(data, behavior_result)
        is_attack = bool(vulnerabilities) or bool(behavior_result.get("is_attack")) or is_bot

        primary = _top_vuln(vulnerabilities)
        cvss = _safe_float(primary.get("cvss_score") if primary else 0.0)
        cvss_vector = str(primary.get("cvss_vector")) if primary and primary.get("cvss_vector") else "N/A"

        if primary:
            attack_type = str(primary.get("attack_type") or "unknown")
            owasp = primary.get("owasp")
            remediation = str(primary.get("remediation") or "")
            threat_keyword = str(primary.get("keyword") or primary.get("name") or attack_type)
        elif is_bot:
            attack_type = "bot"
            owasp = "A07:2021 Identification and Authentication Failures"
            remediation = "Add bot protections (rate limiting, CAPTCHA, device fingerprinting) and lockout policies."
            threat_keyword = ""
        else:
            attack_type = "legitimate"
            owasp = None
            remediation = ""
            threat_keyword = ""

        if cvss <= 0.0 and is_attack:
            # Provide a non-CVSS severity signal for behavioral attacks.
            risk_level = str(behavior_result.get("risk_level") or "low")
            severity = "HIGH" if risk_level == "high" else "MEDIUM" if risk_level == "medium" else "LOW"
        else:
            severity = _severity_from_cvss(cvss)

        cve_references: List[str] = []
        if nvd and threat_keyword and attack_type not in ("legitimate", "bot"):
            cve_references = nvd.fetch_cves(threat_keyword, limit=3)

        response = {
            "success": True,
            "session_id": session_id,
            "is_attack": bool(is_attack),
            "is_bot": bool(is_bot),
            "attack_type": attack_type,
            "severity": severity,
            "cvss_score": float(cvss),
            "cvss_vector": cvss_vector,
            "cve_references": cve_references,
            "remediation": remediation,
            "risk_level": str(behavior_result.get("risk_level") or "low"),
            "confidence": _safe_float(behavior_result.get("confidence")),
            "owasp": owasp,
            "vulnerabilities": vulnerabilities,
            "timestamp": timestamp,
            "analyzed_by": "pattern+behavior",
        }

        # Log (redact sensitive fields by default).
        log_event = dict(data)
        log_event.update(response)
        log_event["timestamp"] = timestamp
        if blob_logger:
            blob_logger.log(_redact_for_logging(log_event))

        return jsonify(response)
    except Exception as e:
        print(f"[ERR] Error in /api/track: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(force=True, silent=True) or {}
        if not isinstance(data, dict):
            data = {}

        network_result: Dict[str, Any] = {"label": 0, "confidence": 0}
        if network_model:
            network_result = network_model.predict(data.get("network_features", [0] * 11))

        web_result: Dict[str, Any] = {"label": "benign", "confidence": 0}
        if web_model:
            web_result = web_model.predict(data.get("payload", ""))

        risk_score = 0
        if risk_engine:
            risk_score = risk_engine.calculate(network_result, web_result)

        keyword = str(data.get("threat_keyword") or "").strip()
        cves: List[str] = []
        if nvd and keyword:
            cves = nvd.fetch_cves(keyword, limit=3)

        ai_analysis = "Claude analysis not available"
        if claude:
            ai_analysis = claude.analyze({"network": network_result, "web": web_result, "risk_score": risk_score, "cves": cves})

        deception_strategy = "No deception deployed"
        if deception_engine:
            deception_strategy = deception_engine.deploy(keyword)

        advanced_result = {
            "network": network_result,
            "web": web_result,
            "risk_score": risk_score,
            "cves": cves,
            "ai_analysis": ai_analysis,
            "deception": deception_strategy,
            "timestamp": datetime.now().isoformat(),
        }

        if blob_logger:
            blob_logger.log(advanced_result)

        return jsonify(advanced_result)
    except Exception as e:
        print(f"[ERR] Error in /api/analyze: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def stats():
    try:
        logs: List[Dict[str, Any]] = []
        if blob_logger:
            logs = blob_logger.get_all_logs(limit=1000)

        # Only include events that look like /api/track events.
        track_events = [e for e in logs if isinstance(e, dict) and e.get("session_id")]
        attack_events = [e for e in track_events if _event_is_attack(e)]

        cvss_scores = [_safe_float(e.get("cvss_score")) for e in attack_events if _safe_float(e.get("cvss_score")) > 0.0]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0

        severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for e in attack_events:
            sev = str(e.get("severity") or _severity_from_cvss(_safe_float(e.get("cvss_score"))))
            if sev in severity_distribution:
                severity_distribution[sev] += 1

        vulnerability_distribution: Dict[str, int] = Counter()
        owasp_top_10: Dict[str, int] = Counter()
        cve_counter: Counter[str] = Counter()

        for e in attack_events:
            at = e.get("attack_type")
            if isinstance(at, str) and at:
                vulnerability_distribution[at] += 1

            owasp = e.get("owasp")
            if isinstance(owasp, str) and owasp:
                owasp_top_10[owasp] += 1

            cves = e.get("cve_references")
            if isinstance(cves, list):
                for cve in cves:
                    if isinstance(cve, str) and cve.startswith("CVE-"):
                        cve_counter[cve] += 1

        behavioral_metrics = {
            "avg_mouse_movements": 0.0,
            "avg_keystrokes": 0.0,
            "avg_time_to_submit": 0.0,
            "total_paste_events": 0,
            "honeypot_filled_count": 0,
            "rapid_submissions_count": 0,
        }

        if track_events:
            behavioral_metrics["avg_mouse_movements"] = sum(_safe_float(e.get("mouse_movements")) for e in track_events) / len(track_events)
            behavioral_metrics["avg_keystrokes"] = sum(_safe_float(e.get("keystrokes")) for e in track_events) / len(track_events)
            behavioral_metrics["avg_time_to_submit"] = sum(_safe_float(e.get("time_to_submit")) for e in track_events) / len(track_events)
            behavioral_metrics["total_paste_events"] = sum(_safe_int(e.get("paste_events")) for e in track_events)
            behavioral_metrics["honeypot_filled_count"] = sum(1 for e in track_events if _safe_int(e.get("honeypot_filled")) == 1)
            behavioral_metrics["rapid_submissions_count"] = sum(1 for e in track_events if _safe_int(e.get("rapid_submission")) == 1)

        # Recent attacks for the table.
        recent_attacks: List[Dict[str, Any]] = []
        for e in sorted(attack_events, key=lambda x: str(x.get("timestamp", "")), reverse=True)[:20]:
            cves = e.get("cve_references") if isinstance(e.get("cve_references"), list) else []
            recent_attacks.append(
                {
                    "timestamp": e.get("timestamp"),
                    "session_id": e.get("session_id"),
                    "severity": e.get("severity"),
                    "cvss_score": _safe_float(e.get("cvss_score")),
                    "attack_type": e.get("attack_type"),
                    "cve": cves[0] if cves else None,
                    "owasp": e.get("owasp"),
                }
            )

        top_cves = [{"cve": cve, "count": count} for cve, count in cve_counter.most_common(10)]

        return jsonify(
            {
                "total_events": len(track_events),
                "total_attacks": len(attack_events),
                "avg_cvss_score": float(avg_cvss),
                "severity_distribution": severity_distribution,
                "behavioral_metrics": behavioral_metrics,
                "vulnerability_distribution": dict(vulnerability_distribution),
                "top_cves": top_cves,
                "owasp_top_10": dict(owasp_top_10),
                "recent_attacks": recent_attacks,
            }
        )
    except Exception as e:
        print(f"[ERR] Error in /api/stats: {e}")
        return jsonify(
            {
                "total_events": 0,
                "total_attacks": 0,
                "avg_cvss_score": 0.0,
                "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "behavioral_metrics": {},
                "vulnerability_distribution": {},
                "top_cves": [],
                "owasp_top_10": {},
                "recent_attacks": [],
            }
        )


@app.route("/api/clear", methods=["POST"])
def clear_data():
    try:
        if not blob_logger:
            return jsonify({"success": False, "error": "Blob logger not configured"}), 500

        cleared = blob_logger.clear_all_logs()
        return jsonify({"success": True, "message": f"Cleared {cleared} logs"})
    except Exception as e:
        print(f"[ERR] Error in /api/clear: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "blob_logger": blob_logger is not None,
            "vuln_detector": vuln_detector is not None,
            "behavior_detector": behavior_detector is not None,
            "network_model": network_model is not None,
            "web_model": web_model is not None,
            "claude": claude is not None,
            "nvd": nvd is not None,
            "risk_engine": risk_engine is not None,
            "deception_engine": deception_engine is not None,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
