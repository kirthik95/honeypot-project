import os
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

from ai.claude_engine import AIEngine
from deception.deception_engine import DeceptionEngine
from fusion.risk_engine import RiskEngine
from honeypot.behavior_detector import AttackDetector
from honeypot.blob_logger import BlobLogger
from honeypot.vuln_detector import VulnerabilityDetector
from intel.nvd_lookup import NVDLookup
from ml.network_model import NetworkModel
from ml.web_model import WebAttackModel
from honeypot.dynamic_cvss_calculator import DynamicCVSSCalculator
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
    # The ML WebAttackModel is now the primary web payload detector.
    # The vulnerability detector is treated as an optional CVSS/enrichment engine.
    print(f"[WARN] Vulnerability Detector unavailable: {e}")
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
    ai_engine = AIEngine()
    print("[OK] OpenAI AI Engine initialized")
except Exception as e:
    print(f"[WARN] AI Engine unavailable: {e}")
    ai_engine = None

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
try:
    cvss_calculator = DynamicCVSSCalculator()
    print("[OK] Dynamic CVSS Calculator initialized")
except Exception as e:
    print(f"[WARN] Dynamic CVSS Calculator unavailable: {e}")
    cvss_calculator = None
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

        # Primary web attack classification via XGBoost model trained on SecOps CSV payloads.
        web_result: Dict[str, Any] = {"label": "benign", "confidence": 0.0}
        if web_model:
            # Build a unified payload string from likely text fields.
            candidate_fields = ["email", "username", "password", "payload", "query", "input", "comment", "filename", "path"]
            parts: List[str] = []
            for key in candidate_fields:
                val = data.get(key)
                if val is not None:
                    parts.append(str(val))
            payload_text = " ".join(parts)
            if payload_text.strip():
                web_result = web_model.predict(payload_text)

        behavior_result: Dict[str, Any] = {"is_attack": False, "risk_level": "low", "confidence": 0.0}
        if behavior_detector:
            behavior_result = behavior_detector.predict(data)

        is_bot = _compute_is_bot(data, behavior_result)
        # ML model is the primary signal; behavior + bot heuristics are supporting.
        ml_label = str(web_result.get("label") or "benign").lower()
        ml_confidence = _safe_float(web_result.get("confidence"))

        ml_attack = ml_label not in ("benign", "normal") and ml_confidence >= 50.0
        is_attack = ml_attack or bool(behavior_result.get("is_attack")) or is_bot

        primary = _top_vuln(vulnerabilities)

        attack_for_cvss = None
        payload_for_cvss = ""

        # 1️⃣ Pattern-based attack
        if primary:
            attack_for_cvss = str(primary.get("attack_type") or "")
            payload_for_cvss = str(primary.get("evidence", {}).get("match", ""))

        # 2️⃣ ML-based attack (fallback)
        elif ml_attack:
        
            attack_for_cvss = ml_label
            
            candidate_fields = ["email", "username", "password", "payload", "query", "input"]
            payload_parts = []
            for key in candidate_fields:
                if data.get(key):
                    payload_parts.append(str(data.get(key)))
            payload_for_cvss = " ".join(payload_parts)

        # 3️⃣ Calculate dynamic CVSS
        if attack_for_cvss and cvss_calculator:
            cvss_result = cvss_calculator.calculate_cvss(
                attack_type=attack_for_cvss,
                payload=payload_for_cvss,
                context={"field": "web_input"}
            )
            cvss = _safe_float(cvss_result.get("cvss_score"))
            cvss_vector = str(cvss_result.get("cvss_vector") or "N/A")
        else:
            cvss = 0.0
            cvss_vector = "N/A"
        if primary:
            attack_type= primary.get("attack_type","unknown")
        elif ml_attack:
            attack_type=ml_label
        elif is_bot:
            attack_type="bot_attack"
        else:
            attack_type='legitimate'
        owasp = None
        remediation = ""
        threat_keyword = ""

        if ml_attack:
            # Map ML labels from the XGBoost model to attack metadata.
            label_map = {
                "sqli": ("sql_injection", "A03:2021 Injection", "SQL Injection", "Use parameterized queries and strict server-side validation."),
                "sql_injection": ("sql_injection", "A03:2021 Injection", "SQL Injection", "Use parameterized queries and strict server-side validation."),
                "xss": ("xss", "A03:2021 Injection", "Cross-Site Scripting", "Encode output, sanitize HTML, and enforce a strong CSP."),
                "os_command": ("command_injection", "A03:2021 Injection", "Command Injection", "Never pass user input to shell, use allowlists and safe OS APIs."),
                "command_injection": ("command_injection", "A03:2021 Injection", "Command Injection", "Never pass user input to shell, use allowlists and safe OS APIs."),
                "path_traversal": ("path_traversal", "A01:2021 Broken Access Control", "Path Traversal", "Normalize paths and block traversal sequences like ../ and ..\\\\."),
                "ssrf": ("ssrf", "A10:2021 Server-Side Request Forgery (SSRF)", "SSRF", "Block internal IPs and metadata services; use outbound allowlists."),
            }
            mapped = label_map.get(ml_label)
            if mapped:
                attack_type, owasp, threat_keyword, remediation = mapped
            else:
                attack_type = ml_label or "unknown"
                threat_keyword = ml_label or "web attack"
                remediation = "Review the payload and apply standard input validation, output encoding, and least-privilege controls."

        elif primary:
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

        # FIX 1: Use attack_type for CVE lookup (not threat_keyword)
        cve_references: List[str] = []
        if nvd and attack_type not in ("legitimate", "bot", "unknown", ""):
            search_terms = {
                "sql_injection": "sql injection",
                "xss": "cross site scripting",
                "command_injection": "command injection",
                "path_traversal": "path traversal",
                "ssrf": "server side request forgery",
            }
            search_term = search_terms.get(attack_type, attack_type.replace("_", " "))
            print(f"[INFO] NVD lookup for '{search_term}'")
            cve_references = nvd.fetch_cves(search_term, limit=3)
            print(f"[INFO] Found {len(cve_references)} CVEs")

        # FIX 2: AI analysis in /api/track with proper detection data
        ai_analysis = None
        if ai_engine and is_attack and attack_type not in ("legitimate", "bot", "unknown", ""):
            payload_sample = (data.get("email") or data.get("username") or data.get("payload") or "")[:100]
            ai_detection_data = {
                "attack_type": attack_type,
                "severity": severity,
                "cvss_score": cvss,
                "cvss_vector": cvss_vector,
                "ml_label": ml_label,
                "ml_confidence": ml_confidence,
                "is_bot": is_bot,
                "cve_references": cve_references,
                "owasp": owasp,
                "payload_sample": payload_sample,
            }
            try:
                print(f"[INFO] Calling AI analysis for {attack_type}")
                ai_analysis = ai_engine.analyze(ai_detection_data)
                print(f"[INFO] AI analysis completed: {len(ai_analysis)} chars")
            except Exception as e:
                print(f"[WARN] AI analysis failed: {e}")
                ai_analysis = None

        # FIX 3: Include ai_analysis in response
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
            "ml_label": ml_label,
            "ml_confidence": ml_confidence,
            "risk_level": str(behavior_result.get("risk_level") or "low"),
            "confidence": _safe_float(behavior_result.get("confidence")),
            "owasp": owasp,
            "vulnerabilities": vulnerabilities,
            "timestamp": timestamp,
            "analyzed_by": "ml+behavior+pattern",
            "ai_analysis": ai_analysis,
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
        attack_type_input = str(data.get("attack_type") or "").strip().lower()
        severity_input = str(data.get("severity") or "").strip().upper()
        cvss_score = _safe_float(data.get("cvss_score"))
        cvss_vector = str(data.get("cvss_vector") or "N/A")
        owasp = str(data.get("owasp") or "").strip() or None
        session_id = str(data.get("session_id") or "").strip()
        event_timestamp = str(data.get("timestamp") or "").strip()

        provided_cves: List[str] = []
        raw_cves = data.get("cve_references")
        if isinstance(raw_cves, list):
            provided_cves = [cve for cve in raw_cves if isinstance(cve, str) and cve.startswith("CVE-")]
        single_cve = data.get("cve")
        if isinstance(single_cve, str) and single_cve.startswith("CVE-") and single_cve not in provided_cves:
            provided_cves.append(single_cve)

        if not keyword:
            keyword = attack_type_input or str(single_cve or "").strip()

        cves: List[str] = list(provided_cves)
        if nvd and keyword and not cves:
            cves = nvd.fetch_cves(keyword, limit=3)

        label_map = {
            "sqli": "sql_injection",
            "sql_injection": "sql_injection",
            "xss": "xss",
            "os_command": "command_injection",
            "command_injection": "command_injection",
            "path_traversal": "path_traversal",
            "ssrf": "ssrf",
            "bot_attack": "bot",
        }

        mapped_input_type = label_map.get(attack_type_input, attack_type_input)
        web_label = str(web_result.get("label") or "benign").lower()
        mapped_web_type = label_map.get(web_label, web_label)

        attack_type = mapped_input_type or (mapped_web_type if mapped_web_type not in ("benign", "normal") else "unknown")

        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        if severity_input in valid_severities:
            severity = severity_input
        elif cvss_score > 0.0:
            severity = _severity_from_cvss(cvss_score)
        elif attack_type in ("bot", "unknown", "legitimate", ""):
            severity = "LOW"
        else:
            severity = "MEDIUM"

        ai_detection_data = {
            "attack_type": attack_type or "unknown",
            "severity": severity,
            "cvss_score": float(cvss_score),
            "cvss_vector": cvss_vector,
            "owasp": owasp,
            "cve_references": cves,
            "threat_keyword": keyword,
            "session_id": session_id,
            "timestamp": event_timestamp or datetime.now().isoformat(),
            "network": network_result,
            "web": web_result,
            "risk_score": risk_score,
        }

        ai_analysis = "AI analysis not available"
        if ai_engine:
            ai_analysis = ai_engine.analyze(ai_detection_data)

        # Helpful reference links for analysts to pivot into public research.
        reference_links = {
            "medium": [],
            "hackerone": [],
        }
        if cves:
            # Provide search URLs rather than scraping live content, so this stays reliable.
            for cve in cves:
                reference_links["medium"].append(f"https://medium.com/search?q={cve}")
                reference_links["hackerone"].append(f"https://hackerone.com/reports/search?query={cve}")
        elif keyword:
            reference_links["medium"].append(f"https://medium.com/search?q={keyword}")
            reference_links["hackerone"].append(f"https://hackerone.com/reports/search?query={keyword}")

        deception_strategy = "No deception deployed"
        if deception_engine:
            deception_strategy = deception_engine.deploy(keyword)

        advanced_result = {
            "network": network_result,
            "web": web_result,
            "risk_score": risk_score,
            "attack_type": attack_type or "unknown",
            "severity": severity,
            "cvss_score": float(cvss_score),
            "cvss_vector": cvss_vector,
            "owasp": owasp,
            "session_id": session_id,
            "event_timestamp": event_timestamp,
            "cves": cves,
            "ai_analysis": ai_analysis,
            "reference_links": reference_links,
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
            "ai_engine": ai_engine is not None,
            "nvd": nvd is not None,
            "risk_engine": risk_engine is not None,
            "deception_engine": deception_engine is not None,
            "cvss_calculator": cvss_calculator is not None,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
