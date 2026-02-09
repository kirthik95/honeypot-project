"""
ADVANCED HONEYPOT BACKEND - COMPLETE VERSION WITH DASHBOARD SUPPORT
Includes: /api/track, /api/stats, /health, Azure Blob logging, XGBoost ML
"""

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import os, json, logging, re
import numpy as np
import pandas as pd
from collections import defaultdict

# ---------------- OPTIONAL AZURE BLOB ----------------
try:
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import ResourceExistsError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    logging.warning("Azure SDK not available - using local storage only")

import xgboost as xgb
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder

# ---------------- APP ----------------
app = Flask(__name__)
CORS(app)

# ---------------- CONFIG ----------------
class Config:
    AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    BLOB_CONTAINER_NAME = "honeypot-logs"
    LOCAL_LOG_DIR = "logs"

    BEHAVIOR_MODEL_PATH = "models/behavior_detector.pkl"
    ATTACK_CLASSIFIER_PATH = "models/attack_classifier.pkl"
    VECTORIZER_PATH = "models/tfidf_vectorizer.pkl"
    LABEL_ENCODER_PATH = "models/label_encoder.pkl"

    THRESHOLD = 0.5

    BEHAVIOR_FEATURES = [
        "mouse_movements", "keystrokes", "focus_events", "paste_events",
        "time_to_submit", "rapid_submission", "honeypot_filled",
        "honeypot_total_length", "email_length", "password_length",
        "cookies_enabled"
    ]

config = Config()
os.makedirs(config.LOCAL_LOG_DIR, exist_ok=True)
os.makedirs("models", exist_ok=True)

# ---------------- LOGGING ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(config.LOCAL_LOG_DIR, "honeypot.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------- AZURE / LOCAL LOGGER ----------------
class BlobLogger:
    def __init__(self):
        self.client = None
        self.local_dir = os.path.join(config.LOCAL_LOG_DIR, "attacks")
        os.makedirs(self.local_dir, exist_ok=True)

        if AZURE_AVAILABLE and config.AZURE_STORAGE_CONNECTION_STRING:
            try:
                self.client = BlobServiceClient.from_connection_string(
                    config.AZURE_STORAGE_CONNECTION_STRING
                )

                container_client = self.client.get_container_client(
                    config.BLOB_CONTAINER_NAME
                )

                try:
                    container_client.create_container()
                    logger.info("✅ Created Azure Blob container")
                except ResourceExistsError:
                    logger.info("✅ Azure Blob container already exists")

                logger.info("✅ Azure Blob Storage connected successfully")

            except Exception as e:
                logger.warning(f"⚠️ Azure Blob disabled: {e}")
                self.client = None

    def log(self, data: dict):
        """Save attack log to local file and Azure Blob"""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        sid = data.get("session_id", "unknown")
        filename = f"{ts}_{sid}.json"

        # Always save locally
        local_path = os.path.join(self.local_dir, filename)
        with open(local_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"📁 Saved locally: {filename}")

        # Try to save to Azure
        if self.client:
            try:
                blob = self.client.get_blob_client(
                    config.BLOB_CONTAINER_NAME, f"attacks/{filename}"
                )
                blob.upload_blob(json.dumps(data, indent=2), overwrite=True)
                logger.info(f"☁️ Uploaded to Azure: {filename}")
            except Exception as e:
                logger.warning(f"⚠️ Azure upload failed: {e}")

    def get_all_logs(self, limit=1000):
        """Fetch all attack logs for dashboard stats"""
        logs = []
        
        # Load from local files
        try:
            files = sorted(os.listdir(self.local_dir), reverse=True)[:limit]
            for filename in files:
                if filename.endswith('.json'):
                    with open(os.path.join(self.local_dir, filename), 'r') as f:
                        logs.append(json.load(f))
        except Exception as e:
            logger.error(f"Error loading local logs: {e}")
        
        # If Azure available, also try to load from there
        if self.client and not logs:
            try:
                container = self.client.get_container_client(config.BLOB_CONTAINER_NAME)
                blobs = list(container.list_blobs(name_starts_with="attacks/"))[:limit]
                
                for blob in blobs:
                    blob_client = container.get_blob_client(blob.name)
                    content = blob_client.download_blob().readall()
                    logs.append(json.loads(content))
            except Exception as e:
                logger.warning(f"Could not load from Azure: {e}")
        
        return logs

blob_logger = BlobLogger()

# ---------------- VULNERABILITY DETECTOR ----------------
class VulnerabilityDetector:
    """Pattern-based vulnerability detection"""
    
    SQL = [
        r"union.*select", r"or\s+1\s*=\s*1", r"drop\s+table",
        r"or\s+'1'\s*=\s*'1", r"admin'\s*--", r"';.*--"
    ]
    
    XSS = [
        r"<script", r"onerror\s*=", r"javascript:",
        r"<img.*onerror", r"alert\(", r"<svg.*onload"
    ]
    
    CMD = [
        r";\s*(ls|cat|rm)", r"\|\s*(ls|cat)", r"/etc/passwd",
        r"&&\s*whoami", r"`.*`", r"\$\(.*\)"
    ]
    
    PATH = [
        r"\.\./", r"\.\./\.\./", r"%2e%2e/", r"\.\.\\",
        r"/etc/", r"/windows/"
    ]

    OWASP_MAP = {
        'sql_injection': {
            'owasp': 'A03:2021 – Injection',
            'cve_examples': ['CVE-2021-44228', 'CVE-2019-16278'],
            'description': 'SQL Injection Attack Detected'
        },
        'xss': {
            'owasp': 'A03:2021 – Injection',
            'cve_examples': ['CVE-2021-42013', 'CVE-2020-14882'],
            'description': 'Cross-Site Scripting (XSS) Attack Detected'
        },
        'command_injection': {
            'owasp': 'A03:2021 – Injection',
            'cve_examples': ['CVE-2021-44228', 'CVE-2021-3156'],
            'description': 'Command Injection Attack Detected'
        },
        'path_traversal': {
            'owasp': 'A01:2021 – Broken Access Control',
            'cve_examples': ['CVE-2021-41773', 'CVE-2020-5902'],
            'description': 'Path Traversal Attack Detected'
        },
        'bot_attack': {
            'owasp': 'A07:2021 – Identification and Authentication Failures',
            'cve_examples': ['CVE-2021-35587'],
            'description': 'Automated Bot Attack Detected'
        }
    }

    def detect(self, data):
        """Detect vulnerabilities in input data"""
        text = " ".join([
            str(data.get("email", "")),
            str(data.get("password", "")),
            str(data.get("username", ""))
        ]).lower()

        vulns = []
        
        # Check SQL Injection
        if any(re.search(p, text, re.IGNORECASE) for p in self.SQL):
            vulns.append({
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                **self.OWASP_MAP['sql_injection']
            })
        
        # Check XSS
        if any(re.search(p, text, re.IGNORECASE) for p in self.XSS):
            vulns.append({
                "type": "xss",
                "severity": "HIGH",
                "cvss_score": 7.2,
                **self.OWASP_MAP['xss']
            })
        
        # Check Command Injection
        if any(re.search(p, text, re.IGNORECASE) for p in self.CMD):
            vulns.append({
                "type": "command_injection",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                **self.OWASP_MAP['command_injection']
            })
        
        # Check Path Traversal
        if any(re.search(p, text, re.IGNORECASE) for p in self.PATH):
            vulns.append({
                "type": "path_traversal",
                "severity": "HIGH",
                "cvss_score": 7.5,
                **self.OWASP_MAP['path_traversal']
            })
        
        # Check Bot behavior
        if data.get("honeypot_filled", 0) > 0:
            vulns.append({
                "type": "bot_attack",
                "severity": "MEDIUM",
                "cvss_score": 5.3,
                **self.OWASP_MAP['bot_attack']
            })

        return vulns

vuln_detector = VulnerabilityDetector()

# ---------------- ML DETECTOR ----------------
class AttackDetector:
    def __init__(self):
        self.behavior = None
        self.vectorizer = None
        self.classifier = None
        self.encoder = None
        self.load()

    def load(self):
        """Load or train ML models"""
        if os.path.exists(config.BEHAVIOR_MODEL_PATH):
            try:
                self.behavior = joblib.load(config.BEHAVIOR_MODEL_PATH)
                logger.info("✅ Loaded behavior model from disk")
            except:
                logger.warning("⚠️ Could not load behavior model, retraining...")
                self.train_behavior()
        else:
            self.train_behavior()

        if os.path.exists(config.ATTACK_CLASSIFIER_PATH):
            try:
                self.classifier = joblib.load(config.ATTACK_CLASSIFIER_PATH)
                self.vectorizer = joblib.load(config.VECTORIZER_PATH)
                self.encoder = joblib.load(config.LABEL_ENCODER_PATH)
                logger.info("✅ Loaded attack classifier from disk")
            except:
                logger.warning("⚠️ Could not load classifier, retraining...")
                self.train_classifier()
        else:
            self.train_classifier()

    def train_behavior(self):
        """Train behavioral detection model"""
        logger.info("🤖 Training behavior detection model...")
        
        # Generate synthetic data (legitimate vs bot behavior)
        np.random.seed(42)
        n = 1000
        
        # Legitimate users: more mouse, longer time
        legit = np.column_stack([
            np.random.randint(50, 500, n//2),  # mouse_movements
            np.random.randint(10, 100, n//2),  # keystrokes
            np.random.randint(2, 10, n//2),    # focus_events
            np.random.randint(0, 2, n//2),     # paste_events
            np.random.uniform(5, 60, n//2),    # time_to_submit
            np.zeros(n//2),                     # rapid_submission
            np.zeros(n//2),                     # honeypot_filled
            np.zeros(n//2),                     # honeypot_total_length
            np.random.randint(10, 50, n//2),   # email_length
            np.random.randint(8, 20, n//2),    # password_length
            np.ones(n//2)                       # cookies_enabled
        ])
        
        # Bots: low mouse, fast time, honeypot filled
        bots = np.column_stack([
            np.random.randint(0, 10, n//2),
            np.random.randint(0, 10, n//2),
            np.random.randint(0, 2, n//2),
            np.random.randint(2, 10, n//2),
            np.random.uniform(0.1, 3, n//2),
            np.ones(n//2),
            np.random.randint(1, 4, n//2),
            np.random.randint(10, 100, n//2),
            np.random.randint(5, 100, n//2),
            np.random.randint(1, 100, n//2),
            np.random.randint(0, 2, n//2)
        ])
        
        X = np.vstack([legit, bots])
        y = np.hstack([np.zeros(n//2), np.ones(n//2)])
        
        # Shuffle
        idx = np.random.permutation(len(X))
        X, y = X[idx], y[idx]
        
        self.behavior = xgb.XGBClassifier(
            max_depth=6,
            learning_rate=0.1,
            n_estimators=100,
            random_state=42
        )
        self.behavior.fit(X, y)
        joblib.dump(self.behavior, config.BEHAVIOR_MODEL_PATH)
        logger.info("✅ Behavior model trained and saved")

    def train_classifier(self):
        """Train attack type classifier"""
        logger.info("🤖 Training attack classifier...")
        
        texts = [
            "admin' OR '1'='1", "admin'--", "UNION SELECT",
            "<script>alert(1)</script>", "javascript:alert",
            "; cat /etc/passwd", "| ls -la",
            "user@example.com", "john.doe@company.com", "test@test.com"
        ]
        labels = [
            "attack", "attack", "attack",
            "attack", "attack",
            "attack", "attack",
            "legit", "legit", "legit"
        ]
        
        self.vectorizer = TfidfVectorizer(max_features=50)
        X = self.vectorizer.fit_transform(texts)
        
        self.encoder = LabelEncoder()
        y = self.encoder.fit_transform(labels)
        
        self.classifier = xgb.XGBClassifier(max_depth=4, learning_rate=0.1)
        self.classifier.fit(X, y)
        
        joblib.dump(self.classifier, config.ATTACK_CLASSIFIER_PATH)
        joblib.dump(self.vectorizer, config.VECTORIZER_PATH)
        joblib.dump(self.encoder, config.LABEL_ENCODER_PATH)
        logger.info("✅ Attack classifier trained and saved")

    def predict(self, data):
        """Predict if submission is an attack"""
        try:
            features = [data.get(f, 0) for f in config.BEHAVIOR_FEATURES]
            prob = self.behavior.predict_proba([features])[0][1]
            
            return {
                "is_attack": bool(prob >= config.THRESHOLD),
                "confidence": float(prob),
                "risk_level": "high" if prob > 0.7 else "medium" if prob > 0.3 else "low"
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {"is_attack": False, "confidence": 0.0, "risk_level": "unknown"}

detector = AttackDetector()

# ---------------- API ROUTES ----------------
@app.route("/api/track", methods=["POST"])
def track():
    """Main endpoint to receive and analyze attacks"""
    try:
        data = request.get_json(force=True, silent=True) or {}

        session_id = data.get(
            "session_id", f"session-{int(datetime.now().timestamp())}"
        )
        data["session_id"] = session_id

        # Pattern-based detection
        vulns = vuln_detector.detect(data)
        
        # ML-based detection
        prediction = detector.predict(data)

        # Calculate CVSS
        cvss = max([v["cvss_score"] for v in vulns], default=0.0)
        
        # Determine severity
        if cvss >= 9.0:
            severity = "CRITICAL"
        elif cvss >= 7.0:
            severity = "HIGH"
        elif cvss >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW" if cvss > 0 else "INFO"

        # Build result
        result = {
            **data,
            "vulnerabilities": vulns,
            "cvss_score": float(cvss),
            "severity": severity,
            "is_attack": bool(prediction["is_attack"] or vulns),
            "risk_level": prediction["risk_level"],
            "timestamp": datetime.now().isoformat()
        }

        # Log attack
        try:
            blob_logger.log(result)
            logger.info(f"🚨 Attack logged: {session_id} - {severity} - CVSS {cvss}")
        except Exception as log_error:
            logger.warning(f"Logging failed: {log_error}")

        # Return response
        return jsonify({
            "success": True,
            "session_id": session_id,
            "is_attack": result["is_attack"],
            "risk_level": result["risk_level"],
            "severity": severity,
            "cvss_score": float(cvss),
            "vulnerabilities": vulns,
            "message": "Attack analyzed and logged"
        })

    except Exception as e:
        logger.exception("❌ Fatal error in /api/track")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get attack statistics for dashboard"""
    try:
        # Load all attack logs
        logs = blob_logger.get_all_logs(limit=1000)
        
        if not logs:
            return jsonify({
                "total_attacks": 0,
                "attacks_today": 0,
                "vulnerability_distribution": {},
                "severity_distribution": {},
                "top_cves": [],
                "owasp_top_10": {},
                "avg_cvss_score": 0.0
            })
        
        # Calculate stats
        today = datetime.now().date()
        attacks_today = 0
        
        vuln_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        cve_counts = defaultdict(int)
        owasp_counts = defaultdict(int)
        cvss_scores = []
        
        for log in logs:
            # Count today's attacks
            try:
                log_date = datetime.fromisoformat(log.get('timestamp', '')).date()
                if log_date == today:
                    attacks_today += 1
            except:
                pass
            
            # Count severity
            severity = log.get('severity', 'UNKNOWN')
            severity_counts[severity] += 1
            
            # Count CVSS
            cvss = log.get('cvss_score', 0)
            if cvss > 0:
                cvss_scores.append(cvss)
            
            # Count vulnerabilities
            vulns = log.get('vulnerabilities', [])
            for v in vulns:
                vuln_type = v.get('type', 'unknown')
                vuln_counts[vuln_type] += 1
                
                # Count CVEs
                for cve in v.get('cve_examples', []):
                    cve_counts[cve] += 1
                
                # Count OWASP
                owasp = v.get('owasp', 'Unknown')
                owasp_counts[owasp] += 1
        
        # Top CVEs
        top_cves = [
            {"cve": cve, "count": count}
            for cve, count in sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Average CVSS
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        
        # Calculate behavioral metrics (NEW!)
        mouse_movements = []
        keystrokes = []
        time_to_submit = []
        paste_events = 0
        honeypot_filled = 0
        rapid_submissions = 0
        
        for log in logs:
            mouse_movements.append(log.get('mouse_movements', 0))
            keystrokes.append(log.get('keystrokes', 0))
            time_to_submit.append(log.get('time_to_submit', 0))
            if log.get('paste_events', 0) > 0:
                paste_events += log.get('paste_events', 0)
            if log.get('honeypot_filled', 0) > 0:
                honeypot_filled += 1
            if log.get('rapid_submission', 0) == 1:
                rapid_submissions += 1
        
        behavioral_metrics = {
            "avg_mouse_movements": sum(mouse_movements) / len(mouse_movements) if mouse_movements else 0,
            "avg_keystrokes": sum(keystrokes) / len(keystrokes) if keystrokes else 0,
            "avg_time_to_submit": sum(time_to_submit) / len(time_to_submit) if time_to_submit else 0,
            "total_paste_events": paste_events,
            "honeypot_filled_count": honeypot_filled,
            "rapid_submissions_count": rapid_submissions
        }
        
        # Get recent attacks with details (NEW!)
        recent_attacks = []
        for log in sorted(logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:20]:
            vulns = log.get('vulnerabilities', [])
            attack_type = vulns[0].get('type') if vulns else 'unknown'
            cve = vulns[0].get('cve_examples', [''])[0] if vulns else ''
            owasp = vulns[0].get('owasp', '') if vulns else ''
            
            recent_attacks.append({
                "timestamp": log.get('timestamp'),
                "session_id": log.get('session_id'),
                "severity": log.get('severity', 'INFO'),
                "cvss_score": log.get('cvss_score', 0),
                "attack_type": attack_type,
                "cve": cve,
                "owasp": owasp
            })
        
        stats = {
            "total_attacks": len(logs),
            "attacks_today": attacks_today,
            "vulnerability_distribution": dict(vuln_counts),
            "severity_distribution": dict(severity_counts),
            "top_cves": top_cves,
            "owasp_top_10": dict(owasp_counts),
            "avg_cvss_score": round(avg_cvss, 2),
            "behavioral_metrics": behavioral_metrics,
            "recent_attacks": recent_attacks
        }
        
        logger.info(f"📊 Stats requested: {len(logs)} attacks found")
        return jsonify(stats)
        
    except Exception as e:
        logger.exception("❌ Error in /api/stats")
        return jsonify({"error": str(e)}), 500


@app.route("/api/clear", methods=["POST"])
def clear_all_data():
    """Clear all attack logs - for testing purposes"""
    try:
        deleted_count = 0
        
        # Delete local files
        local_dir = blob_logger.local_dir
        if os.path.exists(local_dir):
            for filename in os.listdir(local_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(local_dir, filename)
                    os.remove(filepath)
                    deleted_count += 1
        
        logger.info(f"🗑️  Cleared {deleted_count} local attack logs")
        
        # Delete from Azure Blob (if connected)
        if blob_logger.client:
            try:
                container_client = blob_logger.client.get_container_client(
                    config.BLOB_CONTAINER_NAME
                )
                blobs = container_client.list_blobs(name_starts_with="attacks/")
                for blob in blobs:
                    container_client.delete_blob(blob.name)
                logger.info(f"🗑️  Cleared Azure Blob attack logs")
            except Exception as e:
                logger.warning(f"Could not clear Azure blobs: {e}")
        
        return jsonify({
            "success": True,
            "message": f"Cleared {deleted_count} attack logs",
            "deleted_count": deleted_count
        })
    
    except Exception as e:
        logger.exception("Error clearing data")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "behavior_model_loaded": detector.behavior is not None,
        "attack_classifier_loaded": detector.classifier is not None,
        "azure_blob_connected": blob_logger.client is not None
    })


# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    
    print("\n" + "="*60)
    print("🎯 HONEYPOT BACKEND SERVER")
    print("="*60)
    print(f"📍 Port: {port}")
    print(f"🤖 ML Models: Loaded")
    print(f"☁️  Azure Blob: {'Connected' if blob_logger.client else 'Local only'}")
    print("="*60 + "\n")
    
    app.run(host="0.0.0.0", port=port)