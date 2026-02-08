"""
ADVANCED HONEYPOT BACKEND - FINAL STABLE VERSION
"""

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import os, json, logging, re
import numpy as np
from collections import defaultdict

# ---------------- OPTIONAL AZURE BLOB ----------------
try:
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import ResourceExistsError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

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
                except ResourceExistsError:
                    pass  # container already exists → OK

                logger.info("Azure Blob Storage connected successfully")

            except Exception as e:
                logger.warning(f"Azure Blob disabled: {e}")
                self.client = None

    def log(self, data: dict):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        sid = data.get("session_id", "unknown")
        filename = f"{ts}_{sid}.json"

        with open(os.path.join(self.local_dir, filename), "w") as f:
            json.dump(data, f, indent=2)

        if self.client:
            try:
                blob = self.client.get_blob_client(
                    config.BLOB_CONTAINER_NAME, f"attacks/{filename}"
                )
                blob.upload_blob(json.dumps(data, indent=2), overwrite=True)
            except Exception as e:
                logger.warning(f"Blob upload failed: {e}")

blob_logger = BlobLogger()

# ---------------- VULNERABILITY DETECTOR ----------------
class VulnerabilityDetector:
    SQL = [r"union.*select", r"or\s+1=1", r"drop\s+table"]
    XSS = [r"<script", r"onerror\s*=", r"javascript:"]
    CMD = [r";\s*(ls|cat|rm)", r"\|\s*(ls|cat)", r"/etc/passwd"]

    def detect(self, data):
        text = " ".join([
            str(data.get("email", "")),
            str(data.get("password", "")),
            str(data.get("username", ""))
        ]).lower()

        vulns = []
        if any(re.search(p, text) for p in self.SQL):
            vulns.append({"type": "sql_injection", "severity": "CRITICAL", "cvss": 9.8})
        if any(re.search(p, text) for p in self.XSS):
            vulns.append({"type": "xss", "severity": "HIGH", "cvss": 7.2})
        if any(re.search(p, text) for p in self.CMD):
            vulns.append({"type": "command_injection", "severity": "CRITICAL", "cvss": 9.8})

        return vulns

vuln_detector = VulnerabilityDetector()

# ---------------- ML ----------------
class AttackDetector:
    def __init__(self):
        self.behavior = None
        self.vectorizer = None
        self.classifier = None
        self.encoder = None
        self.load()

    def load(self):
        if os.path.exists(config.BEHAVIOR_MODEL_PATH):
            self.behavior = joblib.load(config.BEHAVIOR_MODEL_PATH)
        else:
            self.train_behavior()

        if os.path.exists(config.ATTACK_CLASSIFIER_PATH):
            self.classifier = joblib.load(config.ATTACK_CLASSIFIER_PATH)
            self.vectorizer = joblib.load(config.VECTORIZER_PATH)
            self.encoder = joblib.load(config.LABEL_ENCODER_PATH)
        else:
            self.train_classifier()

    def train_behavior(self):
        X = np.random.rand(200, len(config.BEHAVIOR_FEATURES))
        y = np.random.randint(0, 2, 200)
        self.behavior = xgb.XGBClassifier()
        self.behavior.fit(X, y)
        joblib.dump(self.behavior, config.BEHAVIOR_MODEL_PATH)

    def train_classifier(self):
        texts = ["admin", "<script>", "user@example.com"]
        labels = ["attack", "attack", "legit"]
        self.vectorizer = TfidfVectorizer()
        X = self.vectorizer.fit_transform(texts)
        self.encoder = LabelEncoder()
        y = self.encoder.fit_transform(labels)
        self.classifier = xgb.XGBClassifier()
        self.classifier.fit(X, y)
        joblib.dump(self.classifier, config.ATTACK_CLASSIFIER_PATH)
        joblib.dump(self.vectorizer, config.VECTORIZER_PATH)
        joblib.dump(self.encoder, config.LABEL_ENCODER_PATH)

    def predict(self, data):
        features = [data.get(f, 0) for f in config.BEHAVIOR_FEATURES]
        prob = self.behavior.predict_proba([features])[0][1]
        return {
            "is_attack": prob >= config.THRESHOLD,
            "risk_level": "high" if prob > 0.7 else "medium" if prob > 0.3 else "low"
        }

detector = AttackDetector()

# ---------------- API ----------------
@app.route("/api/track", methods=["POST"])
def track():
    try:
        data = request.get_json() or {}

        session_id = data.get(
            "session_id", f"session-{int(datetime.now().timestamp())}"
        )
        data["session_id"] = session_id

        vulns = vuln_detector.detect(data)
        prediction = detector.predict(data)

        cvss = max([v["cvss"] for v in vulns], default=0.0)
        severity = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "INFO"

        result = {
            **data,
            "vulnerabilities": vulns,
            "cvss_score": cvss,
            "severity": severity,
            "is_attack": prediction["is_attack"] or bool(vulns),
            "risk_level": prediction["risk_level"],
            "timestamp": datetime.now().isoformat()
        }

        blob_logger.log(result)

        return jsonify({
            "success": True,
            "session_id": session_id,
            "is_attack": result["is_attack"],
            "risk_level": result["risk_level"],
            "severity": severity,
            "cvss_score": cvss,
            "message": "Attack analyzed and logged"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "healthy"})

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Honeypot backend running on port {port}")
    app.run(host="0.0.0.0", port=port)

