import os
from typing import Any, Dict, List, Optional

class AttackDetector:

    FEATURES = [
        "mouse_movements", "keystrokes", "focus_events",
        "paste_events", "time_to_submit",
        "rapid_submission", "honeypot_filled",
        "honeypot_total_length",
        "email_length", "password_length",
        "cookies_enabled"
    ]

    def __init__(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.models_dir = os.path.join(base_dir, "models")
        self.model_path = os.path.join(self.models_dir, "behavior_detector.pkl")
        self.model: Optional[Any] = None
        self.load_or_train()

    def load_or_train(self):
        joblib = self._joblib()
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.train()

    def train(self):
        np = self._np()
        xgb = self._xgb()
        joblib = self._joblib()

        np.random.seed(42)
        n = 1000

        legit = np.random.normal(loc=50, scale=10, size=(n//2, len(self.FEATURES)))
        bots = np.random.normal(loc=5, scale=2, size=(n//2, len(self.FEATURES)))

        X = np.vstack([legit, bots])
        y = np.hstack([np.zeros(n//2), np.ones(n//2)])

        model = xgb.XGBClassifier()
        model.fit(X, y)
        self.model = model

        os.makedirs(self.models_dir, exist_ok=True)
        joblib.dump(model, self.model_path)

    def predict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if self.model is None:
            self.load_or_train()
        model = self.model
        if model is None:
            raise RuntimeError("Behavior model is not available.")

        features = [data.get(f, 0) for f in self.FEATURES]

        prob = model.predict_proba([features])[0][1]

        return {
            "is_attack": bool(prob >= 0.5),
            "confidence": float(prob),
            "risk_level":
                "high" if prob > 0.7
                else "medium" if prob > 0.3
                else "low"
        }

    @staticmethod
    def _np():
        try:
            import numpy as np  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("numpy is required for AttackDetector") from e
        return np

    @staticmethod
    def _joblib():
        try:
            import joblib  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("joblib is required for AttackDetector") from e
        return joblib

    @staticmethod
    def _xgb():
        try:
            import xgboost as xgb  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("xgboost is required for AttackDetector") from e
        return xgb
