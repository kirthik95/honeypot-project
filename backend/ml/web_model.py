import os
from typing import Any, Dict


class WebAttackModel:
    def __init__(self):
        xgb = self._xgb()
        joblib = self._joblib()

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        models_dir = os.path.join(base_dir, "models")

        model_path = os.path.join(models_dir, "web_attack_model.json")
        vectorizer_path = os.path.join(models_dir, "web_vectorizer.pkl")
        encoder_path = os.path.join(models_dir, "web_label_encoder.pkl")

        missing = [p for p in [model_path, vectorizer_path, encoder_path] if not os.path.exists(p)]
        if missing:
            raise FileNotFoundError(f"Missing web model artifacts: {missing}")

        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)

        self.vectorizer = joblib.load(vectorizer_path)
        self.encoder = joblib.load(encoder_path)

    def predict(self, payload: str) -> Dict[str, Any]:
        X = self.vectorizer.transform([payload])
        prediction = self.model.predict(X)[0]
        prob = max(self.model.predict_proba(X)[0])
        return {"label": self.encoder.inverse_transform([prediction])[0], "confidence": float(prob) * 100}

    @staticmethod
    def _joblib():
        try:
            import joblib  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("joblib is required for WebAttackModel") from e
        return joblib

    @staticmethod
    def _xgb():
        try:
            import xgboost as xgb  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("xgboost is required for WebAttackModel") from e
        return xgb

