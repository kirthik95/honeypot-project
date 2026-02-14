import os
from typing import Any, Dict


class WebAttackModel:
    def __init__(self):
        self.xgb = self._xgb()
        joblib = self._joblib()
        self.model_type = "sklearn"

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        models_dir = os.path.join(base_dir, "models")

        model_path = os.path.join(models_dir, "web_attack_model.json")
        vectorizer_path = os.path.join(models_dir, "web_vectorizer.pkl")
        encoder_path = os.path.join(models_dir, "web_label_encoder.pkl")
        self.model_path = model_path

        missing = [p for p in [model_path, vectorizer_path, encoder_path] if not os.path.exists(p)]
        if missing:
            raise FileNotFoundError(f"Missing web model artifacts: {missing}")

        try:
            self.model = self.xgb.XGBClassifier()
            self.model.load_model(model_path)
            self.model_type = "sklearn"
        except Exception:
            # Fallback for sklearn/xgboost compatibility issues in some runtimes.
            booster = self.xgb.Booster()
            booster.load_model(model_path)
            self.model = booster
            self.model_type = "booster"

        self.vectorizer = joblib.load(vectorizer_path)
        self.encoder = joblib.load(encoder_path)

        # Fail fast if vectorizer artifact is incompatible with current sklearn.
        try:
            self.vectorizer.transform(["healthcheck"])
        except Exception as e:
            raise RuntimeError(f"Web vectorizer artifact is incompatible with runtime: {e}") from e

    def predict(self, payload: str) -> Dict[str, Any]:
        X = self.vectorizer.transform([payload])
        probabilities = self._predict_proba(X)
        prediction = self._argmax(probabilities)
        prob = max(probabilities)
        return {"label": self.encoder.inverse_transform([prediction])[0], "confidence": float(prob) * 100}

    def _predict_proba(self, features: Any) -> list[float]:
        if self.model_type == "sklearn":
            try:
                return self.model.predict_proba(features)[0].tolist()
            except Exception:
                self._switch_to_booster()

        np = self._np()
        raw = self.model.predict(self.xgb.DMatrix(features))
        arr = np.asarray(raw, dtype=float)

        if arr.ndim == 2:
            return arr[0].tolist()

        if arr.ndim == 1 and arr.size > 1:
            return arr.tolist()

        if arr.ndim == 1 and arr.size == 1:
            value = float(arr[0])
            if 0.0 <= value <= 1.0:
                return [1.0 - value, value]
            class_index = max(int(round(value)), 0)
            out = [0.0] * (class_index + 1)
            out[class_index] = 1.0
            return out

        return [1.0]

    @staticmethod
    def _argmax(values: list[float]) -> int:
        return max(range(len(values)), key=lambda i: values[i])

    def _switch_to_booster(self) -> None:
        booster = self.xgb.Booster()
        booster.load_model(self.model_path)
        self.model = booster
        self.model_type = "booster"

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

    @staticmethod
    def _np():
        try:
            import numpy as np  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("numpy is required for WebAttackModel predictions") from e
        return np
