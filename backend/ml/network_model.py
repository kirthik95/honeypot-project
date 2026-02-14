import os
import pickle
from typing import Any, Dict, List


class NetworkModel:
    def __init__(self):
        self.xgb = self._xgb()
        self.model_type = "sklearn"

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        models_dir = os.path.join(base_dir, "models")

        model_path = os.path.join(models_dir, "xgboost_network.json")
        scaler_path = os.path.join(models_dir, "scaler.pkl")
        label_encoder_path = os.path.join(models_dir, "label_encoder.pkl")
        self.model_path = model_path

        missing = [p for p in [model_path, scaler_path, label_encoder_path] if not os.path.exists(p)]
        if missing:
            raise FileNotFoundError(f"Missing network model artifacts: {missing}")

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

        with open(scaler_path, "rb") as f:
            self.scaler = pickle.load(f)

        with open(label_encoder_path, "rb") as f:
            self.label_encoder = pickle.load(f)

        # Fail fast if preprocessing artifacts are incompatible with current sklearn.
        try:
            feature_count = int(getattr(self.scaler, "n_features_in_", 11))
            self.scaler.transform([[0.0] * feature_count])
        except Exception as e:
            raise RuntimeError(f"Network scaler artifact is incompatible with runtime: {e}") from e

    def predict(self, features: List[float]) -> Dict[str, Any]:
        scaled = self.scaler.transform([features])
        prob = self._predict_proba(scaled)
        prediction = int(self._argmax(prob))
        return {"label": prediction, "confidence": float(max(prob)) * 100}

    def _predict_proba(self, features: Any) -> List[float]:
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
    def _argmax(values: List[float]) -> int:
        return max(range(len(values)), key=lambda i: values[i])

    def _switch_to_booster(self) -> None:
        booster = self.xgb.Booster()
        booster.load_model(self.model_path)
        self.model = booster
        self.model_type = "booster"

    @staticmethod
    def _np():
        try:
            import numpy as np  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("numpy is required for NetworkModel predictions") from e
        return np

    @staticmethod
    def _xgb():
        try:
            import xgboost as xgb  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("xgboost is required for NetworkModel") from e
        return xgb
