import os
import pickle
from typing import Any, Dict, List


class NetworkModel:
    def __init__(self):
        xgb = self._xgb()

        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        models_dir = os.path.join(base_dir, "models")

        model_path = os.path.join(models_dir, "xgboost_network.json")
        scaler_path = os.path.join(models_dir, "scaler.pkl")
        label_encoder_path = os.path.join(models_dir, "label_encoder.pkl")

        missing = [p for p in [model_path, scaler_path, label_encoder_path] if not os.path.exists(p)]
        if missing:
            raise FileNotFoundError(f"Missing network model artifacts: {missing}")

        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)

        with open(scaler_path, "rb") as f:
            self.scaler = pickle.load(f)

        with open(label_encoder_path, "rb") as f:
            self.label_encoder = pickle.load(f)

    def predict(self, features: List[float]) -> Dict[str, Any]:
        scaled = self.scaler.transform([features])
        prediction = self.model.predict(scaled)[0]
        prob = self.model.predict_proba(scaled)[0]
        return {"label": int(prediction), "confidence": float(max(prob)) * 100}

    @staticmethod
    def _xgb():
        try:
            import xgboost as xgb  # type: ignore[import-not-found]
        except Exception as e:  # pragma: no cover
            raise RuntimeError("xgboost is required for NetworkModel") from e
        return xgb

