"""
Retrain Behavior Detector Model
Fixes XGBoost version compatibility warning
"""

import os
import numpy as np
import xgboost as xgb
import joblib

def retrain_behavior_detector():
    """Retrain behavior detector to fix version warning"""
    
    print("="*60)
    print("Retraining Behavior Detector Model")
    print("="*60)
    
    # Features used by the model
    FEATURES = [
        "mouse_movements", "keystrokes", "focus_events",
        "paste_events", "time_to_submit",
        "rapid_submission", "honeypot_filled",
        "honeypot_total_length",
        "email_length", "password_length",
        "cookies_enabled"
    ]
    
    print(f"\nFeatures: {len(FEATURES)}")
    print(f"  {', '.join(FEATURES)}")
    
    # Generate synthetic training data
    print("\nGenerating training data...")
    np.random.seed(42)
    n = 1000
    
    # Legitimate users (high mouse movements, keystrokes, longer time)
    legit = np.random.normal(loc=50, scale=10, size=(n//2, len(FEATURES)))
    
    # Bots (low interaction, fast submission)
    bots = np.random.normal(loc=5, scale=2, size=(n//2, len(FEATURES)))
    
    # Combine
    X = np.vstack([legit, bots])
    y = np.hstack([np.zeros(n//2), np.ones(n//2)])  # 0=legit, 1=bot
    
    print(f"  Legitimate samples: {n//2}")
    print(f"  Bot samples: {n//2}")
    print(f"  Total samples: {n}")
    
    # Train model
    print("\nTraining XGBoost classifier...")
    model = xgb.XGBClassifier(
        max_depth=6,
        learning_rate=0.1,
        n_estimators=200,
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(X, y)
    print("  Training complete!")
    
    # Evaluate
    accuracy = model.score(X, y)
    print(f"  Accuracy: {accuracy:.4f}")
    
    # Save model
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, "behavior_detector.pkl")
    joblib.dump(model, model_path)
    print(f"\n✓ Model saved: {model_path}")
    
    # Test predictions
    print("\nTesting predictions:")
    print("-"*60)
    
    # Test legitimate user
    legit_sample = [100, 50, 30, 0, 15.5, 0, 0, 0, 20, 12, 1]  # High interaction
    legit_pred = model.predict([legit_sample])[0]
    legit_prob = model.predict_proba([legit_sample])[0][1] * 100
    print(f"  Legitimate user: {legit_sample[:5]}...")
    print(f"    Predicted: {'BOT' if legit_pred == 1 else 'HUMAN'} ({legit_prob:.1f}% bot probability)")
    
    # Test bot
    bot_sample = [2, 3, 1, 1, 0.5, 1, 1, 50, 10, 8, 0]  # Low interaction, rapid
    bot_pred = model.predict([bot_sample])[0]
    bot_prob = model.predict_proba([bot_sample])[0][1] * 100
    print(f"  Bot: {bot_sample[:5]}...")
    print(f"    Predicted: {'BOT' if bot_pred == 1 else 'HUMAN'} ({bot_prob:.1f}% bot probability)")
    
    print("\n" + "="*60)
    print("✓ Behavior Detector Retrained Successfully!")
    print("  Restart your Flask app to load the new model")
    print("="*60)

if __name__ == "__main__":
    retrain_behavior_detector()
