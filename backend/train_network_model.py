"""
Train Network Attack Detection Model
For analyzing network-level traffic patterns
"""

import os
import numpy as np
import xgboost as xgb
import pickle
from sklearn.preprocessing import StandardScaler, LabelEncoder

def train_network_model():
    """Train network-level attack detection model"""
    
    print("="*60)
    print("Training Network Attack Detection Model")
    print("="*60)
    
    # Network features (11 features matching your backend)
    FEATURES = [
        "packet_size",
        "time_to_live",
        "flags",
        "protocol",
        "source_port",
        "dest_port",
        "packet_count",
        "byte_count",
        "duration",
        "is_syn_flood",
        "port_scan_detected"
    ]
    
    print(f"\nNetwork Features: {len(FEATURES)}")
    
    # Generate synthetic network traffic data
    print("\nGenerating synthetic network data...")
    np.random.seed(42)
    n = 2000
    
    # Normal traffic
    normal = np.random.normal(loc=[500, 64, 0, 6, 50000, 80, 10, 5000, 1.0, 0, 0], 
                              scale=[200, 10, 0.5, 2, 10000, 100, 5, 2000, 0.5, 0, 0],
                              size=(n//4, len(FEATURES)))
    
    # DDoS attack (high packet count, short duration, SYN flood)
    ddos = np.random.normal(loc=[64, 64, 2, 6, 50000, 80, 1000, 64000, 0.1, 1, 0],
                            scale=[20, 5, 0.5, 1, 10000, 50, 200, 10000, 0.05, 0, 0],
                            size=(n//4, len(FEATURES)))
    
    # Port scan (many different ports, low packet size)
    portscan = np.random.normal(loc=[40, 128, 1, 6, 50000, 5000, 100, 4000, 5.0, 0, 1],
                                 scale=[10, 20, 0.5, 2, 10000, 3000, 50, 1000, 2.0, 0, 0],
                                 size=(n//4, len(FEATURES)))
    
    # Malware C2 (specific ports, regular intervals)
    malware = np.random.normal(loc=[512, 64, 0, 6, 50000, 443, 5, 2560, 60.0, 0, 0],
                                scale=[100, 10, 0.5, 1, 5000, 10, 2, 500, 10.0, 0, 0],
                                size=(n//4, len(FEATURES)))
    
    # Combine data
    X = np.vstack([normal, ddos, portscan, malware])
    y = np.hstack([
        np.zeros(n//4),      # 0 = normal
        np.ones(n//4),       # 1 = ddos
        np.full(n//4, 2),    # 2 = portscan
        np.full(n//4, 3)     # 3 = malware
    ])
    
    print(f"  Normal traffic: {n//4}")
    print(f"  DDoS attacks: {n//4}")
    print(f"  Port scans: {n//4}")
    print(f"  Malware C2: {n//4}")
    print(f"  Total samples: {n}")
    
    # Scale features
    print("\nScaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Encode labels
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y.astype(int))
    
    # Train XGBoost
    print("\nTraining XGBoost classifier...")
    model = xgb.XGBClassifier(
        max_depth=8,
        learning_rate=0.1,
        n_estimators=300,
        random_state=42,
        eval_metric='mlogloss'
    )
    
    model.fit(X_scaled, y_encoded)
    
    # Evaluate
    accuracy = model.score(X_scaled, y_encoded)
    print(f"  Training accuracy: {accuracy:.4f}")
    
    # Save artifacts
    models_dir = "models"
    os.makedirs(models_dir, exist_ok=True)
    
    # Save XGBoost model
    model_path = os.path.join(models_dir, "xgboost_network.json")
    model.save_model(model_path)
    print(f"\n✓ Model saved: {model_path}")
    
    # Save scaler
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    print(f"✓ Scaler saved: {scaler_path}")
    
    # Save label encoder
    encoder_path = os.path.join(models_dir, "label_encoder.pkl")
    with open(encoder_path, "wb") as f:
        pickle.dump(encoder, f)
    print(f"✓ Label encoder saved: {encoder_path}")
    
    # Test predictions
    print("\nTesting predictions:")
    print("-"*60)
    
    test_samples = [
        (normal[0], "Normal Traffic"),
        (ddos[0], "DDoS Attack"),
        (portscan[0], "Port Scan"),
        (malware[0], "Malware C2")
    ]
    
    for sample, label in test_samples:
        sample_scaled = scaler.transform([sample])
        pred = model.predict(sample_scaled)[0]
        prob = max(model.predict_proba(sample_scaled)[0]) * 100
        pred_label = encoder.inverse_transform([pred])[0]
        
        print(f"  {label}:")
        print(f"    Predicted class: {pred_label} ({prob:.1f}% confidence)")
    
    print("\n" + "="*60)
    print("✓ Network Model Trained Successfully!")
    print("  Restart your Flask app to load the new model")
    print("="*60)

if __name__ == "__main__":
    train_network_model()
