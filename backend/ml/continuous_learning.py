"""
Continuous Learning System for XGBoost Web Attack Model
Automatically retrains the model from new attack data collected by the honeypot
"""

import os
import pandas as pd
import xgboost as xgb
import joblib
from datetime import datetime
from typing import List, Dict, Any
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer


class ContinuousLearningEngine:
    """
    Enables the ML model to learn from new attacks automatically.
    
    Features:
    - Collects new attack data from honeypot logs
    - Retrains model periodically (e.g., every 100 new samples)
    - Maintains model version history
    - Validates new model before deployment
    """
    
    def __init__(self, 
                 models_dir="models",
                 datasets_dir="datasets",
                 min_samples_for_retrain=100):
        """
        Initialize continuous learning engine.
        
        Args:
            models_dir: Directory containing model files
            datasets_dir: Directory containing training data
            min_samples_for_retrain: Minimum new samples before retraining
        """
        self.models_dir = models_dir
        self.datasets_dir = datasets_dir
        self.min_samples_for_retrain = min_samples_for_retrain
        
        # Paths
        self.base_csv = os.path.join(datasets_dir, "web_payloads.csv")
        self.new_attacks_csv = os.path.join(datasets_dir, "new_attacks.csv")
        self.combined_csv = os.path.join(datasets_dir, "combined_payloads.csv")
        
        # Model paths
        self.model_path = os.path.join(models_dir, "web_attack_model.json")
        self.vectorizer_path = os.path.join(models_dir, "web_vectorizer.pkl")
        self.encoder_path = os.path.join(models_dir, "web_label_encoder.pkl")
        
        # Backup paths (versioning)
        self.backup_dir = os.path.join(models_dir, "backups")
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Stats
        self.new_samples_count = 0
        self.total_retrains = 0
        self.last_retrain_time = None
    
    def collect_attack_from_log(self, log_data: Dict[str, Any]) -> bool:
        """
        Extract attack payload from honeypot log and add to training dataset.
        
        Args:
            log_data: Attack log from blob_logger
            
        Returns:
            True if attack was added successfully
        """
        # Extract payload and label from log
        attack_type = log_data.get("attack_type", "unknown")
        
        # Skip if not a real attack
        if attack_type in ["legitimate", "bot", "unknown"]:
            return False
        
        # Extract payload from various fields
        payload_fields = ["email", "username", "password", "payload", "query", "input", "comment"]
        payload_parts = []
        
        for field in payload_fields:
            val = log_data.get(field)
            if val and str(val).strip():
                payload_parts.append(str(val))
        
        if not payload_parts:
            return False
        
        payload = " ".join(payload_parts)
        
        # Map attack type to label
        label_map = {
            "sql_injection": "sql_injection",
            "xss": "xss",
            "command_injection": "command_injection",
            "path_traversal": "path_traversal",
            "ssrf": "ssrf"
        }
        
        label = label_map.get(attack_type, attack_type)
        
        # Append to new attacks CSV
        new_sample = {
            "payload": payload,
            "label": label,
            "timestamp": log_data.get("timestamp", datetime.now().isoformat()),
            "cvss_score": log_data.get("cvss_score", 0.0),
            "confidence": log_data.get("confidence", 0.0)
        }
        
        # Create or append to new_attacks.csv
        df_new = pd.DataFrame([new_sample])
        
        if os.path.exists(self.new_attacks_csv):
            df_new.to_csv(self.new_attacks_csv, mode='a', header=False, index=False)
        else:
            df_new.to_csv(self.new_attacks_csv, index=False)
        
        self.new_samples_count += 1
        print(f"[LEARNING] New attack collected: {label} (total: {self.new_samples_count})")
        
        return True
    
    def should_retrain(self) -> bool:
        """Check if we have enough new samples to trigger retraining"""
        if not os.path.exists(self.new_attacks_csv):
            return False
        
        # Count new samples
        df_new = pd.read_csv(self.new_attacks_csv)
        new_count = len(df_new)
        
        print(f"[LEARNING] New samples: {new_count}/{self.min_samples_for_retrain}")
        
        return new_count >= self.min_samples_for_retrain
    
    def retrain_model(self) -> bool:
        """
        Retrain the model with combined old + new data.
        
        Returns:
            True if retraining succeeded
        """
        print("\n" + "="*60)
        print("CONTINUOUS LEARNING: RETRAINING MODEL")
        print("="*60)
        
        try:
            # 1. Load base dataset
            if not os.path.exists(self.base_csv):
                print(f"[ERROR] Base dataset not found: {self.base_csv}")
                return False
            
            df_base = pd.read_csv(self.base_csv)
            print(f"[1/7] Loaded base dataset: {len(df_base)} samples")
            
            # 2. Load new attacks
            if not os.path.exists(self.new_attacks_csv):
                print("[WARN] No new attacks to learn from")
                return False
            
            df_new = pd.read_csv(self.new_attacks_csv)
            print(f"[2/7] Loaded new attacks: {len(df_new)} samples")
            
            # 3. Combine datasets
            # Only keep payload and label columns
            df_base = df_base[['payload', 'label']]
            df_new = df_new[['payload', 'label']]
            
            df_combined = pd.concat([df_base, df_new], ignore_index=True)
            
            # Remove duplicates
            df_combined = df_combined.drop_duplicates(subset=['payload'])
            
            print(f"[3/7] Combined dataset: {len(df_combined)} unique samples")
            
            # 4. Backup current model
            self._backup_current_model()
            
            # 5. Train new model
            print("[4/7] Training new model...")
            
            X_text = df_combined["payload"]
            y = df_combined["label"]
            
            # Character-level TF-IDF (same config as original)
            vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 3),
                analyzer="char"
            )
            
            X_vec = vectorizer.fit_transform(X_text)
            
            encoder = LabelEncoder()
            y_encoded = encoder.fit_transform(y)
            
            # Train/test split
            X_train, X_test, y_train, y_test = train_test_split(
                X_vec, y_encoded, test_size=0.2, random_state=42
            )
            
            # Train XGBoost
            model = xgb.XGBClassifier(
                max_depth=8,
                learning_rate=0.1,
                n_estimators=300,
                subsample=0.8,
                random_state=42,
                eval_metric='mlogloss'
            )
            
            model.fit(X_train, y_train)
            
            # 6. Validate new model
            train_acc = model.score(X_train, y_train)
            test_acc = model.score(X_test, y_test)
            
            print(f"[5/7] Model performance:")
            print(f"      Training accuracy: {train_acc:.4f}")
            print(f"      Testing accuracy:  {test_acc:.4f}")
            
            # Only deploy if accuracy is good (>85%)
            if test_acc < 0.85:
                print(f"[WARN] New model accuracy too low ({test_acc:.2%}), keeping old model")
                return False
            
            # 7. Save new model
            print("[6/7] Saving improved model...")
            
            model.save_model(self.model_path)
            joblib.dump(vectorizer, self.vectorizer_path)
            joblib.dump(encoder, self.encoder_path)
            
            print(f"[7/7] ✅ Model retrained successfully!")
            print(f"      Accuracy improved: {test_acc:.2%}")
            print(f"      Total samples: {len(df_combined)}")
            print(f"      New samples learned: {len(df_new)}")
            
            # Update combined CSV for next time
            df_combined.to_csv(self.combined_csv, index=False)
            
            # Clear new attacks file (they're now incorporated)
            os.remove(self.new_attacks_csv)
            
            # Update stats
            self.total_retrains += 1
            self.last_retrain_time = datetime.now()
            self.new_samples_count = 0
            
            print("="*60)
            return True
            
        except Exception as e:
            print(f"[ERROR] Retraining failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _backup_current_model(self):
        """Backup current model before retraining"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if os.path.exists(self.model_path):
            backup_path = os.path.join(self.backup_dir, f"model_{timestamp}.json")
            import shutil
            shutil.copy2(self.model_path, backup_path)
            print(f"[BACKUP] Current model saved: {backup_path}")
    
    def auto_retrain_if_needed(self, log_data: Dict[str, Any]) -> bool:
        """
        Automatically collect attack and retrain if threshold reached.
        
        Call this from your /api/track endpoint after each attack.
        
        Args:
            log_data: Attack log data
            
        Returns:
            True if model was retrained
        """
        # Collect attack
        collected = self.collect_attack_from_log(log_data)
        
        if not collected:
            return False
        
        # Check if we should retrain
        if self.should_retrain():
            return self.retrain_model()
        
        return False