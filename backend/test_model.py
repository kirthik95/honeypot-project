"""
Test the trained XGBoost model with sample payloads
"""

import xgboost as xgb
import joblib
import sys

def test_model():
    """Test the trained model with various payloads"""
    
    print("="*60)
    print("Testing Trained XGBoost Model")
    print("="*60)
    
    # Load model artifacts
    try:
        model = xgb.XGBClassifier()
        model.load_model('models/web_attack_model.json')
        print("✓ Model loaded")
        
        vectorizer = joblib.load('models/web_vectorizer.pkl')
        print("✓ Vectorizer loaded")
        
        encoder = joblib.load('models/web_label_encoder.pkl')
        print("✓ Label encoder loaded")
        
        print(f"✓ Model trained on classes: {encoder.classes_.tolist()}")
        print()
        
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        sys.exit(1)
    
    # Test payloads
    test_cases = [
        ("' OR 1=1--", "sql_injection"),
        ("admin' --", "sql_injection"),
        ("<script>alert('XSS')</script>", "xss"),
        ("<img src=x onerror=alert(1)>", "xss"),
        ("; ls -la", "command_injection"),
        ("| cat /etc/passwd", "command_injection"),
        ("../../../etc/passwd", "path_traversal"),
        ("..\\..\\..\\windows\\system32", "path_traversal"),
        ("http://169.254.169.254/latest/meta-data/", "ssrf"),
        ("http://localhost/admin", "ssrf"),
        ("user@example.com", "benign"),
        ("Hello world", "benign"),
        ("Password123", "benign"),
    ]
    
    print("Testing Predictions:")
    print("-"*60)
    
    correct = 0
    total = len(test_cases)
    
    for payload, expected in test_cases:
        # Predict
        X = vectorizer.transform([payload])
        prediction_idx = model.predict(X)[0]
        predicted_label = encoder.inverse_transform([prediction_idx])[0]
        confidence = max(model.predict_proba(X)[0]) * 100
        
        # Check if correct
        is_correct = predicted_label == expected
        if is_correct:
            correct += 1
            status = "✓"
        else:
            status = "✗"
        
        # Print result
        print(f"{status} Payload: {payload[:40]:<40}")
        print(f"  Expected:  {expected:<20}")
        print(f"  Predicted: {predicted_label:<20} ({confidence:.1f}% confidence)")
        
        if not is_correct:
            print(f"  ⚠️  MISMATCH!")
        print()
    
    # Summary
    accuracy = (correct / total) * 100
    print("="*60)
    print(f"Test Results: {correct}/{total} correct ({accuracy:.1f}%)")
    print("="*60)
    
    if accuracy >= 90:
        print("✅ Model is performing well!")
    elif accuracy >= 70:
        print("⚠️  Model accuracy is acceptable but could be improved")
        print("   Consider adding more training data")
    else:
        print("❌ Model accuracy is low. Need to retrain with more data")
    
    return accuracy

if __name__ == "__main__":
    test_model()
