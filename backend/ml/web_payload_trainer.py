import pandas as pd
import xgboost as xgb
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import os

def train_web_model(csv_path):
    df = pd.read_csv(csv_path)

    # Expecting:
    # payload column
    # label column
    X_text = df["payload"]
    y = df["label"]

    # Character-level TF-IDF
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 3),
        analyzer="char"
    )

    X_vec = vectorizer.fit_transform(X_text)

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X_vec, y_encoded, test_size=0.2, random_state=42
    )

    model = xgb.XGBClassifier(
        max_depth=8,
        learning_rate=0.1,
        n_estimators=300,
        subsample=0.8,
        random_state=42
    )

    model.fit(X_train, y_train)

    print("Accuracy:", model.score(X_test, y_test))

    # Save models
    os.makedirs("models", exist_ok=True)

    model.save_model("models/web_attack_model.json")
    joblib.dump(vectorizer, "models/web_vectorizer.pkl")
    joblib.dump(encoder, "models/web_label_encoder.pkl")

    print("✅ Web model saved successfully")

if __name__ == "__main__":
    train_web_model("datasets/web_payloads.csv")
