"""
Email Security Platform — Multi-Model Training Pipeline
========================================================
Loads emails.csv, preprocesses text, trains Naive Bayes, Logistic Regression,
and Random Forest classifiers with TF-IDF features, and saves all models +
vectorizer + per-model metrics.
"""

import os
import re
import json
import warnings
import numpy as np
import pandas as pd
import joblib
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

warnings.filterwarnings("ignore")

# ── NLTK data ────────────────────────────────────────────────────────────────
nltk.download("stopwords", quiet=True)
STOP_WORDS = set(stopwords.words("english"))
stemmer = PorterStemmer()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "emails.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")
STATS_PATH = os.path.join(MODEL_DIR, "stats.json")

# Model definitions
MODELS = {
    "nb": {
        "name": "Naive Bayes",
        "class": MultinomialNB,
        "params": {"alpha": 0.1},
        "file": "nb_model.pkl",
    },
    "lr": {
        "name": "Logistic Regression",
        "class": LogisticRegression,
        "params": {"max_iter": 1000, "C": 1.0, "solver": "lbfgs"},
        "file": "lr_model.pkl",
    },
    "rf": {
        "name": "Random Forest",
        "class": RandomForestClassifier,
        "params": {"n_estimators": 200, "max_depth": None, "random_state": 42, "n_jobs": -1},
        "file": "rf_model.pkl",
    },
}


# ── Text preprocessing ───────────────────────────────────────────────────────
def preprocess_text(text: str) -> str:
    """Lower-case, strip non-alpha chars, remove stopwords, stem."""
    text = text.lower()
    text = re.sub(r"[^a-z\s]", "", text)
    tokens = text.split()
    tokens = [stemmer.stem(w) for w in tokens if w not in STOP_WORDS]
    return " ".join(tokens)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("  EMAIL SECURITY PLATFORM — MULTI-MODEL TRAINING PIPELINE")
    print("=" * 65)

    # 1. Load data
    print("\n[1/7] Loading dataset …")
    df = pd.read_csv(DATA_PATH)
    print(f"      Loaded {len(df):,} emails  |  Columns: {list(df.columns)}")

    # 2. Basic EDA
    spam_count = int(df["spam"].sum())
    ham_count = len(df) - spam_count
    print(f"\n[2/7] Data overview")
    print(f"      Spam : {spam_count:,}  ({spam_count / len(df) * 100:.1f}%)")
    print(f"      Ham  : {ham_count:,}  ({ham_count / len(df) * 100:.1f}%)")

    # 3. Preprocess
    print("\n[3/7] Preprocessing text …")
    df["clean_text"] = df["text"].astype(str).apply(preprocess_text)
    print("      Done.")

    # 4. Vectorize
    print("\n[4/7] TF-IDF vectorization …")
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X = vectorizer.fit_transform(df["clean_text"])
    y = df["spam"].values
    print(f"      Feature matrix shape: {X.shape}")

    # 5. Train / test split
    print("\n[5/7] Splitting data (80/20) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {X_train.shape[0]:,}  |  Test: {X_test.shape[0]:,}")

    # 6. Train all models
    print("\n[6/7] Training models …")
    os.makedirs(MODEL_DIR, exist_ok=True)

    all_stats = {
        "total_emails": len(df),
        "spam_count": spam_count,
        "ham_count": ham_count,
        "feature_count": X.shape[1],
        "models": {},
    }

    best_model_key = None
    best_f1 = 0

    for key, cfg in MODELS.items():
        print(f"\n      -- {cfg['name']} --")
        model = cfg["class"](**cfg["params"])
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        print(f"      Accuracy  : {acc:.4f}")
        print(f"      Precision : {prec:.4f}")
        print(f"      Recall    : {rec:.4f}")
        print(f"      F1-Score  : {f1:.4f}")
        print(f"      Confusion Matrix: {cm.tolist()}")

        # Save model
        model_path = os.path.join(MODEL_DIR, cfg["file"])
        joblib.dump(model, model_path)
        print(f"      Saved -> {model_path}")

        all_stats["models"][key] = {
            "name": cfg["name"],
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm.tolist(),
        }

        if f1 > best_f1:
            best_f1 = f1
            best_model_key = key

    all_stats["default_model"] = best_model_key

    # Also keep top-level accuracy/precision/recall/f1 from best model for backwards compat
    best = all_stats["models"][best_model_key]
    all_stats["accuracy"] = best["accuracy"]
    all_stats["precision"] = best["precision"]
    all_stats["recall"] = best["recall"]
    all_stats["f1_score"] = best["f1_score"]
    all_stats["confusion_matrix"] = best["confusion_matrix"]

    # 7. Save vectorizer and stats
    print("\n[7/7] Saving artifacts …")
    joblib.dump(vectorizer, VECTORIZER_PATH)

    with open(STATS_PATH, "w") as f:
        json.dump(all_stats, f, indent=2)

    print(f"\n[OK] Vectorizer  -> {VECTORIZER_PATH}")
    print(f"[OK] Stats       -> {STATS_PATH}")
    print(f"[OK] Best model  -> {best_model_key} ({cfg['name']}) with F1={best_f1:.4f}")
    print("\n" + "=" * 65)
    print("  ALL MODELS TRAINED SUCCESSFULLY")
    print("=" * 65)


if __name__ == "__main__":
    main()
