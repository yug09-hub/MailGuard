"""
Email Security Platform — Flask Backend
========================================
Multi-model classifier with phishing detection, URL scanning,
explainable AI, email intelligence, and SQLite history.
"""

import os
import re
import json
import sqlite3
import hashlib
import joblib
import nltk
import numpy as np
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

# ── NLTK setup ───────────────────────────────────────────────────────────────
nltk.download("stopwords", quiet=True)
STOP_WORDS = set(stopwords.words("english"))
stemmer = PorterStemmer()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
STATS_PATH = os.path.join(MODEL_DIR, "stats.json")
DB_PATH = os.path.join(BASE_DIR, "data", "history.db")

# ── Model config ──────────────────────────────────────────────────────────────
MODEL_FILES = {
    "nb": {"file": "nb_model.pkl", "name": "Naive Bayes"},
    "lr": {"file": "lr_model.pkl", "name": "Logistic Regression"},
    "rf": {"file": "rf_model.pkl", "name": "Random Forest"},
}

# ── Load models & vectorizer ─────────────────────────────────────────────────
vectorizer = joblib.load(os.path.join(MODEL_DIR, "vectorizer.pkl"))
models = {}
for key, cfg in MODEL_FILES.items():
    path = os.path.join(MODEL_DIR, cfg["file"])
    if os.path.exists(path):
        models[key] = joblib.load(path)
    else:
        print(f"[WARN] Model not found: {path}")

# Fallback: load old single model if new ones don't exist
if not models:
    old_path = os.path.join(MODEL_DIR, "spam_model.pkl")
    if os.path.exists(old_path):
        models["nb"] = joblib.load(old_path)
        print("[INFO] Loaded legacy spam_model.pkl as 'nb'")

with open(STATS_PATH) as f:
    model_stats = json.load(f)

DEFAULT_MODEL = model_stats.get("default_model", "nb")

# ── Database setup ────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            snippet TEXT,
            prediction TEXT NOT NULL,
            confidence REAL,
            spam_probability REAL,
            ham_probability REAL,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'Low',
            model_used TEXT,
            email_hash TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()

# ── Phishing detection data ──────────────────────────────────────────────────
URGENCY_PHRASES = [
    "act now", "act immediately", "urgent action", "limited time",
    "expires today", "expire soon", "last chance", "final warning",
    "immediate response", "respond immediately", "within 24 hours",
    "within 48 hours", "hurry up", "don't delay", "claim your prize",
    "claim now", "you have been selected", "congratulations you won",
    "winner notification", "you are a winner", "once in a lifetime",
    "risk free", "no obligation", "free gift", "guaranteed",
    "act before it's too late", "offer expires", "deal ends",
    "limited offer", "exclusive deal", "don't miss out",
    "time sensitive", "take action now", "verify your account",
    "confirm your identity", "update your information",
    "suspension notice", "account suspended", "unauthorized access",
    "security alert", "unusual activity", "login attempt detected",
]

PERSONAL_INFO_PHRASES = [
    "social security", "ssn", "credit card", "bank account",
    "routing number", "pin number", "password", "login credentials",
    "date of birth", "mother's maiden name", "personal information",
    "financial information", "account number", "verify your identity",
    "confirm your details", "update your payment", "billing information",
    "tax refund", "wire transfer", "send money",
    "western union", "moneygram", "bitcoin wallet",
    "paypal account", "bank details", "full name and address",
]

SPOOFING_INDICATORS = [
    "noreply@", "no-reply@", "admin@", "support@", "security@",
    "helpdesk@", "service@", "info@", "alert@", "notification@",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".win", ".bid", ".loan", ".click",
    ".gdn", ".racing", ".review", ".country", ".stream",
    ".download", ".accountant", ".science", ".work", ".party",
    ".date", ".faith", ".cricket", ".trade", ".webcam",
    ".tk", ".ml", ".ga", ".cf", ".gq",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
    "rb.gy", "tiny.cc", "lnkd.in", "shorte.st", "adf.ly",
]

TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "yahoo.com", "apple.com", "amazon.com", "linkedin.com",
    "github.com", "stackoverflow.com", "facebook.com", "twitter.com",
    "instagram.com", "youtube.com", "wikipedia.org", "reddit.com",
    "dropbox.com", "zoom.us", "slack.com", "notion.so",
    "stripe.com", "paypal.com", "netflix.com", "spotify.com",
]

# ── Common spam keywords for XAI ─────────────────────────────────────────────
SPAM_KEYWORDS = [
    "free", "winner", "congratulations", "prize", "click", "claim",
    "offer", "deal", "discount", "money", "cash", "credit", "loan",
    "investment", "profit", "earn", "income", "wealthy", "rich",
    "guarantee", "risk-free", "limited", "exclusive", "urgent",
    "act now", "buy", "order", "subscribe", "unsubscribe",
    "viagra", "pharmacy", "pills", "medication", "weight loss",
    "diet", "supplement", "casino", "lottery", "jackpot",
    "inheritance", "beneficiary", "attorney", "million", "billion",
    "wire transfer", "bank account", "password", "verify", "confirm",
    "suspend", "locked", "unauthorized", "security", "alert",
]


# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)


# ── Text preprocessing ───────────────────────────────────────────────────────
def preprocess_text(text: str) -> str:
    """Mirror the same preprocessing used during training."""
    text = text.lower()
    text = re.sub(r"[^a-z\s]", "", text)
    tokens = text.split()
    tokens = [stemmer.stem(w) for w in tokens if w not in STOP_WORDS]
    return " ".join(tokens)


# ── Core classification ──────────────────────────────────────────────────────
def classify(text: str, model_key: str = None) -> dict:
    """Return prediction dict for a single email."""
    if model_key is None or model_key not in models:
        model_key = DEFAULT_MODEL
    model = models[model_key]

    clean = preprocess_text(text)
    vec = vectorizer.transform([clean])
    pred = model.predict(vec)[0]

    # Get probabilities
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(vec)[0]
    else:
        proba = np.array([1 - pred, pred], dtype=float)

    # ── XAI: Extract top suspicious keywords ──────────────────────────────
    feature_names = vectorizer.get_feature_names_out()
    keyword_contributions = []

    if hasattr(model, "feature_log_prob_"):
        # Naive Bayes
        spam_log_probs = model.feature_log_prob_[1]
        ham_log_probs = model.feature_log_prob_[0]
        nonzero_indices = vec[0].nonzero()[1]
        if len(nonzero_indices) > 0:
            for i in nonzero_indices:
                word = feature_names[i]
                contribution = float(spam_log_probs[i] - ham_log_probs[i])
                keyword_contributions.append({
                    "word": word,
                    "contribution": round(contribution, 4),
                    "spam_prob": round(float(np.exp(spam_log_probs[i])), 6),
                })
    elif hasattr(model, "coef_"):
        # Logistic Regression
        coefficients = model.coef_[0]
        nonzero_indices = vec[0].nonzero()[1]
        if len(nonzero_indices) > 0:
            for i in nonzero_indices:
                word = feature_names[i]
                contribution = float(coefficients[i])
                keyword_contributions.append({
                    "word": word,
                    "contribution": round(contribution, 4),
                    "spam_prob": round(abs(contribution), 6),
                })
    elif hasattr(model, "feature_importances_"):
        # Random Forest
        importances = model.feature_importances_
        nonzero_indices = vec[0].nonzero()[1]
        if len(nonzero_indices) > 0:
            for i in nonzero_indices:
                word = feature_names[i]
                contribution = float(importances[i])
                keyword_contributions.append({
                    "word": word,
                    "contribution": round(contribution, 4),
                    "spam_prob": round(contribution, 6),
                })

    # Sort by contribution (most spammy first)
    keyword_contributions.sort(key=lambda x: x["contribution"], reverse=True)

    # Top keywords
    detected_keywords = [kc["word"] for kc in keyword_contributions[:10]]
    top_contributions = keyword_contributions[:10]

    confidence = float(max(proba))
    label = "spam" if pred == 1 else "ham"

    return {
        "prediction": label,
        "confidence": round(confidence * 100, 2),
        "spam_probability": round(float(proba[1]) * 100, 2),
        "ham_probability": round(float(proba[0]) * 100, 2),
        "detected_keywords": detected_keywords,
        "keyword_contributions": top_contributions,
        "model_used": model_key,
        "model_name": MODEL_FILES[model_key]["name"],
    }


# ── Phishing detection ───────────────────────────────────────────────────────
def detect_phishing(text: str) -> dict:
    """Analyze email for phishing indicators and return risk assessment."""
    text_lower = text.lower()
    threats = []
    risk_score = 0

    # Check urgency phrases
    found_urgency = []
    for phrase in URGENCY_PHRASES:
        if phrase in text_lower:
            found_urgency.append(phrase)
    if found_urgency:
        score = min(len(found_urgency) * 8, 30)
        risk_score += score
        threats.append({
            "type": "Urgency Phrases",
            "severity": "high" if len(found_urgency) > 2 else "medium",
            "details": f"Found {len(found_urgency)} urgency phrase(s)",
            "matches": found_urgency[:5],
            "icon": "⚡",
        })

    # Check personal info requests
    found_personal = []
    for phrase in PERSONAL_INFO_PHRASES:
        if phrase in text_lower:
            found_personal.append(phrase)
    if found_personal:
        score = min(len(found_personal) * 12, 35)
        risk_score += score
        threats.append({
            "type": "Personal Info Request",
            "severity": "high",
            "details": f"Requests for {len(found_personal)} type(s) of personal data",
            "matches": found_personal[:5],
            "icon": "🔓",
        })

    # Check spoofing indicators
    found_spoofing = []
    for indicator in SPOOFING_INDICATORS:
        if indicator in text_lower:
            found_spoofing.append(indicator)
    if found_spoofing:
        risk_score += 15
        threats.append({
            "type": "Spoofing Indicators",
            "severity": "medium",
            "details": f"Found {len(found_spoofing)} potential spoofing pattern(s)",
            "matches": found_spoofing,
            "icon": "🎭",
        })

    # Check suspicious domains in text
    urls = extract_urls(text)
    suspicious_domains = []
    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    suspicious_domains.append(domain)
                    break
        except Exception:
            pass
    if suspicious_domains:
        risk_score += min(len(suspicious_domains) * 10, 25)
        threats.append({
            "type": "Suspicious Domains",
            "severity": "high",
            "details": f"Found {len(suspicious_domains)} suspicious domain(s)",
            "matches": suspicious_domains[:5],
            "icon": "🌐",
        })

    # Check for excessive capitalization (shouting)
    upper_words = len(re.findall(r"\b[A-Z]{3,}\b", text))
    if upper_words > 3:
        risk_score += min(upper_words * 3, 15)
        threats.append({
            "type": "Excessive Capitalization",
            "severity": "low",
            "details": f"Found {upper_words} ALL-CAPS words (common in spam/phishing)",
            "matches": re.findall(r"\b[A-Z]{3,}\b", text)[:5],
            "icon": "📢",
        })

    # Cap at 100
    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threats": threats,
        "threat_count": len(threats),
    }


# ── URL scanning ──────────────────────────────────────────────────────────────
def extract_urls(text: str) -> list:
    """Extract all URLs from text."""
    url_pattern = r'https?://[^\s<>"\')\]}{,]+'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    return list(set(urls))


def scan_urls(text: str) -> list:
    """Analyze all URLs found in email text."""
    urls = extract_urls(text)
    results = []

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()

            # Start with base risk
            risk_points = 0
            flags = []

            # Check HTTPS
            is_https = parsed.scheme == "https"
            if not is_https:
                risk_points += 20
                flags.append("No HTTPS")

            # Check URL shortener
            is_shortener = any(s in domain for s in URL_SHORTENERS)
            if is_shortener:
                risk_points += 25
                flags.append("URL shortener detected")

            # Check suspicious TLD
            has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
            if has_suspicious_tld:
                risk_points += 30
                flags.append("Suspicious TLD")

            # Check trusted domain
            is_trusted = any(domain.endswith(td) for td in TRUSTED_DOMAINS)
            if is_trusted:
                risk_points = max(0, risk_points - 20)

            # Check for IP address in URL
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.search(ip_pattern, domain):
                risk_points += 35
                flags.append("IP address used instead of domain")

            # Check for suspicious path patterns
            suspicious_paths = ["login", "verify", "secure", "account", "update", "confirm", "banking"]
            for sp in suspicious_paths:
                if sp in path:
                    risk_points += 10
                    flags.append(f"Suspicious path: /{sp}")
                    break

            # Check very long URL (obfuscation)
            if len(url) > 150:
                risk_points += 10
                flags.append("Unusually long URL")

            # Check for multiple subdomains
            subdomain_count = domain.count(".")
            if subdomain_count > 3:
                risk_points += 15
                flags.append("Multiple subdomains")

            # Determine status
            risk_points = min(risk_points, 100)
            if risk_points >= 50:
                status = "High Risk"
            elif risk_points >= 20:
                status = "Suspicious"
            else:
                status = "Safe"

            results.append({
                "url": url,
                "domain": domain,
                "is_https": is_https,
                "is_shortener": is_shortener,
                "is_trusted": is_trusted,
                "risk_points": risk_points,
                "status": status,
                "flags": flags,
            })
        except Exception:
            results.append({
                "url": url,
                "domain": "unknown",
                "is_https": False,
                "is_shortener": False,
                "is_trusted": False,
                "risk_points": 50,
                "status": "Suspicious",
                "flags": ["Could not parse URL"],
            })

    return results


# ── Email intelligence ────────────────────────────────────────────────────────
def analyze_email_intelligence(text: str) -> dict:
    """Analyze email metadata and content intelligence."""
    text_lower = text.lower()

    # Language detection (simple heuristic)
    try:
        from langdetect import detect
        language = detect(text)
        lang_map = {
            "en": "English", "es": "Spanish", "fr": "French",
            "de": "German", "it": "Italian", "pt": "Portuguese",
            "nl": "Dutch", "ru": "Russian", "zh-cn": "Chinese",
            "ja": "Japanese", "ko": "Korean", "ar": "Arabic",
            "hi": "Hindi",
        }
        language = lang_map.get(language, language.upper())
    except Exception:
        language = "English"

    # Sentiment analysis (simple heuristic)
    try:
        from textblob import TextBlob
        blob = TextBlob(text)
        polarity = blob.sentiment.polarity
        subjectivity = blob.sentiment.subjectivity
        if polarity > 0.2:
            sentiment = "Positive"
        elif polarity < -0.2:
            sentiment = "Negative"
        else:
            sentiment = "Neutral"
    except Exception:
        polarity = 0.0
        subjectivity = 0.5
        # Simple fallback
        positive_words = len(re.findall(r'\b(good|great|thank|please|appreciate|happy|welcome)\b', text_lower))
        negative_words = len(re.findall(r'\b(urgent|warning|suspend|lost|risk|danger|threat|problem)\b', text_lower))
        if positive_words > negative_words:
            sentiment = "Positive"
        elif negative_words > positive_words:
            sentiment = "Negative"
        else:
            sentiment = "Neutral"

    # Count links
    urls = extract_urls(text)
    link_count = len(urls)

    # Count suspicious keywords
    suspicious_count = 0
    found_spam_kws = []
    for kw in SPAM_KEYWORDS:
        if kw in text_lower:
            suspicious_count += 1
            found_spam_kws.append(kw)

    # Email length category
    char_count = len(text)
    word_count = len(text.split())
    if word_count < 50:
        length_category = "Short"
    elif word_count < 200:
        length_category = "Medium"
    else:
        length_category = "Long"

    # Check for attachments mention
    has_attachment_mention = bool(re.search(r'(attach|enclosed|see attached|find attached)', text_lower))

    return {
        "language": language,
        "sentiment": sentiment,
        "polarity": round(polarity, 3),
        "subjectivity": round(subjectivity, 3),
        "char_count": char_count,
        "word_count": word_count,
        "length_category": length_category,
        "link_count": link_count,
        "suspicious_keyword_count": suspicious_count,
        "suspicious_keywords_found": found_spam_kws[:10],
        "has_attachment_mention": has_attachment_mention,
    }


# ── Highlight suspicious words ───────────────────────────────────────────────
def get_highlighted_text(text: str, keywords: list) -> str:
    """Return the email text with suspicious words wrapped in markers."""
    if not keywords:
        return text
    # Create pattern from keywords
    pattern = r'\b(' + '|'.join(re.escape(kw) for kw in keywords) + r')\b'
    highlighted = re.sub(pattern, r'[[HIGHLIGHT]]\1[[/HIGHLIGHT]]', text, flags=re.IGNORECASE)
    return highlighted


# ── Save to history ───────────────────────────────────────────────────────────
def save_to_history(result: dict, text: str):
    """Save prediction result to SQLite database."""
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO history (timestamp, snippet, prediction, confidence,
               spam_probability, ham_probability, risk_score, risk_level, model_used, email_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                text[:150] + ("…" if len(text) > 150 else ""),
                result["prediction"],
                result["confidence"],
                result["spam_probability"],
                result["ham_probability"],
                result.get("phishing", {}).get("risk_score", 0),
                result.get("phishing", {}).get("risk_level", "Low"),
                result.get("model_used", "nb"),
                hashlib.md5(text.encode()).hexdigest()[:12],
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ── Full analysis (combines everything) ───────────────────────────────────────
def full_analysis(text: str, model_key: str = None) -> dict:
    """Run all analysis engines on an email."""
    # Classification
    result = classify(text, model_key)

    # Phishing
    phishing = detect_phishing(text)
    result["phishing"] = phishing

    # URL scanning
    url_results = scan_urls(text)
    result["url_scan"] = url_results

    # Email intelligence
    intelligence = analyze_email_intelligence(text)
    result["intelligence"] = intelligence

    # Highlighted text
    all_suspicious = result["detected_keywords"][:10]
    # Also highlight phishing keywords
    for threat in phishing["threats"]:
        all_suspicious.extend(threat.get("matches", [])[:3])
    result["highlighted_text"] = get_highlighted_text(text, list(set(all_suspicious)))

    return result


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/predict", methods=["POST"])
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    text = data.get("email_text", data.get("text", "")).strip()
    model_key = data.get("model", None)

    if not text:
        return jsonify({"error": "No email text provided."}), 400

    result = full_analysis(text, model_key)
    result["timestamp"] = datetime.now().isoformat()
    result["snippet"] = text[:150] + ("…" if len(text) > 150 else "")

    # Save to DB
    save_to_history(result, text)

    return jsonify(result)


@app.route("/api/batch_predict", methods=["POST"])
@app.route("/batch_predict", methods=["POST"])
def batch_predict():
    emails = []

    if "file" in request.files:
        file = request.files["file"]
        if file.filename.endswith(".csv"):
            try:
                df = pd.read_csv(file)
                email_col = next(
                    (col for col in df.columns if col.lower() in ["text", "email", "content", "body", "message"]),
                    None,
                )
                if email_col:
                    emails = df[email_col].dropna().astype(str).tolist()
                else:
                    for col in df.columns:
                        if df[col].dtype == "object":
                            emails = df[col].dropna().astype(str).tolist()
                            break
            except Exception as e:
                return jsonify({"error": f"Failed to parse CSV: {str(e)}"}), 400
        else:
            return jsonify({"error": "Only CSV files are supported for file upload."}), 400
    else:
        data = request.get_json(silent=True) or {}
        emails = data.get("emails", [])

    if not emails:
        return jsonify({"error": "No emails provided in request or CSV."}), 400

    model_key = request.form.get("model") or (request.get_json(silent=True) or {}).get("model", None)

    results = []
    for email_text in emails[:100]:  # Cap at 100 emails
        text = str(email_text).strip()
        if text:
            r = full_analysis(text, model_key)
            r["snippet"] = text[:150] + ("…" if len(text) > 150 else "")
            r["timestamp"] = datetime.now().isoformat()
            results.append(r)
            save_to_history(r, text)

    spam_count = sum(1 for r in results if r["prediction"] == "spam")
    high_risk_count = sum(1 for r in results if r.get("phishing", {}).get("risk_level") == "High")
    avg_confidence = round(np.mean([r["confidence"] for r in results]), 2) if results else 0

    return jsonify({
        "results": results,
        "total": len(results),
        "spam_count": spam_count,
        "ham_count": len(results) - spam_count,
        "high_risk_count": high_risk_count,
        "avg_confidence": avg_confidence,
    })


@app.route("/api/stats")
@app.route("/stats")
def stats():
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) as cnt FROM history").fetchone()
    total_predictions = row["cnt"] if row else 0
    conn.close()

    return jsonify({
        **model_stats,
        "predictions_made": total_predictions,
        "available_models": list(models.keys()),
    })


@app.route("/api/history")
@app.route("/history")
def history():
    filter_type = request.args.get("filter", "all")
    search = request.args.get("search", "")
    limit = min(int(request.args.get("limit", 50)), 200)

    conn = get_db()
    query = "SELECT * FROM history"
    params = []
    conditions = []

    if filter_type in ("spam", "ham"):
        conditions.append("prediction = ?")
        params.append(filter_type)

    if search:
        conditions.append("snippet LIKE ?")
        params.append(f"%{search}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


@app.route("/api/history/<int:entry_id>", methods=["DELETE"])
def delete_history(entry_id):
    conn = get_db()
    conn.execute("DELETE FROM history WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/analytics")
def analytics():
    """Return analytics data for the dashboard charts."""
    conn = get_db()

    # Spam vs Ham distribution
    spam_count = conn.execute("SELECT COUNT(*) FROM history WHERE prediction='spam'").fetchone()[0]
    ham_count = conn.execute("SELECT COUNT(*) FROM history WHERE prediction='ham'").fetchone()[0]

    # Risk distribution
    low_risk = conn.execute("SELECT COUNT(*) FROM history WHERE risk_level='Low'").fetchone()[0]
    med_risk = conn.execute("SELECT COUNT(*) FROM history WHERE risk_level='Medium'").fetchone()[0]
    high_risk = conn.execute("SELECT COUNT(*) FROM history WHERE risk_level='High'").fetchone()[0]

    # Avg confidence
    avg_conf = conn.execute("SELECT AVG(confidence) FROM history").fetchone()[0] or 0

    # Recent trend (last 20)
    recent = conn.execute(
        "SELECT prediction, confidence, risk_score, timestamp FROM history ORDER BY id DESC LIMIT 20"
    ).fetchall()

    conn.close()

    # Model comparison from stats
    model_comparison = []
    models_data = model_stats.get("models", {})
    for key, data in models_data.items():
        model_comparison.append({
            "key": key,
            "name": data["name"],
            "accuracy": data["accuracy"],
            "precision": data["precision"],
            "recall": data["recall"],
            "f1_score": data["f1_score"],
        })

    return jsonify({
        "spam_ham": {"spam": spam_count, "ham": ham_count},
        "risk_distribution": {"low": low_risk, "medium": med_risk, "high": high_risk},
        "avg_confidence": round(avg_conf, 2),
        "total_analyses": spam_count + ham_count,
        "model_comparison": model_comparison,
        "recent_trend": [dict(r) for r in recent],
    })


@app.route("/api/models")
def list_models():
    """Return available models and their info."""
    result = []
    models_data = model_stats.get("models", {})
    for key in models.keys():
        info = models_data.get(key, {})
        result.append({
            "key": key,
            "name": MODEL_FILES[key]["name"],
            "accuracy": info.get("accuracy", 0),
            "precision": info.get("precision", 0),
            "recall": info.get("recall", 0),
            "f1_score": info.get("f1_score", 0),
            "is_default": key == DEFAULT_MODEL,
        })
    return jsonify(result)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n>>> Email Security Platform running at http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
