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
import uuid
import joblib
import nltk
from functools import wraps
import numpy as np
from datetime import datetime
from urllib.parse import urlparse
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

# Optional imports - may not be available on all platforms (e.g., Vercel)
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None

# Performance Optimization: Top-level imports
try:
    from langdetect import detect
except ImportError:
    detect = None
try:
    from textblob import TextBlob
except ImportError:
    TextBlob = None

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort, send_file
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
# Flask-Mail and itsdangerous removed as Forgot Password feature was deleted

# Import IMAP client (optional for Vercel)
try:
    from imap_client import (
        create_session, close_session, fetch_with_session,
        detect_imap_server, active_sessions, IMAPClient
    )
    IMAP_AVAILABLE = True
except Exception as e:
    print(f"[WARN] IMAP client not available: {e}")
    IMAP_AVAILABLE = False
    create_session = close_session = fetch_with_session = detect_imap_server = None
    active_sessions = {}
    IMAPClient = None

# Import OAuth2 config (optional for Vercel)
try:
    from oauth_config import (
        get_oauth_url, exchange_code_for_token, refresh_access_token,
        OAUTH_CONFIG, DEFAULT_REDIRECT_URI
    )
    OAUTH_AVAILABLE = True
except Exception as e:
    print(f"[WARN] OAuth config not available: {e}")
    OAUTH_AVAILABLE = False
    get_oauth_url = exchange_code_for_token = refresh_access_token = None
    OAUTH_CONFIG = {}
    DEFAULT_REDIRECT_URI = ''

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
STATS_PATH = os.path.join(MODEL_DIR, "stats.json")

# In Vercel, the filesystem is read-only except for /tmp
if os.environ.get("VERCEL"):
    DB_PATH = os.path.join("/tmp", "history.db")
    # Tell NLTK to use /tmp for data
    NLTK_DATA_DIR = os.path.join("/tmp", "nltk_data")
    if not os.path.exists(NLTK_DATA_DIR):
        os.makedirs(NLTK_DATA_DIR, exist_ok=True)
    if NLTK_DATA_DIR not in nltk.data.path:
        nltk.data.path.append(NLTK_DATA_DIR)
else:
    DB_PATH = os.path.join(BASE_DIR, "data", "history.db")
    NLTK_DATA_DIR = None


# ── NLTK setup ───────────────────────────────────────────────────────────────
_nltk_initialized = False

def ensure_nltk():
    global _nltk_initialized
    if _nltk_initialized:
        return
    try:
        # Try to download to the designated directory
        target_dir = NLTK_DATA_DIR if (globals().get('NLTK_DATA_DIR') and os.environ.get("VERCEL")) else None
        nltk.download("stopwords", download_dir=target_dir, quiet=True)
        nltk.download("punkt", download_dir=target_dir, quiet=True)
        _nltk_initialized = True
    except Exception as e:
        print(f"[WARN] NLTK download failed: {e}")

# We don't call ensure_nltk() here anymore. We call it inside preprocess_text.
STOP_WORDS = None
stemmer = PorterStemmer()

# ── Model config ──────────────────────────────────────────────────────────────
MODEL_FILES = {
    "nb": {"file": "nb_model.pkl", "name": "Naive Bayes"},
    "lr": {"file": "lr_model.pkl", "name": "Logistic Regression"},
    "rf": {"file": "rf_model.pkl", "name": "Random Forest"},
}

# ── Lazy Loading ─────────────────────────────────────────────────────────────
_models = {}
_vectorizer = None

def get_vectorizer():
    global _vectorizer
    if _vectorizer is None:
        path = os.path.join(MODEL_DIR, "vectorizer.pkl")
        if os.path.exists(path):
            _vectorizer = joblib.load(path)
        else:
            raise FileNotFoundError(f"Vectorizer not found at {path}")
    return _vectorizer

def get_model(key):
    global _models
    if key not in _models:
        cfg = MODEL_FILES.get(key)
        if not cfg:
            # Fallback for old single model
            if key == "nb":
                path = os.path.join(MODEL_DIR, "spam_model.pkl")
                if os.path.exists(path):
                    _models[key] = joblib.load(path)
                    return _models[key]
            raise ValueError(f"Unknown model key: {key}")
        
        path = os.path.join(MODEL_DIR, cfg["file"])
        if os.path.exists(path):
            _models[key] = joblib.load(path)
        else:
            raise FileNotFoundError(f"Model file not found: {path}")
    return _models[key]

# Load stats eagerly as it's small JSON
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
    
    # Table for IMAP email accounts (session-only, no password storage)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS imap_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            email_address TEXT NOT NULL,
            imap_server TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_fetch_at TEXT
        )
    """)
    
    # Table for fetched emails with classification results
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fetched_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            uid TEXT NOT NULL,
            subject TEXT,
            sender TEXT,
            recipient TEXT,
            date TEXT,
            body TEXT,
            prediction TEXT,
            confidence REAL,
            spam_probability REAL,
            ham_probability REAL,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'Low',
            fetched_at TEXT NOT NULL,
            UNIQUE(session_id, uid)
        )
    """)
    
    # Users table for authentication
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT
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
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)

# Initialize Flask-Bcrypt
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Mail configuration removed as Forgot Password feature was deleted


# ── User Model ───────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, email, role='user', active=True):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self._is_active = active
    
    @property
    def is_active(self):
        return self._is_active
    
    def is_admin(self):
        return self.role == 'admin'
    
    def get_id(self):
        return str(self.id)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    """Load user from database by ID."""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    
    if user:
        return User(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            role=user['role'],
            active=bool(user['is_active'])
        )
    return None


def create_default_admin():
    """Create default admin user if no users exist."""
    conn = get_db()
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    
    if user_count == 0:
        # Create default admin user
        password_hash = bcrypt.generate_password_hash('admin123').decode('utf-8')
        conn.execute(
            """INSERT INTO users (username, email, password_hash, role, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            ('admin', 'admin@mailguard.local', password_hash, 'admin', datetime.now().isoformat())
        )
        conn.commit()
        print("[INFO] Default admin user created: admin/admin123")
    
    conn.close()


# Create default admin on startup
create_default_admin()

# Performance Optimization: Ensure NLTK is ready once at startup
ensure_nltk()


# ── Text preprocessing ───────────────────────────────────────────────────────
def preprocess_text(text: str) -> str:
    """Mirror the same preprocessing used during training."""
    global STOP_WORDS
    if STOP_WORDS is None:
        try:
            STOP_WORDS = set(stopwords.words("english"))
        except Exception:
            ensure_nltk()
            STOP_WORDS = set(stopwords.words("english"))
    
    text = text.lower()
    text = re.sub(r"[^a-z\s]", "", text)
    tokens = text.split()
    tokens = [stemmer.stem(w) for w in tokens if w not in STOP_WORDS]
    return " ".join(tokens)


# ── Core classification ──────────────────────────────────────────────────────
def classify(text: str, model_key: str = None) -> dict:
    """Return prediction dict for a single email."""
    if model_key is None:
        model_key = DEFAULT_MODEL
    
    try:
        model = get_model(model_key)
        vectorizer = get_vectorizer()
    except Exception as e:
        return {
            "error": str(e),
            "prediction": "error",
            "confidence": 0,
            "spam_probability": 0,
            "ham_probability": 0,
            "model_used": model_key,
            "model_name": MODEL_FILES.get(model_key, {"name": "Unknown"})["name"],
        }

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
        "model_name": MODEL_FILES.get(model_key, {"name": "Unknown"})["name"],
    }


def ensemble_classify(text: str) -> dict:
    """Run all models and return ensemble result using majority voting."""
    models_to_run = ["nb", "lr", "rf"]
    all_contributions = {}
    individual_results = {}
    predictions = []
    probabilities = []
    all_detected_keywords = []

    for key in models_to_run:
        res = classify(text, key)
        if "error" in res:
            continue
        
        individual_results[key] = {
            "prediction": res["prediction"],
            "confidence": res["confidence"],
            "spam_probability": res["spam_probability"],
            "ham_probability": res["ham_probability"],
            "model_name": res["model_name"]
        }
        predictions.append(1 if res["prediction"] == "spam" else 0)
        probabilities.append(res["spam_probability"])
        all_detected_keywords.extend(res.get("detected_keywords", []))

        # Collect contributions
        for kc in res.get("keyword_contributions", []):
            word = kc["word"]
            if word not in all_contributions:
                all_contributions[word] = 0
            # Aggregate the score (average later)
            all_contributions[word] += kc["contribution"]

    if not predictions:
        return {"error": "All models failed to run."}

    # Majority voting
    avg_pred = np.mean(predictions)
    final_label = "spam" if avg_pred > 0.5 else "ham"
    
    # Agreement
    agreement_count = sum(1 for p in predictions if (1 if final_label == "spam" else 0) == p)
    agreement_percentage = round((agreement_count / len(predictions)) * 100, 2)
    
    # Average probability score as confidence
    avg_spam_prob = np.mean(probabilities)
    confidence_score = round(avg_spam_prob if final_label == "spam" else (100 - avg_spam_prob), 2)

    # Unique keywords from all models
    unique_keywords = list(set(all_detected_keywords))[:15]

    # Aggregate keyword contributions for XAI
    aggregated_xai = []
    for word, total_score in all_contributions.items():
        avg_score = total_score / len(models_to_run)
        aggregated_xai.append({
            "word": word,
            "contribution": round(avg_score, 4)
        })
    
    # Sort by magnitude of contribution
    aggregated_xai.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    top_xai = aggregated_xai[:10]

    return {
        "prediction": final_label,
        "confidence": confidence_score,
        "spam_probability": round(avg_spam_prob, 2),
        "ham_probability": round(100 - avg_spam_prob, 2),
        "individual_predictions": individual_results,
        "agreement_percentage": agreement_percentage,
        "detected_keywords": [x["word"] for x in top_xai],
        "keyword_contributions": top_xai,
        "model_used": "ensemble",
        "model_name": "Ensemble (NB + LR + RF)"
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
    language = "English"
    if detect:
        try:
            detected_lang = detect(text)
            lang_map = {
                "en": "English", "es": "Spanish", "fr": "French",
                "de": "German", "it": "Italian", "pt": "Portuguese",
                "nl": "Dutch", "ru": "Russian", "zh-cn": "Chinese",
                "ja": "Japanese", "ko": "Korean", "ar": "Arabic",
                "hi": "Hindi",
            }
            language = lang_map.get(detected_lang, detected_lang.upper())
        except Exception as e:
            print(f"[WARN] Language detection failed: {e}")

    # Sentiment analysis (simple heuristic)
    polarity = 0.0
    subjectivity = 0.5
    sentiment = "Neutral"
    if TextBlob:
        try:
            blob = TextBlob(text)
            polarity = blob.sentiment.polarity
            subjectivity = blob.sentiment.subjectivity
            if polarity > 0.2:
                sentiment = "Positive"
            elif polarity < -0.2:
                sentiment = "Negative"
            else:
                sentiment = "Neutral"
        except Exception as e:
            print(f"[WARN] Sentiment analysis failed: {e}")
            # Simple fallback logic already exists below if needed, 
            # but we'll try to use polarity if TextBlob succeeded.
    
    if not TextBlob or sentiment == "Neutral":
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
    if model_key == "ensemble" or model_key is None:
        result = ensemble_classify(text)
    else:
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


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Check if this is an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json
        
        if not username or not password:
            if is_ajax:
                return jsonify({"status": "error", "message": "Please enter both username and password."})
            flash('Please enter both username and password.', 'danger')
            return render_template("login.html")
        
        # Find user in database
        conn = get_db()
        user_data = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
        ).fetchone()
        conn.close()
        
        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                active=bool(user_data['is_active'])
            )
            login_user(user, remember=True)
            
            # Update last login
            conn = get_db()
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now().isoformat(), user_data['id'])
            )
            conn.commit()
            conn.close()
            
            # Determine redirect URL
            next_page = request.args.get('next')
            redirect_url = next_page if (next_page and next_page.startswith('/')) else url_for('index')
            
            if is_ajax:
                return jsonify({
                    "status": "success", 
                    "message": f"Welcome back, {username}!", 
                    "redirect": redirect_url
                })
            
            flash(f'Welcome back, {username}!', 'success')
            return redirect(redirect_url)
        else:
            if is_ajax:
                return jsonify({"status": "error", "message": "Invalid password"})
            flash('Invalid password', 'danger')
    
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Handle user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Validation
        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template("signup.html")
        
        # Check if username or email already exists
        conn = get_db()
        existing = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (username, email)
        ).fetchone()
        
        if existing:
            conn.close()
            if existing['username'] == username:
                flash('Username already taken.', 'danger')
            else:
                flash('Email already registered.', 'danger')
            return render_template("signup.html")
        
        # Create new user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            conn.execute(
                """INSERT INTO users (username, email, password_hash, role, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (username, email, password_hash, 'user', datetime.now().isoformat())
            )
            conn.commit()
            conn.close()
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.close()
            flash('Error creating account. Please try again.', 'danger')
            return render_template("signup.html")
    
    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('login'))


# Forgot password and reset password routes were removed


@app.route("/api/auth/status")
def auth_status():
    """Return current authentication status."""
    if current_user.is_authenticated:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": current_user.id,
                "username": current_user.username,
                "email": current_user.email,
                "role": current_user.role,
                "is_admin": current_user.is_admin()
            }
        })
    return jsonify({"authenticated": False})


# ═══════════════════════════════════════════════════════════════════════════════
# Main Application Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "env": "vercel" if os.environ.get("VERCEL") else "local",
        "models_loaded": list(_models.keys()),
        "vectorizer_loaded": _vectorizer is not None
    })


@app.route("/api/predict", methods=["POST"])
@app.route("/predict", methods=["POST"])
@login_required
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
@login_required
def batch_predict():
    emails = []

    if "file" in request.files:
        file = request.files["file"]
        if file.filename.endswith(".csv"):
            if not PANDAS_AVAILABLE:
                return jsonify({"error": "CSV processing requires pandas which is not available in this environment"}), 503
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
@login_required
def stats():
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) as cnt FROM history").fetchone()
    total_predictions = row["cnt"] if row else 0
    conn.close()

    return jsonify({
        **model_stats,
        "predictions_made": total_predictions,
        "available_models": list(MODEL_FILES.keys()),
    })


@app.route("/api/history")
@app.route("/history")
@login_required
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
@login_required
def delete_history(entry_id):
    conn = get_db()
    conn.execute("DELETE FROM history WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/analytics")
@login_required
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
@login_required
def list_models():
    """Return available models and their info."""
    result = []
    models_data = model_stats.get("models", {})
    for key in MODEL_FILES.keys():
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


# ═══════════════════════════════════════════════════════════════════════════════
# IMAP Email Integration Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/imap/detect-server", methods=["POST"])
@login_required
def detect_server():
    """Auto-detect IMAP server for an email address."""
    if not IMAP_AVAILABLE:
        return jsonify({"error": "IMAP functionality is not available in this environment"}), 503
    data = request.get_json(force=True)
    email_address = data.get("email", "").strip()
    
    if not email_address or "@" not in email_address:
        return jsonify({"error": "Valid email address required"}), 400
    
    config = detect_imap_server(email_address)
    return jsonify({
        "email": email_address,
        "imap_server": config["server"],
        "port": config["port"],
        "ssl": config["ssl"]
    })


@app.route("/api/imap/connect", methods=["POST"])
@login_required
def imap_connect():
    """Connect to IMAP server and create a session."""
    if not IMAP_AVAILABLE:
        return jsonify({"error": "IMAP functionality is not available in this environment"}), 503
    data = request.get_json(force=True)
    email_address = data.get("email", "").strip()
    app_password = data.get("password", "").strip()
    imap_server = data.get("imap_server", "").strip()
    demo_mode = data.get("demo", False)
    
    if not email_address or "@" not in email_address:
        return jsonify({"error": "Valid email address required"}), 400
    
    # Demo mode for testing without real credentials
    if demo_mode or app_password.lower() == 'demo':
        try:
            session_id = str(uuid.uuid4())
            
            # Try to save to database, but don't fail if table doesn't exist
            try:
                conn = get_db()
                conn.execute(
                    """INSERT INTO imap_sessions (session_id, email_address, imap_server, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (session_id, email_address, 'demo-server', datetime.now().isoformat())
                )
                conn.commit()
                conn.close()
            except Exception as db_err:
                print(f"[Demo Mode] DB warning (non-critical): {db_err}")
            
            # Add demo session to active sessions
            active_sessions[session_id] = {
                'demo': True,
                'email_address': email_address,
                'created_at': datetime.now().isoformat()
            }
            
            return jsonify({
                "success": True,
                "session_id": session_id,
                "email": email_address,
                "message": "Demo mode - connected (no real emails)"
            })
        except Exception as e:
            print(f"[Demo Mode Error] {e}")
            return jsonify({"error": f"Demo mode error: {str(e)}"}), 500
    
    if not app_password:
        return jsonify({"error": "App password required"}), 400

    config = detect_imap_server(email_address)
    imap_server = imap_server or config["server"]
    
    try:
        # Create session
        session_id = create_session(email_address, app_password, imap_server)
        
        # Save to database
        try:
            conn = get_db()
            conn.execute(
                """INSERT INTO imap_sessions (session_id, email_address, imap_server, created_at)
                   VALUES (?, ?, ?, ?)""",
                (session_id, email_address, imap_server, datetime.now().isoformat())
            )
            conn.commit()
            conn.close()
        except Exception as db_err:
            print(f"[IMAP] DB error (non-critical): {db_err}")
        
        return jsonify({
            "success": True,
            "session_id": session_id,
            "email": email_address,
            "imap_server": imap_server
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401


# ═══════════════════════════════════════════════════════════════════════════════
# Administrative Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    """Serve the admin dashboard."""
    return render_template("admin.html")


@app.route("/api/admin/users")
@login_required
@admin_required
def admin_list_users():
    """Return list of all users."""
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, email, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Delete a user account."""
    if current_user.id == user_id:
        return jsonify({"error": "You cannot delete your own admin account."}), 400
        
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_user(user_id):
    """Enable or disable a user account."""
    if current_user.id == user_id:
        return jsonify({"error": "You cannot deactivate your own admin account."}), 400
        
    conn = get_db()
    user = conn.execute("SELECT is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
        
    new_status = 0 if user['is_active'] else 1
    conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "is_active": bool(new_status)})


@app.route("/api/admin/stats")
@login_required
@admin_required
def admin_system_stats():
    """System-wide usage statistics."""
    conn = get_db()
    
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    total_analyses = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    
    # Analyses per day (last 7 days)
    daily = conn.execute("""
        SELECT date(timestamp) as day, COUNT(*) as count 
        FROM history 
        GROUP BY day 
        ORDER BY day DESC 
        LIMIT 7
    """).fetchall()
    
    # Model distribution
    models = conn.execute("""
        SELECT model_used, COUNT(*) as count 
        FROM history 
        GROUP BY model_used
    """).fetchall()
    
    conn.close()
    
    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "total_analyses": total_analyses,
        "daily_analyses": [dict(d) for d in daily],
        "model_distribution": {m['model_used']: m['count'] for m in models}
    })

@app.route("/api/imap/disconnect", methods=["POST"])
def imap_disconnect():
    """Disconnect and close an IMAP session."""
    if not IMAP_AVAILABLE:
        return jsonify({"error": "IMAP functionality is not available in this environment"}), 503
    data = request.get_json(force=True)
    session_id = data.get("session_id", "").strip()
    
    if not session_id:
        return jsonify({"error": "Session ID required"}), 400
    
    # Close session
    close_session(session_id)
    
    # Remove from database
    conn = get_db()
    conn.execute("DELETE FROM imap_sessions WHERE session_id = ?", (session_id,))
    conn.execute("DELETE FROM fetched_emails WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "Disconnected successfully"})


@app.route("/api/imap/fetch", methods=["POST"])
def imap_fetch():
    """Fetch emails from inbox and classify them."""
    if not IMAP_AVAILABLE:
        return jsonify({"error": "IMAP functionality is not available in this environment"}), 503
    data = request.get_json(force=True)
    session_id = data.get("session_id", "").strip()
    limit = min(int(data.get("limit", 20)), 50)  # Max 50 emails
    
    if not session_id:
        return jsonify({"error": "Session ID required"}), 400
    
    try:
        # Fetch emails using session
        emails = fetch_with_session(session_id, limit=limit)
        
        # Classify each email
        results = []
        conn = get_db()
        
        for email_data in emails:
            # Combine subject and body for classification
            text_to_classify = f"Subject: {email_data['subject']}\n\n{email_data['body']}"
            
            # Run classification
            analysis = full_analysis(text_to_classify, model_key="ensemble")
            
            # Save to database
            conn.execute(
                """INSERT OR REPLACE INTO fetched_emails 
                   (session_id, uid, subject, sender, recipient, date, body,
                    prediction, confidence, spam_probability, ham_probability,
                    risk_score, risk_level, fetched_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    email_data['uid'],
                    email_data['subject'],
                    email_data['sender'],
                    email_data['recipient'],
                    email_data['date'],
                    email_data['body'][:2000],  # Limit body size
                    analysis['prediction'],
                    analysis['confidence'],
                    analysis['spam_probability'],
                    analysis['ham_probability'],
                    analysis.get('phishing', {}).get('risk_score', 0),
                    analysis.get('phishing', {}).get('risk_level', 'Low'),
                    datetime.now().isoformat()
                )
            )
            
            results.append({
                **email_data,
                "prediction": analysis['prediction'],
                "confidence": analysis['confidence'],
                "spam_probability": analysis['spam_probability'],
                "ham_probability": analysis['ham_probability'],
                "risk_score": analysis.get('phishing', {}).get('risk_score', 0),
                "risk_level": analysis.get('phishing', {}).get('risk_level', 'Low'),
            })
        
        # Update last fetch time
        conn.execute(
            "UPDATE imap_sessions SET last_fetch_at = ? WHERE session_id = ?",
            (datetime.now().isoformat(), session_id)
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "count": len(results),
            "emails": results
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/imap/emails")
def get_fetched_emails():
    """Get fetched emails for a session."""
    session_id = request.args.get("session_id", "").strip()
    limit = min(int(request.args.get("limit", 50)), 100)
    
    if not session_id:
        return jsonify({"error": "Session ID required"}), 400
    
    conn = get_db()
    rows = conn.execute(
        """SELECT * FROM fetched_emails 
           WHERE session_id = ? 
           ORDER BY date DESC 
           LIMIT ?""",
        (session_id, limit)
    ).fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in rows])


@app.route("/api/imap/sessions")
def list_sessions():
    """List active IMAP sessions (without sensitive data)."""
    conn = get_db()
    rows = conn.execute(
        """SELECT session_id, email_address, imap_server, created_at, last_fetch_at 
           FROM imap_sessions 
           ORDER BY created_at DESC"""
    ).fetchall()
    conn.close()
    
    sessions = []
    for row in rows:
        session_data = dict(row)
        # Check if session is still active in memory
        session_data['is_active'] = row['session_id'] in active_sessions
        sessions.append(session_data)
    
    return jsonify(sessions)


@app.route("/api/imap/session/<session_id>")
def get_session_info(session_id):
    """Get info about a specific session."""
    conn = get_db()
    row = conn.execute(
        """SELECT session_id, email_address, imap_server, created_at, last_fetch_at 
           FROM imap_sessions WHERE session_id = ?""",
        (session_id,)
    ).fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Session not found"}), 404
    
    session_data = dict(row)
    session_data['is_active'] = session_id in active_sessions
    
    return jsonify(session_data)


# ═══════════════════════════════════════════════════════════════════════════════
# OAuth2 Routes for Gmail
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/oauth/google/url")
def google_oauth_url():
    """Get Google OAuth2 authorization URL."""
    if not OAUTH_AVAILABLE:
        return jsonify({"error": "OAuth functionality is not available in this environment"}), 503
    # Check if OAuth is configured
    if not OAUTH_CONFIG['google']['client_id']:
        return jsonify({
            "error": "OAuth not configured",
            "message": "Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables"
        }), 503
    
    oauth_url = get_oauth_url('google')
    return jsonify({
        "auth_url": oauth_url,
        "provider": "google"
    })


@app.route("/oauth/callback")
def oauth_callback():
    """Handle OAuth2 callback from Google."""
    if not OAUTH_AVAILABLE:
        return jsonify({"error": "OAuth functionality is not available in this environment"}), 503
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return f"""
        <html>
        <body style="font-family: Inter, sans-serif; padding: 40px; text-align: center;">
            <h2 style="color: #ef4444;">Authentication Failed</h2>
            <p>{error}</p>
            <script>setTimeout(() => window.close(), 3000);</script>
        </body>
        </html>
        """, 400
    
    if not code:
        return jsonify({"error": "No authorization code received"}), 400
    
    # Exchange code for token
    token_data = exchange_code_for_token('google', code)
    
    if not token_data:
        return jsonify({"error": "Failed to exchange code for token"}), 400
    
    # Get user email from token info
    import requests
    userinfo = requests.get(
        'https://www.googleapis.com/oauth2/v2/userinfo',
        headers={'Authorization': f'Bearer {token_data["access_token"]}'}
    ).json()
    
    email_address = userinfo.get('email')
    
    if not email_address:
        return jsonify({"error": "Could not get email from OAuth"}), 400
    
    # Create IMAP session with OAuth2 token
    try:
        client = IMAPClient(
            email_address=email_address,
            use_oauth2=True,
            access_token=token_data['access_token'],
            imap_server='imap.gmail.com'
        )
        
        # Test connection
        if not client.test_connection():
            raise Exception("Failed to connect with OAuth2 token")
        
        # Store session
        active_sessions[client.session_id] = {
            'client': client,
            'email_address': email_address,
            'imap_server': 'imap.gmail.com',
            'created_at': datetime.now().isoformat(),
            'oauth_provider': 'google',
            'access_token': token_data['access_token'],
            'refresh_token': token_data.get('refresh_token'),
            'token_expires_at': token_data.get('expires_in', 3600)
        }
        
        # Save to database
        conn = get_db()
        conn.execute(
            """INSERT INTO imap_sessions (session_id, email_address, imap_server, created_at)
               VALUES (?, ?, ?, ?)""",
            (client.session_id, email_address, 'imap.gmail.com', datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        
        # Return success page that communicates with parent window
        return f"""
        <html>
        <body style="font-family: Inter, sans-serif; padding: 40px; text-align: center;">
            <h2 style="color: #06d6a0;">Connected Successfully!</h2>
            <p>Signed in as {email_address}</p>
            <script>
                if (window.opener) {{
                    window.opener.postMessage({{
                        type: 'OAUTH_SUCCESS',
                        session_id: '{client.session_id}',
                        email: '{email_address}'
                    }}, '*');
                }}
                setTimeout(() => window.close(), 2000);
            </script>
        </body>
        </html>
        """
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PDF Report Generation ───────────────────────────────────────────────────
# Import fpdf2 optionally - may not be available on all platforms
try:
    from fpdf import FPDF
    import io
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    FPDF = None

def sanitize_for_pdf(text):
    """Sanitize text for PDF output - replace Unicode chars with ASCII equivalents."""
    if not isinstance(text, str):
        text = str(text)
    
    # Replace common Unicode characters with ASCII equivalents
    replacements = {
        '\u2013': '-',   # en-dash
        '\u2014': '-',   # em-dash
        '\u2018': "'",   # left single quote
        '\u2019': "'",   # right single quote
        '\u201c': '"',   # left double quote
        '\u201d': '"',   # right double quote
        '\u2026': '...', # ellipsis
        '\u00a0': ' ',   # non-breaking space
        '\u00ad': '',    # soft hyphen
        '\u201a': ',',   # single low quote
        '\u201e': '"',   # double low quote
        '\u2022': '*',   # bullet
        '\u2023': '*',   # triangular bullet
        '\u2043': '-',   # hyphen bullet
        '\u2212': '-',   # minus sign
        '\u2264': '<=',  # less than or equal
        '\u2265': '>=',  # greater than or equal
        '\u2260': '!=',  # not equal
        '\u00d7': 'x',   # multiplication sign
        '\u00f7': '/',   # division sign
        '\u00e2': 'a',   # â
        '\u00e9': 'e',   # é
        '\u00ea': 'e',   # ê
        '\u00eb': 'e',   # ë
        '\u00e8': 'e',   # è
        '\u00ef': 'i',   # ï
        '\u00ee': 'i',   # î
        '\u00ec': 'i',   # ì
        '\u00c2': 'A',   # Â
        '\u00c9': 'E',   # É
        '\u00ca': 'E',   # Ê
        '\u00cb': 'E',   # Ë
        '\u00c8': 'E',   # È
        '\u00cf': 'I',   # Ï
        '\u00ce': 'I',   # Î
        '\u00cc': 'I',   # Ì
        '\u00f1': 'n',   # ñ
        '\u00d1': 'N',   # Ñ
        '\u00a9': '(C)', # copyright
        '\u00ae': '(R)', # registered
        '\u2122': '(TM)', # trademark
        '\u20ac': 'EUR', # euro
        '\u00a3': 'GBP', # pound
        '\u00a5': 'JPY', # yen
        '\u00b0': 'deg', # degree
        '\u00b1': '+/-', # plus-minus
        '\u00b5': 'u',   # micro
        '\u00b7': '*',   # middle dot
        '\u00bc': '1/4', # 1/4
        '\u00bd': '1/2', # 1/2
        '\u00be': '3/4', # 3/4
        '\u2190': '<-',  # left arrow
        '\u2192': '->',  # right arrow
        '\u2191': '^',   # up arrow
        '\u2193': 'v',   # down arrow
        '\u2713': 'OK',  # check mark
        '\u2714': 'OK',  # heavy check mark
        '\u2717': 'X',   # ballot X
        '\u2718': 'X',   # heavy ballot X
        '\u2605': '*',   # star
        '\u2606': '*',   # empty star
        '\u2660': 'S',   # spade
        '\u2663': 'C',   # club
        '\u2665': 'H',   # heart
        '\u2666': 'D',   # diamond
        '\u25cf': '*',   # black circle
        '\u25cb': 'o',   # white circle
        '\u25a0': '#',   # black square
        '\u25a1': '[]',  # white square
        '\u2011': '-',   # non-breaking hyphen
        '\u2010': '-',   # hyphen
        '\u2002': ' ',   # en space
        '\u2003': ' ',   # em space
        '\u2009': ' ',   # thin space
        '\u200a': ' ',   # hair space
        '\u200b': '',    # zero-width space
        '\ufeff': '',    # BOM
        '\u200e': '',    # LTR mark
        '\u200f': '',    # RTL mark
    }
    
    for unicode_char, replacement in replacements.items():
        text = text.replace(unicode_char, replacement)
    
    # Remove any remaining non-ASCII characters
    return text.encode('ascii', 'ignore').decode('ascii')

class PDFReport(FPDF):
    def header(self):
        # Logo/Title area with gradient-like effect
        self.set_fill_color(30, 41, 59)  # #1e293b
        self.rect(0, 0, 210, 40, 'F')
        
        # Accent line
        self.set_fill_color(6, 214, 160)  # #06d6a0
        self.rect(0, 40, 210, 2, 'F')
        
        self.set_xy(10, 10)
        self.set_font('Arial', 'B', 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, 'MailGuard Security', ln=True)
        
        self.set_xy(10, 22)
        self.set_font('Arial', '', 10)
        self.set_text_color(148, 163, 184)  # #94a3b8
        self.cell(0, 6, 'Advanced Threat Intelligence Report', ln=True)
        
        # Shield icon representation
        self.set_xy(175, 8)
        self.set_font('Arial', 'B', 24)
        self.set_text_color(6, 214, 160)
        self.cell(25, 10, sanitize_for_pdf('\u2713'), align='C')  # Checkmark
        
    def footer(self):
        self.set_y(-20)
        # Footer line
        self.set_draw_color(226, 232, 240)
        self.set_line_width(0.5)
        self.line(10, -20, 200, -20)
        
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()} | MailGuard Security Platform | Generated on {datetime.now().strftime("%Y-%m-%d %H:%M")}', 0, 0, 'C')

@app.route("/api/generate-pdf", methods=["POST"])
@login_required
def generate_pdf():
    """Generate a professional PDF report server-side."""
    if not FPDF_AVAILABLE:
        return jsonify({"error": "PDF generation not available in this environment"}), 503
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        result = data.get('result')
        email_text = data.get('email_text', '')
        
        if not result:
            return jsonify({"error": "No analysis result provided"}), 400
        
        # Sanitize inputs for PDF
        is_spam = result.get('prediction') == 'spam'
        confidence = result.get('confidence', 0)
        spam_prob = result.get('spam_probability', 0)
        ham_prob = result.get('ham_probability', 0)
        model_name = sanitize_for_pdf(result.get('model_name', 'Ensemble'))
        
        # Colors
        accent = (239, 68, 68) if is_spam else (16, 185, 129)  # Red or Green
        accent_bg = (254, 242, 242) if is_spam else (240, 253, 244)
        verdict = "SPAM DETECTED" if is_spam else "SAFE EMAIL"
        
        pdf = PDFReport()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=25)
        
        # Report ID and Date
        now = datetime.now()
        date_str = now.strftime('%B %d, %Y')
        time_str = now.strftime('%H:%M:%S')
        report_id = f"MG-{now.strftime('%Y%m%d')}-{now.strftime('%H%M')}-{str(uuid.uuid4())[:4].upper()}"
        
        pdf.set_xy(130, 12)
        pdf.set_font('Arial', '', 8)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(0, 5, f'Report ID: {sanitize_for_pdf(report_id)}', ln=True)
        pdf.set_x(130)
        pdf.cell(0, 5, f'{sanitize_for_pdf(date_str)} {time_str}', ln=True)
        
        # Verdict Box with shadow effect
        pdf.set_fill_color(245, 245, 245)  # Shadow
        pdf.rect(12, 52, 190, 42, 'F')
        pdf.set_fill_color(*accent_bg)
        pdf.set_draw_color(*accent)
        pdf.set_line_width(1)
        pdf.rect(10, 50, 190, 42, 'DF')
        
        # Verdict icon
        pdf.set_xy(15, 55)
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(*accent)
        icon_text = 'X' if is_spam else sanitize_for_pdf('\u2713')
        pdf.cell(15, 10, icon_text, align='C')
        
        pdf.set_xy(32, 55)
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, 'ANALYSIS VERDICT', ln=True)
        
        pdf.set_xy(32, 63)
        pdf.set_font('Arial', 'B', 22)
        pdf.set_text_color(*accent)
        pdf.cell(0, 10, verdict, ln=True)
        
        pdf.set_xy(32, 77)
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(100, 116, 139)
        classification = "potentially malicious" if is_spam else "legitimate"
        pdf.cell(0, 6, f'AI identified this as {classification} with {confidence}% confidence.', ln=True)
        
        # Confidence Circle with gauge effect
        pdf.set_xy(165, 55)
        pdf.set_fill_color(255, 255, 255)
        pdf.set_draw_color(*accent)
        pdf.set_line_width(2)
        pdf.ellipse(165, 55, 28, 28, 'DF')
        pdf.set_xy(165, 64)
        pdf.set_font('Arial', 'B', 16)
        pdf.set_text_color(*accent)
        pdf.cell(28, 8, f'{int(spam_prob if is_spam else ham_prob)}%', align='C')
        pdf.set_xy(165, 82)
        pdf.set_font('Arial', 'B', 7)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(28, 5, 'CONFIDENCE', align='C')
        
        y_pos = 105
        
        # Two-column layout for Security Indicators and Model Info
        # Left column - Security Indicators
        pdf.set_xy(10, y_pos)
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, 'Security Indicators', ln=True)
        pdf.set_draw_color(226, 232, 240)
        pdf.set_line_width(0.5)
        pdf.line(10, y_pos + 8, 95, y_pos + 8)
        
        y_pos += 15
        phishing = result.get('phishing', {})
        threats = phishing.get('threats', [])
        
        if threats:
            for threat in threats[:3]:  # Max 3 threats
                severity = threat.get('severity', 'low')
                if severity == 'high':
                    pdf.set_draw_color(239, 68, 68)
                    severity_color = (239, 68, 68)
                elif severity == 'medium':
                    pdf.set_draw_color(245, 158, 11)
                    severity_color = (245, 158, 11)
                else:
                    pdf.set_draw_color(16, 185, 129)
                    severity_color = (16, 185, 129)
                
                pdf.set_xy(12, y_pos)
                pdf.set_line_width(3)
                pdf.line(10, y_pos, 10, y_pos + 14)
                
                pdf.set_xy(15, y_pos)
                pdf.set_font('Arial', 'B', 9)
                pdf.set_text_color(30, 41, 59)
                threat_type = sanitize_for_pdf(threat.get('type', 'Unknown Threat'))
                pdf.cell(0, 5, threat_type, ln=True)
                
                pdf.set_x(15)
                pdf.set_font('Arial', '', 8)
                pdf.set_text_color(100, 116, 139)
                details = sanitize_for_pdf(threat.get('details', ''))
                pdf.cell(0, 4, details, ln=True)
                
                pdf.set_x(15)
                pdf.set_font('Arial', 'B', 7)
                pdf.set_text_color(*severity_color)
                pdf.cell(0, 4, f'Severity: {severity.upper()}', ln=True)
                y_pos += 20
        else:
            pdf.set_xy(12, y_pos)
            pdf.set_font('Arial', 'I', 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 6, 'No active phishing threats detected.', ln=True)
            y_pos += 12
        
        # Right column - Model Performance
        pdf.set_xy(105, 105)
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, 'Model Performance', ln=True)
        pdf.line(105, 113, 200, 113)
        
        model_y = 120
        
        # Spam/Ham probabilities
        pdf.set_xy(107, model_y)
        pdf.set_font('Arial', '', 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(40, 5, 'Spam Probability:', ln=False)
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(239, 68, 68)
        pdf.cell(0, 5, f'{spam_prob}%', ln=True)
        
        # Progress bar for spam
        pdf.set_fill_color(226, 232, 240)
        pdf.rect(107, model_y + 7, 85, 5, 'F')
        pdf.set_fill_color(239, 68, 68)
        pdf.rect(107, model_y + 7, 85 * (spam_prob / 100), 5, 'F')
        
        model_y += 18
        pdf.set_xy(107, model_y)
        pdf.set_font('Arial', '', 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(40, 5, 'Ham Probability:', ln=False)
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(16, 185, 129)
        pdf.cell(0, 5, f'{ham_prob}%', ln=True)
        
        # Progress bar for ham
        pdf.set_fill_color(226, 232, 240)
        pdf.rect(107, model_y + 7, 85, 5, 'F')
        pdf.set_fill_color(16, 185, 129)
        pdf.rect(107, model_y + 7, 85 * (ham_prob / 100), 5, 'F')
        
        model_y += 18
        pdf.set_xy(107, model_y)
        pdf.set_font('Arial', '', 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(40, 5, 'Model Used:', ln=False)
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 5, model_name, ln=True)
        
        model_y += 10
        pdf.set_xy(107, model_y)
        pdf.set_font('Arial', '', 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(40, 5, 'Risk Score:', ln=False)
        risk_score = phishing.get('risk_score', 0)
        pdf.set_font('Arial', 'B', 9)
        if risk_score >= 70:
            pdf.set_text_color(239, 68, 68)
        elif risk_score >= 35:
            pdf.set_text_color(245, 158, 11)
        else:
            pdf.set_text_color(16, 185, 129)
        pdf.cell(0, 5, f'{risk_score}/100 ({phishing.get("risk_level", "Low")})', ln=True)
        
        # Continue with the lower content
        y_pos = max(y_pos, 175)
        
        # URL Scan Section
        url_scan = result.get('url_scan', [])
        if url_scan:
            if y_pos > 230:
                pdf.add_page()
                y_pos = 50
            
            pdf.set_xy(10, y_pos)
            pdf.set_font('Arial', 'B', 12)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(0, 8, 'Embedded URL Security Scan', ln=True)
            pdf.line(10, y_pos + 8, 200, y_pos + 8)
            y_pos += 15
            
            for url_data in url_scan[:4]:  # Max 4 URLs
                url = sanitize_for_pdf(url_data.get('url', '')[:60])
                status = url_data.get('status', 'Unknown')
                is_https = url_data.get('is_https', False)
                flags = url_data.get('flags', [])
                
                # Status color
                if status == 'High Risk':
                    status_color = (239, 68, 68)
                elif status == 'Suspicious':
                    status_color = (245, 158, 11)
                else:
                    status_color = (16, 185, 129)
                
                pdf.set_xy(12, y_pos)
                pdf.set_font('Arial', 'B', 8)
                pdf.set_text_color(30, 41, 59)
                pdf.cell(0, 5, url, ln=True)
                
                pdf.set_x(12)
                pdf.set_font('Arial', '', 7)
                pdf.set_text_color(100, 116, 139)
                security = "Secure (HTTPS)" if is_https else "Unsecure (HTTP)"
                pdf.cell(60, 4, security, ln=False)
                
                pdf.set_font('Arial', 'B', 7)
                pdf.set_text_color(*status_color)
                pdf.cell(0, 4, f'Status: {status}', ln=True)
                
                if flags:
                    pdf.set_x(12)
                    pdf.set_font('Arial', 'I', 6)
                    pdf.set_text_color(150, 150, 150)
                    flags_text = ', '.join(flags[:2])
                    pdf.cell(0, 3, sanitize_for_pdf(f'Flags: {flags_text}'), ln=True)
                
                y_pos += 12
        
        # XAI Section
        if y_pos > 220:
            pdf.add_page()
            y_pos = 50
        
        pdf.set_xy(10, y_pos)
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, 'AI Explanation - Key Contributing Terms', ln=True)
        pdf.line(10, y_pos + 8, 200, y_pos + 8)
        y_pos += 15
        
        keyword_contributions = result.get('keyword_contributions', [])
        if keyword_contributions:
            max_contrib = max(abs(k.get('contribution', 0)) for k in keyword_contributions)
            for kw in keyword_contributions[:8]:  # Max 8 keywords
                word = sanitize_for_pdf(kw.get('word', ''))
                contrib = kw.get('contribution', 0)
                pct = (abs(contrib) / max_contrib) * 100 if max_contrib > 0 else 0
                
                pdf.set_xy(12, y_pos)
                pdf.set_font('Arial', 'B', 9)
                pdf.set_text_color(30, 41, 59)
                pdf.cell(50, 6, word, ln=False)
                
                # Bar background
                pdf.set_fill_color(226, 232, 240)
                pdf.rect(62, y_pos + 1, 80, 5, 'F')
                
                # Bar fill with gradient effect
                bar_color = (239, 68, 68) if contrib > 0 else (16, 185, 129)
                pdf.set_fill_color(*bar_color)
                bar_width = 80 * (pct / 100)
                if bar_width < 1:
                    bar_width = 1
                pdf.rect(62, y_pos + 1, bar_width, 5, 'F')
                
                pdf.set_xy(145, y_pos)
                pdf.set_font('Arial', 'B', 8)
                pdf.set_text_color(*bar_color)
                pdf.cell(20, 6, f'{contrib:+.4f}', ln=True)
                y_pos += 10
        else:
            pdf.set_xy(12, y_pos)
            pdf.set_font('Arial', 'I', 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 6, 'No significant keyword contributions detected.', ln=True)
            y_pos += 12
        
        # Metadata Section
        if y_pos > 230:
            pdf.add_page()
            y_pos = 50
        
        pdf.set_xy(10, y_pos)
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, 'Analysis Metadata', ln=True)
        pdf.line(10, y_pos + 8, 200, y_pos + 8)
        y_pos += 15
        
        intelligence = result.get('intelligence', {})
        
        # Two-column metadata layout
        meta_items_left = [
            ('Model Used', model_name),
            ('Email Length', f"{intelligence.get('word_count', 0)} words"),
            ('Character Count', f"{intelligence.get('char_count', 0)} chars"),
        ]
        meta_items_right = [
            ('Sentiment', sanitize_for_pdf(intelligence.get('sentiment', 'Neutral'))),
            ('Language', sanitize_for_pdf(intelligence.get('language', 'English'))),
            ('Links Found', str(intelligence.get('link_count', 0))),
        ]
        
        # Left column
        left_y = y_pos
        for label, value in meta_items_left:
            pdf.set_xy(12, left_y)
            pdf.set_font('Arial', '', 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(45, 5, label + ':', ln=False)
            pdf.set_font('Arial', 'B', 9)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(0, 5, sanitize_for_pdf(str(value)), ln=True)
            left_y += 8
        
        # Right column
        right_y = y_pos
        for label, value in meta_items_right:
            pdf.set_xy(110, right_y)
            pdf.set_font('Arial', '', 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(45, 5, label + ':', ln=False)
            pdf.set_font('Arial', 'B', 9)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(0, 5, sanitize_for_pdf(str(value)), ln=True)
            right_y += 8
        
        y_pos = max(left_y, right_y) + 10
        
        # Email Content Section
        if y_pos > 200:
            pdf.add_page()
            y_pos = 50
        
        pdf.set_xy(10, y_pos)
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, 'Analyzed Email Content', ln=True)
        pdf.line(10, y_pos + 8, 200, y_pos + 8)
        
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(226, 232, 240)
        pdf.rect(10, y_pos + 12, 190, 60, 'DF')
        
        pdf.set_xy(15, y_pos + 16)
        pdf.set_font('Courier', '', 8)
        pdf.set_text_color(30, 41, 59)
        
        # Sanitize and truncate content
        content = sanitize_for_pdf(email_text)
        if len(content) > 800:
            content = content[:800] + '... [truncated]'
        
        # Wrap text manually
        lines = []
        current_line = ""
        for word in content.split():
            word = sanitize_for_pdf(word)
            if len(current_line) + len(word) + 1 <= 90:
                current_line += word + " "
            else:
                lines.append(current_line)
                current_line = word + " "
        if current_line:
            lines.append(current_line)
        
        line_y = y_pos + 16
        for i, line in enumerate(lines[:25]):  # Max 25 lines
            if line_y > y_pos + 68:
                pdf.set_xy(15, line_y)
                pdf.set_font('Courier', 'I', 8)
                pdf.set_text_color(150, 150, 150)
                pdf.cell(0, 4, '... [content continues]', ln=True)
                break
            pdf.set_xy(15, line_y)
            pdf.set_font('Courier', '', 8)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(0, 4, sanitize_for_pdf(line), ln=True)
            line_y += 4
        
        # Disclaimer footer on new page if needed
        if pdf.page_no() == 1:
            pdf.set_y(-30)
        else:
            pdf.set_y(-25)
        
        pdf.set_font('Arial', 'I', 8)
        pdf.set_text_color(150, 150, 150)
        pdf.multi_cell(0, 4, sanitize_for_pdf('DISCLAIMER: This document is for informational purposes only. Security analysis was performed using trained machine learning models. MailGuard does not guarantee 100% accuracy and recommends manual verification for high-risk flags. This report was generated by MailGuard AI Security Platform.'))
        
        # Output PDF
        pdf_output = pdf.output(dest='S')
        if isinstance(pdf_output, str):
            pdf_bytes = pdf_output.encode('latin-1', errors='ignore')
        else:
            pdf_bytes = pdf_output
        
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'MailGuard_Report_{report_id}.pdf'
        )
        
    except Exception as e:
        import traceback
        print(f"[PDF Generation Error] {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n>>> Email Security Platform running at http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
