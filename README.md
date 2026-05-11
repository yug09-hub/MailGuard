# MailGuard AI — Email Security Platform

An AI-powered email security and phishing detection platform with multi-model spam classification, explainable AI, URL scanning, and a real-time analytics dashboard.

## Live Demo

Deployed on Render — [https://mailguard-ai.onrender.com](https://mailguard-ai.onrender.com) *(update this link after deployment)*

---

## Features

- **Multi-Model Classification** — Naive Bayes, Logistic Regression, and Random Forest
- **Ensemble Mode** — Majority voting across all three models
- **Explainable AI (XAI)** — Keyword contribution breakdown showing *why* an email was flagged
- **Phishing Risk Detection** — Urgency phrases, personal info requests, spoofing indicators
- **URL Security Scanner** — HTTPS check, shortener detection, suspicious TLDs, IP-based URLs
- **Email Intelligence** — Language detection, sentiment analysis, word metrics
- **Batch Processing** — Upload CSV or paste multiple emails at once
- **Analytics Dashboard** — Interactive Chart.js graphs for history and risk distribution
- **PDF Export** — Download formatted analysis reports
- **User Authentication** — Login/signup with role-based access (admin/user)
- **IMAP Integration** — Connect your email account to fetch and scan real emails
- **SQLite History** — Persistent analysis history with search and filtering

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, Flask 3.1 |
| ML | Scikit-learn (TF-IDF + NB/LR/RF) |
| Frontend | HTML, Tailwind CSS, React (CDN), Chart.js |
| Database | SQLite |
| Auth | Flask-Login, Flask-Bcrypt |
| Server | Gunicorn |
| Hosting | Render |

---

## Project Structure

```
├── app.py               # Flask app — routes, ML inference, phishing logic
├── main.py              # Gunicorn entry point
├── train_model.py       # Model training script
├── imap_client.py       # IMAP email fetching
├── oauth_config.py      # OAuth2 configuration
├── replace_emojis.py    # Emoji sanitization utility
├── requirements.txt     # Python dependencies
├── render.yaml          # Render deployment config
├── vercel.json          # Vercel deployment config (legacy)
├── emails.csv           # Sample training data
├── model/
│   ├── nb_model.pkl     # Naive Bayes model
│   ├── lr_model.pkl     # Logistic Regression model
│   ├── rf_model.pkl     # Random Forest model
│   ├── vectorizer.pkl   # TF-IDF vectorizer
│   └── stats.json       # Model accuracy stats
├── data/
│   └── history.db       # SQLite database
├── static/
│   ├── style.css
│   └── script.js
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   └── admin.html
└── frontend/
    ├── app.jsx
    └── index.html
```

---

## Local Setup

1. **Clone the repo**
   ```bash
   git clone https://github.com/yug09-hub/MailGuard.git
   cd MailGuard
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train models** *(skip if `.pkl` files already exist)*
   ```bash
   python train_model.py
   ```

4. **Run the app**
   ```bash
   python app.py
   ```
   Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

5. **Default admin credentials**
   - Username: `admin`
   - Password: `admin123`
   *(Change this immediately in production)*

---

## Deploying to Render

### One-click via render.yaml

This repo includes a `render.yaml` blueprint. Render will auto-detect it.

1. Go to [https://render.com](https://render.com) and log in
2. Click **New → Blueprint**
3. Connect your GitHub account and select the `MailGuard` repo
4. Render reads `render.yaml` automatically — click **Apply**
5. Set the `SECRET_KEY` environment variable (or let Render generate one)
6. Wait for the build to finish (~3–5 minutes)
7. Your app will be live at `https://mailguard-ai.onrender.com`

### Manual setup (Web Service)

1. Go to [https://render.com](https://render.com) → **New → Web Service**
2. Connect the `yug09-hub/MailGuard` GitHub repo
3. Fill in:
   | Field | Value |
   |-------|-------|
   | Runtime | Python 3 |
   | Build Command | `pip install -r requirements.txt` |
   | Start Command | `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120` |
4. Add environment variables:
   | Key | Value |
   |-----|-------|
   | `SECRET_KEY` | *(any long random string)* |
   | `RENDER` | `1` |
5. Add a **Disk** (for SQLite persistence):
   - Name: `mailguard-data`
   - Mount Path: `/data`
   - Size: 1 GB
6. Click **Create Web Service**

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask session secret key |
| `RENDER` | Auto-set | Tells app it's running on Render |
| `VERCEL` | Auto-set | Tells app it's running on Vercel |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/predict` | Classify a single email |
| `POST` | `/api/batch_predict` | Classify multiple emails (JSON or CSV) |
| `GET` | `/api/history` | Fetch analysis history |
| `GET` | `/api/stats` | Model accuracy and stats |
| `GET` | `/api/analytics` | Chart data for dashboard |
| `POST` | `/api/imap/connect` | Connect an IMAP email account |
| `POST` | `/api/imap/fetch` | Fetch and classify emails via IMAP |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
