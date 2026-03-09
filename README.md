# Email Spam Guard (SpamGuard AI)

SpamGuard AI is a comprehensive AI-powered Email Security & Phishing Detection Platform. It transforms standard spam classification into a full-fledged security dashboard capable of analyzing emails for spam probabilities, detecting phishing indicators, scanning URLs for security risks, and providing explainable AI (XAI) insights.

## Features

- **Multi-Model Classification:** Choose between Naive Bayes, Logistic Regression, and Random Forest models to analyze incoming emails.
- **Explainable AI (XAI):** See exactly *why* an email was classified as spam with a breakdown of keyword contributions and highlighted suspicious content.
- **Phishing Risk Detection:** Advanced heuristics identify urgency phrases, personal info requests, and spoofing indicators to calculate a Phishing Risk Score.
- **URL Security Scan:** Extracts and scans embedded URLs for HTTPS usage, URL shorteners, suspicious top-level domains (TLDs), and IP-based URLs.
- **Email Intelligence:** Analyzes language, sentiment, word metrics, and suspicious keyword counts.
- **Batch Processing:** Upload a CSV file or paste multiple emails to classify them all at once.
- **Real-time Analytics Dashboard:** Visualize historical data, spam vs. ham distribution, and risk levels using interactive Chart.js graphs.
- **Analysis History:** SQLite-backed history tracking with search and filtering capabilities.
- **PDF Export:** Download nicely formatted PDF reports of individual email analysis results.
- **Modern UI:** Responsive, SaaS-like interface built with React (CDN), Tailwind CSS concepts, and a sleek dark mode.

## Architecture

- **Backend:** Python / Flask
- **Machine Learning:** Scikit-learn (TF-IDF Vectorizer + Classification models)
- **Frontend:** HTML, CSS, React (via CDN), Babel, Chart.js, Lucide Icons
- **Database:** SQLite

## Project Structure

```
├── app.py                 # Main Flask application and API endpoints
├── train_model.py         # Script to train models and generate vectorizer
├── requirements.txt       # Python dependencies
├── model/                 # Serialized ML models and vectorizer (.pkl)
├── data/                  # SQLite database (history.db)
├── static/
│   ├── style.css          # Core styles and custom CSS variables
│   └── script.js          # Main vanilla JS logic connecting to React concepts
├── templates/
│   └── index.html         # Main dashboard layout
└── frontend/
    └── app.jsx            # React frontend components and UI state
```

## Installation and Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yug09-hub/EMAIL-SPAM-GUARD.git
   cd EMAIL-SPAM-GUARD
   ```

2. **Install dependencies:**
   Make sure you have Python installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the models (Optional if models are already provided):**
   ```bash
   python train_model.py
   ```

4. **Run the Flask Backend:**
   ```bash
   python app.py
   ```
   The server will start on `http://127.0.0.1:5000/`.

## API Endpoints

- `POST /api/predict`: Classify a single email text.
- `POST /api/batch_predict`: Classify a batch of emails (JSON or CSV).
- `GET /api/history`: Retrieve analysis history.
- `GET /api/stats`: Retrieve model metrics and overall statistics.
- `GET /api/analytics`: Retrieve data formatted for dashboard charts.

## License

MIT License
