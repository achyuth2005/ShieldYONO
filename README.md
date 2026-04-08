# 🛡️ ShieldYONO — URL Phishing Classifier

Real-time phishing URL detection system designed for SBI YONO-like attacks. Analyzes URLs for phishing indicators, brand impersonation, and structural anomalies using **ML (XGBoost) + rule-based scoring**.

![Shield](https://img.shields.io/badge/status-hackathon--ready-brightgreen) ![Python](https://img.shields.io/badge/python-3.10+-blue) ![React](https://img.shields.io/badge/frontend-React-61dafb) ![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [API Usage](#api-usage)
- [ML Model](#ml-model)
- [Demo Flow](#demo-flow)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)

---

## 🎯 Overview

ShieldYONO is a hackathon-ready phishing URL detection system that:

1. **Accepts a URL** from user input, browser extension, or bot
2. **Preprocesses** it (decode, unshorten, follow redirects)
3. **Extracts 34+ features** across URL structure, domain intelligence, and brand impersonation
4. **Runs an ML model** (XGBoost primary, Logistic Regression fallback)
5. **Applies rule-based boosters/reducers** for clear-cut signals
6. **Returns a risk score (0–100)** with tier (SAFE/SUSPICIOUS/PHISHING), verdict, and top reasons

### Why ShieldYONO?

- 🎯 **Focused on SBI/YONO attacks** — detects brand impersonation, typosquatting, homoglyphs
- 🧠 **Explainable AI** — every verdict comes with human-readable (English + Hindi) reasons
- ⚡ **Fast** — works even when WHOIS/DNS/SSL lookups fail (graceful fallbacks)
- 🏗️ **Hackathon-ready** — clean code, working demo, clear presentation flow

---

## 🏛️ Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐
│   Frontend   │───▶│  FastAPI     │───▶│  URL Preprocessor   │
│  React+TW    │    │  Backend    │    │  (decode, resolve)  │
└─────────────┘    └──────┬──────┘    └──────────┬──────────┘
                          │                       │
                   ┌──────▼──────┐         ┌──────▼──────────┐
                   │  Redis      │         │ Feature Extractor│
                   │  Cache      │         │ (34+ features)   │
                   └─────────────┘         └──────┬──────────┘
                                                  │
                   ┌─────────────┐         ┌──────▼──────────┐
                   │  SQLite     │◀────────│  ML Predictor    │
                   │  Scan Logs  │         │  (XGBoost/LR)    │
                   └─────────────┘         └──────┬──────────┘
                                                  │
                                           ┌──────▼──────────┐
                                           │  Risk Scorer     │
                                           │  (rules+score)   │
                                           └─────────────────┘
```

---

## ✨ Features

### Feature Extraction (34+ features)

| Group | Features |
|-------|----------|
| **URL Structure** | length, entropy, special chars, hyphens, subdomains, HTTPS, path depth, IP address, port, query params |
| **Domain Intelligence** | domain age (WHOIS), SSL cert age/issuer, TLD risk, DNS anomalies, MX records |
| **Brand Impersonation** | SBI/YONO keyword detection, typosquatting distance, homoglyph detection, IDN analysis, brand-in-subdomain |

### Risk Scoring Rules

| Signal | Boost |
|--------|-------|
| IP address in URL | +20 |
| Brand keyword in non-official domain | +25 |
| Typosquatting (distance ≤ 3) | +20 |
| Homoglyph characters | +20 |
| Brand in subdomain | +20 |
| Very new domain (< 30 days) | +15 |
| IDN domain | +12 |
| High-risk TLD | +10 |
| No HTTPS | +8 |
| Official SBI domain | **-100 (always safe)** |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- Redis (optional — falls back gracefully)

### 1. Clone & Setup

```bash
cd SBI_Hackathon

# Create Python virtual environment
python -m venv venv
source venv/bin/activate   # macOS/Linux
# venv\Scripts\activate    # Windows

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Train the ML Model

```bash
# Run the full pipeline (generate data → extract features → train)
python scripts/run_pipeline.py
```

This will:
- Generate ~5000 synthetic URLs (balanced phishing/legitimate)
- Extract 34 features per URL
- Train XGBoost + Logistic Regression models
- Save models to `ml/models/`

### 3. Start the Backend

```bash
# From project root
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at: http://localhost:8000/docs

### 4. Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

---

## 📡 API Usage

### Scan a URL

```bash
GET /api/check-url?url=https://sbi-login-verify.xyz/update

# Response:
{
  "url": "https://sbi-login-verify.xyz/update",
  "resolved_url": "https://sbi-login-verify.xyz/update",
  "risk_score": 85.0,
  "risk_tier": "PHISHING",
  "confidence": 0.91,
  "verdict": "⚠️ WARNING: This URL is likely a phishing attempt...",
  "verdict_hi": "⚠️ चेतावनी: यह URL संभवतः एक फ़िशिंग प्रयास है...",
  "reasons": [
    {"code": "BRAND_KEYWORD_SUSPICIOUS", "severity": "HIGH", ...},
    {"code": "HIGH_RISK_TLD", "severity": "MEDIUM", ...}
  ],
  "action": {"block": true, "warn": true, ...},
  "scan_id": "a1b2c3d4e5f6",
  "cached": false,
  "model_used": "xgboost"
}
```

### Other Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/analytics` | Scan statistics summary |
| `GET /api/recent-scans` | Recent scan history |
| `GET /api/sample-urls` | Demo sample URLs |
| `GET /api/feature-importance` | ML feature importances |
| `GET /api/health` | Health check |

---

## 🧠 ML Model

### Training Pipeline

1. **Data Generation** — Synthetic URLs with SBI brand impersonation patterns
2. **Feature Extraction** — 34 numeric features extracted (fast mode, no network calls)
3. **Train/Val/Test Split** — 60/20/20 stratified split
4. **XGBoost** — Primary classifier with class imbalance weighting
5. **Logistic Regression** — Fallback + explainability baseline
6. **Heuristic** — Rule-based fallback when no models are available

### Priority: Recall > Precision

The model is tuned to **minimize false negatives** (missing phishing URLs) even at the cost of some false positives. In phishing detection, it's safer to flag a legitimate URL than to miss a phishing one.

---

## 🎬 Demo Flow

1. Open the frontend at http://localhost:5173
2. Click "Try sample URLs" to see pre-loaded examples
3. Select a **phishing URL** → observe high risk score, red card, detailed reasons
4. Select a **safe URL** (e.g., sbi.co.in) → observe score of 0, green card, "Official domain"
5. Switch to **Hindi** using the language toggle
6. Check the **Analytics** panel for scan history
7. Show the API docs at http://localhost:8000/docs

---

## 📁 Project Structure

```
SBI_Hackathon/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes.py          # API endpoints
│   │   ├── core/
│   │   │   ├── config.py          # Configuration
│   │   │   ├── database.py        # SQLite scan logs
│   │   │   └── cache.py           # Redis caching
│   │   ├── models/
│   │   │   └── schemas.py         # Pydantic models
│   │   ├── services/
│   │   │   ├── url_preprocessor.py    # URL decode/resolve
│   │   │   ├── feature_extractor.py   # 34+ feature extraction
│   │   │   ├── ml_predictor.py        # Model loading/inference
│   │   │   └── risk_scorer.py         # Score + rules + reasons
│   │   └── main.py                # FastAPI app
│   └── tests/
│       └── test_core.py           # Unit tests
├── frontend/
│   ├── src/
│   │   ├── App.jsx                # Main dashboard
│   │   ├── api.js                 # API client
│   │   ├── index.css              # Tailwind + custom styles
│   │   └── main.jsx               # React entry
│   └── index.html
├── ml/
│   ├── models/                    # Trained model artifacts
│   └── evaluation/                # Training reports
├── data/
│   ├── raw/                       # Generated datasets
│   └── processed/                 # Feature-extracted datasets
├── scripts/
│   ├── generate_data.py           # Synthetic data generation
│   ├── extract_features.py        # Batch feature extraction
│   ├── train_model.py             # Model training pipeline
│   └── run_pipeline.py            # Full pipeline runner
├── docs/
│   └── architecture.md
├── requirements.txt
├── .env.example
└── README.md
```

---

## ⚠️ Limitations

- **Synthetic training data** — Model trained on generated URLs, not real-world phishing corpus
- **WHOIS/DNS lookups** — May be slow or fail for some domains; graceful fallbacks used
- **No real-time threat feed** — Does not integrate with VirusTotal, Google Safe Browsing, etc.
- **Single-model approach** — No ensemble or deep learning models
- **Browser extension** — Not included (API-ready for integration)

---

## 🔮 Future Improvements

1. **Real phishing datasets** — Integrate PhishTank, OpenPhish, or VirusTotal feeds
2. **Deep learning** — URL character-level CNN/LSTM for pattern detection
3. **Browser extension** — Chrome/Firefox extension for real-time warnings
4. **Visual similarity** — Screenshot-based comparison with official SBI pages
5. **Threat intelligence** — Real-time blocklist/allowlist integration
6. **Multi-language** — Expand beyond English/Hindi
7. **API rate limiting** — Production-grade throttling
8. **Docker deployment** — Containerized deployment with docker-compose
9. **YONO integration** — Embed as a microservice within the YONO app stack

---

## 🛡️ Security Considerations

- **SSRF Protection** — Private/reserved IPs are blocked
- **Redirect Limits** — Max 5 hops to prevent infinite loops
- **Timeout Handling** — All network calls have configurable timeouts
- **Input Validation** — URL scheme and length validation
- **No credential storage** — System only analyzes URLs, never visits them as a user

---

## 📄 License

Built for SBI Hackathon 2026. For demonstration purposes only.
