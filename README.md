# AI/ML Phishing Domain Detector

**Smart India Hackathon (SIH) 1454 - NTRO**

An advanced cybersecurity platform that automatically detects phishing domains and website impersonation through AI/ML-powered analysis combining domain intelligence, content similarity, DOM structure analysis, and visual similarity detection.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Quick Start](#quick-start)
- [API Documentation](#api-documentation)
- [Dashboard Guide](#dashboard-guide)
- [Model Training](#model-training)
- [SIH1454 Alignment](#sih1454-alignment)

## 🎯 Overview

This platform addresses **SIH Problem Statement 1454** by providing:

1. **Domain Intelligence Engine** - Analyze domain characteristics and detect typosquatting
2. **Content Analysis** - Extract HTML, DOM structure, and text fingerprints
3. **Visual Similarity Detection** - Compare screenshots using perceptual hashing and embeddings
4. **ML Classification** - Fuse features into explainable risk scores
5. **REST API** - Programmatic access for batch analysis and integration
6. **Professional Dashboard** - Real-time investigation interface

## ✨ Features

- ✅ Real-time phishing domain detection
- ✅ Side-by-side visual comparison (legitimate vs candidate)
- ✅ Explainable AI with feature contribution scores
- ✅ Batch analysis (100s of domains)
- ✅ JSON/CSV export
- ✅ REST API with comprehensive documentation
- ✅ Watchlist management for legitimate domains
- ✅ Processing time analytics
- ✅ Demo mode with synthetic test data
- ✅ Secure sandboxed webpage analysis
- ✅ Offline demo datasets

## 🏗️ Architecture

```
┌─────────────────────────────┐
│ Domain Input / Feed         │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│ Domain Intelligence Engine  │
│ (Typosquat, Keywords, etc)  │
└──────────────┬──────────────┘
               ▼
    ┌──────────┴──────────┐
    ▼                     ▼
┌──────────────┐    ┌──────────────┐
│ Content      │    │ Visual       │
│ Analyzer     │    │ Analyzer     │
│              │    │              │
│ HTML/DOM     │    │ Screenshots  │
│ Text/Forms   │    │ pHash/CNN    │
└──────┬───────┘    └──────┬───────┘
       │                   │
       └──────────┬────────┘
                  ▼
    ┌─────────────────────────┐
    │ Feature Extraction      │
    │ (7 dimensions)          │
    └──────────┬──────────────┘
               ▼
    ┌─────────────────────────┐
    │ ML Classifier           │
    │ (Logistic Regression)   │
    └──────────┬──────────────┘
               ▼
    ┌─────────────────────────┐
    │ Risk Engine             │
    │ + Explainability        │
    └──────────┬──────────────┘
               ▼
    ┌──────────┴──────────┐
    ▼                     ▼
┌──────────────┐    ┌──────────────┐
│ Dashboard    ���    │ REST API     │
│              │    │              │
│ Real-time    │    │ JSON/Batch   │
│ Analysis     │    │ Export       │
└──────────────┘    └──────────────┘
```

## 🛠️ Technology Stack

### Backend
- **Framework:** FastAPI
- **Database:** PostgreSQL + SQLAlchemy
- **Cache:** Redis
- **Web Analysis:** Playwright, BeautifulSoup, requests
- **ML:** scikit-learn, XGBoost, NumPy, Pandas
- **Vision:** OpenCV, imagehash, sentence-transformers

### Frontend
- **Framework:** React 18 + TypeScript
- **Build:** Vite
- **Styling:** Tailwind CSS
- **Charts:** Recharts
- **Icons:** Lucide React

### Infrastructure
- **Containerization:** Docker & Docker Compose
- **Testing:** pytest, Jest

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose (recommended)
- OR: Python 3.10+, Node.js 18+, PostgreSQL 14+

### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/jeetghosh07-liinux/phishing-domain-detector.git
cd phishing-domain-detector

# Copy environment template
cp .env.example .env

# Build and start services
docker compose up --build
```

**Endpoints:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Database: localhost:5432
- Redis: localhost:6379

### Option 2: Local Development

```bash
# Backend setup
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Database
DATABASE_URL=postgresql://user:pass@localhost/phishing_detector python -c "from app.database import create_tables; create_tables()"

# Start backend
python app/main.py

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

## 📡 API Documentation

### Interactive Docs
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Core Endpoints

#### Health Check
```
GET /api/health
```

#### Analyze Single Domain
```
POST /api/analyze
Content-Type: application/json

{
  "url": "https://example-phishing-domain.com"
}

Response:
{
  "domain": "example-phishing-domain.com",
  "matched_brand": "Example Bank",
  "phishing_probability": 0.94,
  "risk_level": "CRITICAL",
  "processing_time_ms": 1240,
  "features": {
    "domain_similarity": 0.94,
    "text_similarity": 0.86,
    "dom_similarity": 0.82,
    "visual_similarity": 0.91,
    "login_form_score": 0.93,
    "keyword_score": 0.87,
    "https_score": 0.95
  },
  "evidence": [
    {
      "type": "domain_similarity",
      "description": "Domain differs from reference by only 1-2 characters",
      "severity": "high"
    }
  ]
}
```

#### Batch Analysis
```
POST /api/analyze/batch
Content-Type: application/json

{
  "urls": [
    "https://domain1.com",
    "https://domain2.com",
    "https://domain3.com"
  ]
}
```

#### Watchlist Management
```
GET /api/watchlist                          # List all
POST /api/watchlist                         # Add domain
GET /api/watchlist/{id}                     # Get details
PUT /api/watchlist/{id}                     # Update
DELETE /api/watchlist/{id}                  # Remove
```

#### Reports & Export
```
GET /api/reports                            # List analyses
GET /api/reports/{id}                       # Get report
GET /api/export/csv?limit=100              # Export CSV
GET /api/export/json?limit=100             # Export JSON
```

## 📊 Dashboard Guide

### Overview Page
- Real-time statistics (domains scanned, phishing detected, critical alerts)
- Risk distribution chart
- Detection timeline
- Processing time metrics

### Scanner Page
- URL input field
- Real-time analysis progress
- Risk score display
- Evidence summary

### Analysis Result
- Phishing probability gauge
- Side-by-side screenshots (legitimate vs candidate)
- Feature scores (domain, content, DOM, visual, login form)
- Detailed evidence with explanations
- Timeline of analysis stages
- Export options (JSON/CSV)

### Watchlist Management
- Add/remove legitimate reference domains
- Enable/disable monitoring
- View fingerprint details
- Refresh screenshots
- Track candidate matches

### Alerts & Analytics
- Risk distribution (Low/Medium/High/Critical)
- Top impersonated brands
- Detection trends
- False positive feedback
- Performance metrics

## 🧠 Model Training

### Generate Synthetic Dataset
```bash
cd backend
python -m app.ml.generate_dataset
```

This creates:
- 500 legitimate domain samples
- 500 phishing/lookalike samples
- Feature CSV: `data/training_dataset.csv`

### Train Classifier
```bash
python -m app.ml.train
```

Outputs:
- Model file: `app/ml/model.pkl`
- Scaler: `app/ml/scaler.pkl`
- Metrics: accuracy, precision, recall, F1, ROC-AUC

### Evaluate Model
```bash
python -m app.ml.evaluate
```

## 📋 SIH1454 Alignment

This platform directly addresses NTRO's SIH1454 problem statement:

| Requirement | Implementation |
|---|---|
| Phishing probability score | ✅ 0-100% risk score with CRITICAL/HIGH/MEDIUM/LOW levels |
| Impersonated domain detection | ✅ Matched brand identification with confidence scores |
| Risk level classification | ✅ Automatic risk tier assignment |
| Detection reasons | ✅ Explainable evidence with feature contributions |
| Individual feature scores | ✅ 7-dimensional feature vector |
| Visual comparison | ✅ Side-by-side screenshot analysis |
| Content comparison | ✅ HTML/DOM/text similarity metrics |
| Explainable evidence | ✅ Natural language explanations |
| JSON/CSV export | ✅ Full report export |
| REST API | ✅ Comprehensive API with batch support |
| Processing time | ✅ Per-domain and average metrics |

## 🔒 Security Considerations

- ✅ SSRF protection (private IP blocking)
- ✅ Request timeouts & size limits
- ✅ URL validation & scheme checking
- ✅ Browser sandboxing (Playwright headless)
- ✅ No credential storage or submission
- ✅ Rate limiting on API endpoints
- ✅ Structured logging (no sensitive data)
- ✅ Input validation on all endpoints

## 📈 Performance Metrics

- Average detection time: **1.5-2.5 seconds** per domain
- Batch throughput: **25-40 domains/minute**
- Memory footprint: **~500MB** (including browser)
- Model inference: **<50ms** per prediction

## 📚 Additional Resources

- [Architecture Documentation](./docs/ARCHITECTURE.md)
- [ML Methodology](./docs/ML_METHODOLOGY.md)
- [API Reference](./docs/API.md)
- [Deployment Guide](./docs/DEPLOYMENT.md)

## 🤝 Contributing

Contributions welcome! Please follow:
1. Feature branch from `develop`
2. Comprehensive tests
3. Clear commit messages
4. PR description with changes

## 📄 License

MIT License - See LICENSE file

---

**Built for Smart India Hackathon 1454 (NTRO)**

*Cybersecurity through AI/ML Intelligence*
