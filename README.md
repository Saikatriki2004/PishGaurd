<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Flask-3.0+-green.svg" alt="Flask">
  <img src="https://img.shields.io/badge/React-18.2-61DAFB.svg" alt="React">
  <img src="https://img.shields.io/badge/ML-XGBoost-orange.svg" alt="XGBoost">
  <img src="https://img.shields.io/badge/Accuracy-96.8%25-brightgreen.svg" alt="Accuracy">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
</p>

<h1 align="center">🛡️ PhishGuard</h1>

<p align="center">
  <strong>AI-Powered Phishing URL Detection System</strong><br>
  Protect yourself from phishing attacks with real-time URL analysis powered by machine learning.
</p>

---

## 🎯 Overview

**PhishGuard** is a production-grade phishing detection system that uses machine learning to analyze URLs and identify potential phishing threats in real-time. It combines 30+ feature extraction techniques with a calibrated Gradient Boosting classifier to provide accurate, explainable verdicts.

### Key Features

- 🔍 **Real-time URL Analysis** - Scan any URL instantly with detailed risk assessment
- 🤖 **ML-Powered Detection** - Calibrated Gradient Boosting model with 96.8% accuracy
- 📊 **Explainable AI** - Understand why a URL is flagged with per-feature explanations
- ✅ **Trusted Domain Bypass** - Pre-verified trusted domains bypass ML for speed
- 🌐 **Threat Intelligence Map** - Visualize global phishing threats in real-time
- 📈 **Batch Scanning** - Analyze up to 50 URLs simultaneously
- 🔒 **Production-Ready** - Rate limiting, Prometheus metrics, structured logging
- 🛡️ **AI Governance** - Safety controls, policy auditing, and emergency freeze capabilities
- ⚛️ **Modern React Frontend** - Responsive SPA with TailwindCSS and Vite

---

## 🖥️ Screenshots

### URL Scanner Interface
Clean, modern interface for scanning URLs with instant verdicts.

### Threat Map Dashboard
Global visualization of phishing threats and attack vectors.

### Scan History
Track and review all your previous scans with detailed logs.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- Node.js 18+ (for React frontend)
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Saikatriki2004/PishGaurd.git
   cd PishGaurd
   ```

2. **Install Backend dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Flask API server**
   ```bash
   python app.py
   ```
   The API will be available at `http://127.0.0.1:5000`

4. **Install and run React Frontend** (in a new terminal)
   ```bash
   cd phishguard-frontend
   npm install
   npm run dev
   ```
   
   > **Important:** Keep the Flask API server running in a separate terminal while running the React dev server. See [Configuration](#-configuration) for `.env` setup with `VITE_API_URL`.

5. **Open the application**
   ```
   http://localhost:3000
   ```

> **Note:** The Flask backend is now API-only. The React frontend at `phishguard-frontend/` is the primary UI.

---

## 📦 Project Structure

```
PhishGuard/
├── app.py                          # Main Flask application & API routes
├── decision_pipeline.py            # Core ML decision pipeline (compatibility)
├── feature_extractor.py            # URL feature extraction (compatibility)
├── trusted_domains.py              # Trusted domain whitelist (compatibility)
├── settings_manager.py             # Application settings management
├── settings_routes.py              # Settings API routes
├── integrate_live_data.py          # Live data integration module
├── wsgi.py                         # WSGI entry point for production
├── requirements.txt                # Python dependencies
├── Procfile                        # Heroku deployment configuration
│
├── Backend/                        # Backend source modules
│   ├── app.py                      # Alternative app entry point
│   ├── src/
│   │   ├── features/               # Feature extraction modules
│   │   │   ├── feature.py          # Feature definitions
│   │   │   └── feature_extractor.py # URL feature extraction
│   │   ├── pipeline/               # ML pipeline components
│   │   │   └── decision_pipeline.py # Decision making logic
│   │   ├── training/               # Model training scripts
│   │   │   ├── model_trainer.py    # Training orchestration
│   │   │   └── merge_and_train.py  # Dataset merging & training
│   │   ├── governance/             # AI Governance & Safety
│   │   │   ├── governance_engine.py    # Core governance logic
│   │   │   ├── safety_governance.py    # Safety controls
│   │   │   ├── policy_audit.py         # Policy auditing
│   │   │   ├── trusted_domains.py      # Trusted domain management
│   │   │   └── blocklist.py            # Malicious domain blocklist
│   │   ├── monitoring/             # Model monitoring
│   │   │   └── calibration_monitor.py  # Calibration tracking
│   │   └── observability/          # Metrics & logging
│   │       └── explanation_telemetry.py # Explanation tracking
│   ├── config/                     # Configuration files
│   │   └── user_answers.json       # User Q&A configuration
│   ├── models/                     # Trained ML models
│   ├── tests/                      # Unit tests
│   └── audit/                      # Policy audit logs
│
├── phishguard-frontend/            # React Frontend (Vite + TailwindCSS)
│   ├── src/
│   │   ├── App.jsx                 # Main React application
│   │   ├── main.jsx                # Entry point
│   │   ├── pages/                  # Page components
│   │   ├── components/             # Reusable components
│   │   │   └── ErrorBoundary.jsx   # Error handling component
│   │   ├── api/                    # API client
│   │   ├── context/                # React context providers
│   │   └── layouts/                # Layout components
│   ├── package.json                # Node.js dependencies
│   ├── vite.config.js              # Vite configuration
│   └── tailwind.config.js          # TailwindCSS configuration
│
├── models/                         # Production ML models
│   ├── model.pkl                   # Trained Gradient Boosting model (~4.5MB)
│   ├── model_metadata.json         # Model performance metrics
│   └── mock_model.pkl              # Mock model for testing
│
├── static/                         # Static assets (CSS, JS, images)
├── datasets/                       # Training datasets
├── tests/                          # Integration tests
├── config/                         # Global configuration files
├── metrics/                        # Metrics storage
├── audit/                          # Audit logs
├── scripts/                        # Utility scripts
├── GOVERNANCE.md                   # AI Governance documentation
└── Phishing URL Detection.ipynb    # Jupyter notebook for analysis
```

---

## 🔬 How It Works

### Detection Pipeline

```
URL Input → Validation → Trusted Domain Check → Feature Extraction → ML Inference → Verdict
```

1. **URL Validation** - Validates URL format and length
2. **Trusted Domain Gate** - Known safe domains bypass ML (e.g., google.com)
3. **Feature Extraction** - Extracts 30+ features from URL structure and content
4. **Calibrated ML** - Predicts phishing probability with calibrated confidence
5. **Tri-State Verdict** - Returns SAFE, SUSPICIOUS, or PHISHING

### Feature Categories (33 Total Features)

| Category | Features | Description |
|----------|----------|-------------|
| **URL Structure** | `using_ip_address`, `url_length`, `is_shortener`, `has_at_symbol`, `has_double_slash_redirect` | Analyzes URL patterns |
| **Domain Analysis** | `subdomain_count`, `has_dash_in_domain`, `has_https`, `domain_registration_length`, `domain_age` | Domain characteristics |
| **Content Analysis** | `external_resources_ratio`, `external_scripts_ratio`, `suspicious_form_handler`, `iframe_present` | Page content signals |
| **Security Signals** | `certificate_age`, `has_dns_record`, `abnormal_url_whois`, `https_in_domain_name` | Security infrastructure |
| **Behavioral** | `popup_windows`, `right_click_disabled`, `status_bar_manipulation`, `redirect_count` | Suspicious behaviors |
| **Advanced** | `url_entropy`, `homoglyph_detected`, `statistical_report_match` | Advanced detection |
| **Failure Indicators** | `http_fetch_failed`, `whois_lookup_failed`, `dns_lookup_failed` | Extraction failure tracking |

### Decision Thresholds

| Risk Level | Threshold | Verdict |
|------------|-----------|---------|
| Low Risk | < 55% | ✅ SAFE |
| Medium Risk | 55% - 85% | ⚠️ SUSPICIOUS |
| High Risk | ≥ 85% | 🚨 PHISHING |

---

## 📊 Model Performance

The model is trained on 11,000+ labeled URLs with calibrated probability outputs:

| Metric | Phishing Class | Legitimate Class |
|--------|----------------|------------------|
| **Precision** | 97.49% | 96.33% |
| **Recall** | 95.30% | 98.05% |
| **F1-Score** | 96.38% | 97.18% |

**Overall Accuracy: 96.83%**

### Confusion Matrix

|  | Predicted Legitimate | Predicted Phishing |
|--|---------------------|-------------------|
| **Actual Legitimate** | 1,208 | 24 |
| **Actual Phishing** | 46 | 933 |

### Model Details

- **Model Type**: CalibratedClassifierCV (Isotonic calibration)
- **Base Estimator**: GradientBoostingClassifier
- **Input Features**: 33 (30 base + 3 failure indicators)
- **Training Date**: 2025-12-28

---

## 🔌 API Reference

### Scan Single URL

```http
POST /scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "success": true,
  "verdict": "SAFE",
  "risk_score": 15.2,
  "is_trusted_domain": false,
  "explanation": {
    "summary": "This URL appears to be legitimate...",
    "positive_signals": [...],
    "risk_signals": [...]
  }
}
```

### Batch Scan (up to 50 URLs)

```http
POST /api/batch-scan
Content-Type: application/json

{
  "urls": ["https://example1.com", "https://example2.com"]
}
```

### Governance Status

```http
GET /api/governance/status
```

Returns freeze state, budget information, and system health.

### Emergency Unfreeze

```http
POST /api/governance/unfreeze
X-Admin-Key: <admin-key>

{
  "force": true,
  "ticket": "INC-12345"
}
```

### Health Checks

```http
GET /health/live    # Liveness probe
GET /health/ready   # Readiness probe
```

### Prometheus Metrics

```http
GET /metrics
```

---

## 🛠️ Tech Stack

### Backend
- **Flask 3.0+** - Web framework with CORS support
- **Scikit-learn 1.3+** - Machine learning pipeline
- **XGBoost 2.0+** - Gradient boosting ensemble
- **NumPy/Pandas** - Data processing
- **Flask-Limiter** - Rate limiting middleware
- **Prometheus Flask Exporter** - Metrics collection

### Frontend (React SPA)
- **React 18.2** - Component-based UI
- **Vite 5.0** - Fast build tool
- **TailwindCSS 3.4** - Utility-first CSS
- **React Query** - Server state management
- **React Router 6** - Client-side routing
- **Recharts** - Data visualization
- **Leaflet** - Interactive maps


### AI Governance
- **Safety Governance** - Emergency freeze capabilities
- **Policy Auditing** - Compliance tracking
- **Trusted Domain Management** - Whitelist management
- **Blocklist Engine** - Malicious domain blocking

---

## 🧪 Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment mode (`development`/`production`) | `development` |
| `FLASK_DEBUG` | Debug mode | `False` |
| `FRONTEND_URL` | React frontend URL for CORS and API responses | `http://localhost:3000` |
| `ALLOWED_ORIGINS` | Comma-separated allowed CORS origins (production) | Uses `FRONTEND_URL` |
| `PHISHGUARD_ADMIN_KEY` | Admin API key for governance endpoints | Dev key |
| `RATE_LIMIT` | API rate limit | `100/hour` |
| `USE_MOCK_MODEL` | Use mock model for testing | `false` |

### React Frontend Configuration

Create `.env` file in `phishguard-frontend/`:
```env
VITE_API_URL=http://localhost:5000
```

### Trusted Domains

Edit `trusted_domains_manifest.json` to add/remove trusted domains that bypass ML detection.

---

## 🛡️ AI Governance

PhishGuard includes enterprise-grade AI governance features:

- **Emergency Freeze** - Instantly halt all predictions in case of issues
- **Policy Auditing** - Track all governance decisions
- **Budget Controls** - Rate limiting and resource management
- **Transparency** - Full explanation of model decisions

See [GOVERNANCE.md](GOVERNANCE.md) for detailed documentation.

---

## 🚀 Deployment

### Heroku

```bash
heroku create your-app-name
git push heroku main
```

### Docker

```bash
docker build -t phishguard .
docker run -p 5000:5000 phishguard
```

### Production WSGI

```bash
gunicorn wsgi:app -w 4 -b 0.0.0.0:5000
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Dataset sources for phishing URL research
- Scikit-learn and XGBoost communities
- Flask and React framework contributors
- Open-source security research community

---

## 📧 Contact

**Saikat** - [@Saikatriki2004](https://github.com/Saikatriki2004)

Project Link: [https://github.com/Saikatriki2004/PishGaurd](https://github.com/Saikatriki2004/PishGaurd)

---

<p align="center">
  Made with ❤️ for a safer internet
</p>
