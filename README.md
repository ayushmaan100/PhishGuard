
# 🛡️ PhishGuard

**PhishGuard** is a highly mature, real-time phishing detection system designed as a Chrome Extension. It utilizes a sophisticated multi-layered architecture—combining local heuristics, threat intelligence, and a machine learning microservice—to detect and block zero-day phishing attacks before they can compromise user data.

---

## 🏗️ System Architecture

PhishGuard employs a resilient three-tier architecture to balance latency, accuracy, and browser resource constraints:

1. **Client Tier (Chrome Extension - Manifest V3)**: 
   - Intercepts navigation events via the `webNavigation` API.
   - Executes local URL heuristics instantly (<5ms).
   - Injects content scripts to analyze the DOM of visited pages safely.
   - Manages an ephemeral state to ensure reliability even if the service worker is terminated by the browser.

2. **API Gateway (Node.js / Express)**: 
   - Acts as the central orchestrator for heavy external lookups.
   - Performs parallel Domain Intelligence queries (e.g., RDAP for domain age, crt.sh for certificate validation).
   - Enforces strict global and per-install rate limiting to prevent abuse.
   - Employs an MD5-hashed caching layer (30-minute TTL) for instantaneous verdicts on popular sites.

3. **Machine Learning Microservice (Python / Flask)**: 
   - A lightweight, locally hosted microservice dedicated solely to model inference.
   - Powered by a **LightGBM** classifier, chosen for its ultra-fast CPU inference (<5ms) and native handling of missing features.
   - Evaluates exactly 29 synchronized features across URL structure, domain age, and DOM characteristics.

---

## 🔍 The Detection Pipeline

PhishGuard prioritizes the user's browsing experience. To prevent page-load delays, the `orchestrator.js` utilizes a staggered pipeline:

* **Layer 0 (Allowlist)**: Instant check against the Tranco Top 10k list and user-defined personal whitelists.
* **Layer 1A (Google Safe Browsing)**: Asynchronous check against known malicious databases. If GSB flags the site, the pipeline short-circuits to a block.
* **Layer 1B (Local URL Heuristics)**: Synchronous, instant extraction of URL anomalies (e.g., entropy, suspicious TLDs, length) to update the extension badge immediately.
* **Layer 2 (Parallel Enrichment)**: 
  * **2A (Domain)**: Backend fetches WHOIS/RDAP data for domain age.
  * **2B (DOM)**: Content script scans the loaded page for external login forms, hidden inputs, and favicon mismatches (with a strict 800ms timeout).
* **Layer 3 (Machine Learning)**: Aggregated signals are passed to the LightGBM model. Calibrated for >96% precision, it delivers a final verdict and triggers the interstitial warning page if phishing is detected.

---

## 📂 Repository Structure

```text
PhishGuard/
├── phishguard/                     # Chrome Extension (Manifest V3)
│   ├── assets/                     # Icons and local datasets (Tranco 10k)
│   ├── background/                 # Service worker, layers (1-3), orchestrator, caching
│   ├── content/                    # DOM analysis scripts
│   ├── interstitial/               # Warning page UI shown when phishing is blocked
│   ├── onboarding/                 # First-time setup UI
│   ├── popup/                      # Extension popup UI
│   ├── settings/                   # User configuration UI
│   └── manifest.json
│
└── phishguard-v2/                  # Backend Services
    ├── backend/                    # Node.js API Gateway
    │   ├── middleware/             # Caching, Domain Intel
    │   ├── routes/                 # Analysis and health endpoints
    │   ├── server.js               # Express server entry point
    │   └── ml/                     # Python ML Microservice
    │       ├── ml_service.py       # Flask server for ML inference
    │       ├── requirements.txt
    │       └── models/             # Serialized LightGBM models (.pkl)
    └── ml/                         # ML Training & Data Pipeline
        ├── scripts/                # train.py, build_dataset.py, features.py
        └── data/                   # Training datasets
```

---

## 🚀 Installation & Setup

### 1. Run the Machine Learning Microservice
The ML service must be running for Layer 3 analysis to function.
```bash
cd phishguard-v2/backend/ml
# Create a virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the Flask microservice (runs on port 5001)
python ml_service.py
```

### 2. Run the Node.js API Gateway
The Node.js server proxies requests from the extension to the ML service and handles domain lookups.
```bash
cd phishguard-v2/backend

# Install Node dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env to add your Google Safe Browsing API key and configure ports

# Start the Express server (runs on port 3000)
npm start
```

### 3. Load the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `phishguard/` directory from this repository.
5. Pin the extension to your toolbar to access the popup and settings.

---

## 🛠️ Tech Stack
* **Extension**: Vanilla JavaScript, HTML5, CSS3, Chrome Extensions API (Manifest V3).
* **Backend Gateway**: Node.js, Express, node-cache, express-rate-limit.
* **ML Service**: Python, Flask, LightGBM, scikit-learn, pandas.

---

## Contributing

Fork the repository
Create a feature branch: git checkout -b feature/your-feature
Make your changes — run the test suite before committing
Submit a pull request with a clear description of what changes and why

Running Tests
The test suite for each milestone is embedded in the project history. To verify the core logic:
bash# Extension logic tests (Node.js)
node tests/run_tests.js

## ML pipeline tests (Python)
```bash
cd phishguard-ml
python3 scripts/test_features.py
```

---

## ⚠️ Disclaimer
PhishGuard is designed as an educational/research tool to demonstrate multi-layered cybersecurity concepts. While highly accurate, no automated system can detect 100% of malicious websites. Users should always exercise caution when browsing.
```
