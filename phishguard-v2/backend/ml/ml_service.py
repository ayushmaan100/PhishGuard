"""
backend/ml/ml_service.py

Flask microservice that serves LightGBM predictions.
Called by the Node.js API via HTTP on localhost.

WHY A SEPARATE PYTHON PROCESS:
  LightGBM is Python-native. Running it in a Node.js child process
  or via a foreign function interface adds complexity and instability.
  A lightweight Flask service on localhost adds <5ms latency and
  keeps each concern cleanly separated.

ENDPOINTS:
  POST /predict
    Body: { url, domain_intel?, content_signals? }
    Returns: { ml_score, features, model_version, latency_ms }

  GET /health
    Returns: { status: "ok", model_version, threshold }

  GET /feature-importance
    Returns: { features: [{ name, importance }] }

LOADING:
  Model is loaded once at startup and held in memory.
  Inference is pure CPU — no GPU needed for LightGBM at this scale.
  Single-threaded Flask is fine for our request volume (<100 req/min).
"""

import os
import sys
import json
import time
import pickle
import logging
from pathlib import Path
from flask import Flask, request, jsonify

# Add ML scripts to path for feature extractor
ML_DIR = Path(__file__).parent.parent.parent / 'ml'
sys.path.insert(0, str(ML_DIR / 'scripts'))
from features import extract_features, FEATURE_NAMES

import numpy as np

# ── Configuration ─────────────────────────────────────────────────────────────
MODEL_DIR  = ML_DIR / 'models'
PORT       = int(os.environ.get('ML_SERVICE_PORT', 5001))
HOST       = os.environ.get('ML_SERVICE_HOST', '127.0.0.1')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ML] %(levelname)s %(message)s',
)
logger = logging.getLogger(__name__)

# ── Load model at startup ─────────────────────────────────────────────────────
logger.info(f"Loading model from {MODEL_DIR}...")

try:
    with open(MODEL_DIR / 'model.pkl', 'rb') as f:
        MODEL = pickle.load(f)

    with open(MODEL_DIR / 'metadata.json') as f:
        METADATA = json.load(f)

    THRESHOLD     = METADATA['threshold']
    MODEL_VERSION = METADATA['model_version']
    TRAINED_AT    = METADATA.get('trained_at', 'unknown')

    logger.info(f"Model loaded: v{MODEL_VERSION}, threshold={THRESHOLD:.4f}")
    logger.info(f"Trained at: {TRAINED_AT}")
    logger.info(f"Features: {len(FEATURE_NAMES)}")
    logger.info(f"Trees: {METADATA.get('n_estimators', 'unknown')}")

except FileNotFoundError as e:
    logger.error(f"Model files not found: {e}")
    logger.error("Run: python3 ml/scripts/train.py first")
    sys.exit(1)
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    sys.exit(1)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    """Health check — used by Node.js to verify ML service is alive."""
    return jsonify({
        'status':        'ok',
        'model_version': MODEL_VERSION,
        'threshold':     THRESHOLD,
        'trained_at':    TRAINED_AT,
        'features':      len(FEATURE_NAMES),
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Main prediction endpoint.

    Request body:
    {
      "url": "https://paypa1.com/login",
      "domain_intel": {              // optional
        "age_days": 3,
        "cert_age_days": 1,
        "tranco_rank": null
      },
      "content_signals": {           // optional
        "hasLoginForm": true,
        "formActionExternal": false,
        "hasPasswordField": true,
        "faviconMismatch": true,
        "externalResourceRatio": 0.87,
        "titleBrandMismatch": true
      }
    }

    Response:
    {
      "ml_score": 0.94,              // 0.0-1.0 phishing probability
      "is_phishing": true,           // ml_score >= threshold
      "features": { ... },           // extracted features (for debugging)
      "model_version": "1.0.0",
      "latency_ms": 3
    }
    """
    t0 = time.time()

    try:
        body = request.get_json(force=True, silent=True)
        if not body:
            return jsonify({'error': 'Invalid JSON body'}), 400

        url = body.get('url', '').strip()
        if not url:
            return jsonify({'error': 'url is required'}), 400

        domain_intel    = body.get('domain_intel')    or None
        content_signals = body.get('content_signals') or None

        # Extract features
        features = extract_features(url, domain_intel, content_signals)

        # Build feature vector in exact training order
        X = np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float32)

        # Predict
        ml_score    = float(MODEL.predict_proba(X)[0][1])
        is_phishing = ml_score >= THRESHOLD

        latency_ms = round((time.time() - t0) * 1000, 1)

        return jsonify({
            'ml_score':     round(ml_score, 4),
            'is_phishing':  is_phishing,
            'threshold':    THRESHOLD,
            'features':     features,
            'model_version':MODEL_VERSION,
            'latency_ms':   latency_ms,
        })

    except Exception as e:
        logger.error(f"Prediction error for {body.get('url', '?')}: {e}", exc_info=True)
        return jsonify({'error': 'Prediction failed', 'detail': str(e)}), 500


@app.route('/feature-importance', methods=['GET'])
def feature_importance():
    """Return feature importances for debugging and monitoring."""
    importances = MODEL.feature_importances_
    features = sorted(
        [{'name': n, 'importance': int(i)}
         for n, i in zip(FEATURE_NAMES, importances)],
        key=lambda x: x['importance'], reverse=True,
    )
    return jsonify({'features': features, 'model_version': MODEL_VERSION})


@app.route('/batch-predict', methods=['POST'])
def batch_predict():
    """
    Batch prediction for multiple URLs (used by retraining pipeline).

    Request: { "urls": ["url1", "url2", ...] }
    Response: { "results": [{ "url", "ml_score", "is_phishing" }, ...] }
    """
    t0 = time.time()
    body = request.get_json(force=True, silent=True)
    if not body or 'urls' not in body:
        return jsonify({'error': 'urls array required'}), 400

    urls = body['urls'][:500]  # cap at 500 per batch
    results = []

    for url in urls:
        try:
            features = extract_features(url)
            X = np.array([[features[name] for name in FEATURE_NAMES]], dtype=np.float32)
            score = float(MODEL.predict_proba(X)[0][1])
            results.append({
                'url':        url,
                'ml_score':   round(score, 4),
                'is_phishing':score >= THRESHOLD,
            })
        except Exception:
            results.append({'url': url, 'ml_score': 0.5, 'is_phishing': False, 'error': True})

    return jsonify({
        'results':    results,
        'count':      len(results),
        'latency_ms': round((time.time() - t0) * 1000, 1),
    })


if __name__ == '__main__':
    logger.info(f"Starting ML service on {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
