/**
 * layers/layer3-ml.js
 *
 * Layer 3: ML Backend Scoring
 *
 * Calls your PhishGuard V2 backend to get:
 *   1. ML score (LightGBM probability — 0.0 to 1.0)
 *   2. Server-side domain intelligence (RDAP + crt.sh)
 *
 * WHY THIS IS BETTER THAN CALLING APIS DIRECTLY:
 *   - Server-side cache shared across ALL users — domain intel for
 *     "evil.com" is only fetched once globally, not per-user
 *   - API keys (GSB in V2) never exposed in extension code
 *   - ML model runs on your server — model weights never downloaded
 *   - Backend can be updated without Chrome Web Store re-review
 *
 * GRACEFUL DEGRADATION:
 *   If backend is unreachable → returns null → Tier 1+2 heuristics still run
 *   The extension NEVER blocks waiting for V2 — hard 2.5s timeout
 *   Users never notice backend downtime
 *
 * SCORING INTEGRATION:
 *   The ML score is converted to additional points for the scorer:
 *     mlScore 0.90-1.00 → +35 pts (DANGEROUS confidence)
 *     mlScore 0.75-0.90 → +25 pts (HIGH_RISK confidence)
 *     mlScore 0.60-0.75 → +15 pts (SUSPICIOUS confidence)
 *     mlScore < 0.60    → +0  pts (below threshold, no contribution)
 *
 *   These points stack with Tier 1+2 signals and are counted as
 *   a separate 'ml' category — enabling the 3-category rule to fire.
 *
 * CONFIGURATION:
 *   Set BACKEND_URL in this file to your deployed backend URL.
 *   Change to 'http://localhost:3000' for local development.
 */

// ── Configuration ─────────────────────────────────────────────────────────────

// Your deployed backend URL — change this before publishing
// Development: 'http://localhost:3000'
// Production:  'https://your-api.railway.app'
const BACKEND_URL = 'https://your-api.railway.app'

const ANALYZE_ENDPOINT = `${BACKEND_URL}/api/v1/analyze`
const REPORT_ENDPOINT  = `${BACKEND_URL}/api/v1/reports`
const TIMEOUT_MS       = 2500  // never block extension longer than this

// ── Main export ────────────────────────────────────────────────────────────────

/**
 * Get ML score + server-side domain intel for a URL.
 *
 * @param {string} url               — full URL to analyze
 * @param {object} [contentSignals]  — from content script (forwarded to backend)
 * @returns {Promise<MLResult|null>}
 *
 * @typedef {object} MLResult
 * @property {number}   mlScore       — 0.0-1.0 phishing probability
 * @property {boolean}  mlIsPhishing  — mlScore >= backend threshold
 * @property {number}   mlPoints      — points to add to scorer (0-35)
 * @property {string[]} mlSignals     — human-readable ML reasons
 * @property {object}   domainIntel   — { age_days, cert_age_days, tranco_rank }
 * @property {boolean}  fromCache     — result came from server cache
 */
export async function checkML(url, contentSignals = null) {
  // Skip if backend not configured
  if (!BACKEND_URL || BACKEND_URL.includes('your-api')) {
    return null
  }

  // Skip non-HTTP URLs
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return null
  }

  const controller = new AbortController()
  const timer      = setTimeout(() => controller.abort(), TIMEOUT_MS)

  try {
    // Get a stable install ID for rate limiting
    // This is hashed server-side — we never store it as a tracking ID
    const installId = await getInstallId()

    const body = {
      url,
      contentSignals: contentSignals ? {
        hasLoginForm:          contentSignals.hasLoginForm          || false,
        formActionExternal:    contentSignals.formActionExternal    || false,
        hasPasswordField:      contentSignals.hasPasswordField      || false,
        faviconMismatch:       contentSignals.faviconMismatch       || false,
        externalResourceRatio: contentSignals.externalResourceRatio || 0,
        titleBrandMismatch:    contentSignals.titleBrandMismatch    || false,
      } : null,
      installId,
    }

    const res = await fetch(ANALYZE_ENDPOINT, {
      method:  'POST',
      headers: {
        'Content-Type':   'application/json',
        'X-Install-Id':   installId,
        'X-API-Version':  '2',
      },
      body:    JSON.stringify(body),
      signal:  controller.signal,
    })

    clearTimeout(timer)

    if (!res.ok) {
      console.warn('[PhishGuard] Backend returned', res.status)
      return null
    }

    const data = await res.json()

    return {
      mlScore:     data.mlScore      ?? null,
      mlIsPhishing:data.mlIsPhishing ?? false,
      mlPoints:    scoreToPoints(data.mlScore),
      mlSignals:   Array.isArray(data.mlSignals) ? data.mlSignals : [],
      domainIntel: data.domainIntel  ?? null,
      modelVersion:data.modelVersion ?? null,
      fromCache:   data.cached       ?? false,
      latency_ms:  data.latency_ms   ?? null,
    }

  } catch (err) {
    clearTimeout(timer)
    if (err.name === 'AbortError') {
      console.debug('[PhishGuard] Backend timeout — using heuristics only')
    } else if (err.message?.includes('Failed to fetch') ||
               err.message?.includes('NetworkError')) {
      console.debug('[PhishGuard] Backend unreachable — using heuristics only')
    } else {
      console.debug('[PhishGuard] Backend error:', err.message)
    }
    return null
  }
}

/**
 * Send a false positive report to the backend.
 * Called when user clicks "Report" in the popup.
 * Fire-and-forget — we don't wait for or surface the response.
 *
 * @param {string} url
 * @param {object} result — the analysis result that was wrong
 */
export async function reportFalsePositive(url, result) {
  if (!BACKEND_URL || BACKEND_URL.includes('your-api')) return

  try {
    const installId = await getInstallId()
    await fetch(REPORT_ENDPOINT, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Install-Id': installId,
      },
      body: JSON.stringify({
        url,
        verdict:     result?.verdict     ?? 'UNKNOWN',
        score:       result?.score       ?? 0,
        firedSignals:result?.firedSignals ?? [],
        reasons:     result?.reasons     ?? [],
        installId,
      }),
    })
  } catch {
    // Reporting failures are always silent — never surface to user
  }
}

// ── ML score → scorer points ───────────────────────────────────────────────────

/**
 * Convert a raw ML probability (0-1) into scorer points (0-35).
 * These points represent the ML layer's contribution to the final score.
 *
 * The conversion is deliberately conservative at the edges:
 *   - We don't give 35 points for a 0.91 score because the model
 *     might be miscalibrated at the extremes on novel phishing kits
 *   - Below 0.60, the model isn't confident — contribute nothing
 *
 * @param {number|null} mlScore
 * @returns {number}
 */
function scoreToPoints(mlScore) {
  if (mlScore === null || mlScore === undefined) return 0
  if (mlScore >= 0.90) return 35   // Very high confidence → DANGEROUS tier
  if (mlScore >= 0.75) return 25   // High confidence → HIGH_RISK tier
  if (mlScore >= 0.60) return 15   // Moderate confidence → SUSPICIOUS tier
  return 0                          // Below threshold → don't penalise
}

// ── Install ID ────────────────────────────────────────────────────────────────

let _installId = null

/**
 * Get a stable, anonymous install identifier.
 * Generated once on first use and persisted in chrome.storage.local.
 * Used only for rate limiting — never stored on server in raw form.
 */
async function getInstallId() {
  if (_installId) return _installId

  try {
    const stored = await chrome.storage.local.get('_installId')
    if (stored._installId) {
      _installId = stored._installId
      return _installId
    }

    // Generate new install ID
    const array = new Uint8Array(16)
    crypto.getRandomValues(array)
    _installId = Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('')

    await chrome.storage.local.set({ _installId })
    return _installId

  } catch {
    // Fallback: use a session-only random ID
    if (!_installId) {
      _installId = Math.random().toString(36).slice(2) + Date.now().toString(36)
    }
    return _installId
  }
}
