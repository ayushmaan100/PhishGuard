/**
 * backend/routes/analyze.js
 *
 * POST /api/v1/analyze
 *
 * Core detection endpoint called by the extension for Layer 3 (ML scoring).
 * Receives URL + optional content signals, returns ML score + domain intel.
 *
 * Design decisions:
 *  - Domain intel (RDAP + crt.sh) and ML inference run IN PARALLEL
 *  - ML is called with whatever domain intel is available at that point
 *  - If ML service is down → response omits mlScore, extension uses heuristics
 *  - If domain intel fails → ML still runs with sentinel values
 *  - Every failure path returns a valid JSON response (never 5xx to extension)
 *
 * Request body:
 * {
 *   url:            string  (required)
 *   contentSignals: object  (optional, from content script)
 *   installId:      string  (optional, for rate limiting)
 * }
 *
 * Response:
 * {
 *   mlScore:      number|null   — 0.0-1.0 phishing probability
 *   mlIsPhishing: boolean       — mlScore >= threshold
 *   mlSignals:    string[]      — top reasons from ML (for popup display)
 *   domainIntel:  object|null   — { age_days, cert_age_days, tranco_rank }
 *   cached:       boolean
 *   latency_ms:   number
 * }
 */

import express   from 'express'
import rateLimit from 'express-rate-limit'
import crypto    from 'crypto'
import { cache }                      from '../middleware/cache.js'
import { rdapDomainAge, certAge }     from '../middleware/domainIntel.js'

const router = express.Router()

const ML_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001'

// ── Per-install rate limiter ───────────────────────────────────────────────────
const installLimiter = rateLimit({
  windowMs: 10 * 60_000,  // 10 minutes
  max:      200,
  keyGenerator: (req) => {
    const id = req.headers['x-install-id'] || req.ip || 'anonymous'
    return crypto.createHash('sha256').update(String(id)).digest('hex').slice(0, 16)
  },
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    res.status(429).json({ error: 'Rate limit exceeded. Retry in 10 minutes.' })
  },
})
router.use(installLimiter)

// ── POST /api/v1/analyze ───────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  const t0 = Date.now()

  // ── Validate input ──────────────────────────────────────────────────────────
  const { url, contentSignals } = req.body ?? {}

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url is required and must be a string' })
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return res.status(400).json({ error: 'url must start with http:// or https://' })
  }
  if (url.length > 2048) {
    return res.status(400).json({ error: 'url exceeds maximum length of 2048 chars' })
  }

  let hostname
  try {
    hostname = new URL(url).hostname
  } catch {
    return res.status(400).json({ error: 'url is malformed' })
  }

  // ── Cache check ─────────────────────────────────────────────────────────────
  // Cache key: MD5 of URL (deterministic, fixed-length, privacy-acceptable for server cache)
  const urlHash  = crypto.createHash('md5').update(url).digest('hex')
  const cacheKey = `analyze:${urlHash}`
  const cached   = await cache.get(cacheKey)

  if (cached) {
    return res.json({ ...cached, cached: true, latency_ms: Date.now() - t0 })
  }

  // ── Run domain intel and ML in parallel ────────────────────────────────────
  // We don't wait for domain intel before calling ML — both start simultaneously.
  // If domain intel finishes first, it enriches the ML features.
  // If ML finishes first, it runs with sentinel values for domain features.

  let domainIntel = null
  let mlData      = null

  const [domainResult, mlResult] = await Promise.allSettled([
    fetchDomainIntel(hostname),
    callML(url, contentSignals, null),  // initial ML call without domain intel
  ])

  domainIntel = domainResult.status === 'fulfilled' ? domainResult.value : null
  mlData      = mlResult.status    === 'fulfilled' ? mlResult.value    : null

  // If domain intel arrived AND initial ML failed or returned no result,
  // retry ML with enriched features
  if (domainIntel && !mlData) {
    try {
      mlData = await callML(url, contentSignals, domainIntel)
    } catch { /* keep null */ }
  }

  // ── Build response ──────────────────────────────────────────────────────────
  const response = {
    mlScore:      mlData?.ml_score      ?? null,
    mlIsPhishing: mlData?.is_phishing   ?? false,
    mlSignals:    buildSignalLabels(mlData?.features ?? null),
    domainIntel:  domainIntel,
    modelVersion: mlData?.model_version ?? null,
    cached:       false,
    latency_ms:   Date.now() - t0,
  }

  // Cache for 30 minutes — only when we got at least some data
  if (mlData || domainIntel) {
    await cache.set(cacheKey, response, 30 * 60_000)
  }

  return res.json(response)
})

// ── ML service call ─────────────────────────────────────────────────────────────

const ML_TIMEOUT_MS = 2000  // hard timeout — never block extension for > 2s

/**
 * Call the Python ML inference service.
 * Returns null on any failure — extension continues with heuristics.
 */
async function callML(url, contentSignals, domainIntel) {
  const controller = new AbortController()
  const timer      = setTimeout(() => controller.abort(), ML_TIMEOUT_MS)

  try {
    const body = {
      url,
      domain_intel: domainIntel ? {
        age_days:      domainIntel.age_days      ?? null,
        cert_age_days: domainIntel.cert_age_days ?? null,
        tranco_rank:   domainIntel.tranco_rank   ?? null,
      } : null,
      content_signals: contentSignals ? {
        hasLoginForm:          Boolean(contentSignals.hasLoginForm),
        formActionExternal:    Boolean(contentSignals.formActionExternal),
        hasPasswordField:      Boolean(contentSignals.hasPasswordField),
        faviconMismatch:       Boolean(contentSignals.faviconMismatch),
        externalResourceRatio: Number(contentSignals.externalResourceRatio) || 0,
        titleBrandMismatch:    Boolean(contentSignals.titleBrandMismatch),
      } : null,
    }

    const res = await fetch(`${ML_URL}/predict`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  controller.signal,
    })

    clearTimeout(timer)

    if (!res.ok) {
      console.warn('[Analyze] ML service returned', res.status)
      return null
    }

    return res.json()

  } catch (err) {
    clearTimeout(timer)
    if (err.name === 'AbortError') {
      console.warn('[Analyze] ML service timed out after', ML_TIMEOUT_MS, 'ms')
    } else {
      console.warn('[Analyze] ML service error:', err.message)
    }
    return null
  }
}

// ── Domain intelligence ────────────────────────────────────────────────────────

/**
 * Run RDAP + crt.sh lookups in parallel for a hostname.
 * Returns null if both fail.
 */
async function fetchDomainIntel(hostname) {
  const [ageResult, certResult] = await Promise.allSettled([
    rdapDomainAge(hostname),
    certAge(hostname),
  ])

  const ageDays  = ageResult.status  === 'fulfilled' ? ageResult.value  : null
  const certDays = certResult.status === 'fulfilled' ? certResult.value : null

  // Return null only if we have absolutely no data
  if (ageDays === null && certDays === null) return null

  return {
    age_days:      ageDays,
    cert_age_days: certDays,
    tranco_rank:   null,  // Extension handles Tranco via bundled JSON
  }
}

// ── Signal labels for popup display ────────────────────────────────────────────

/**
 * Convert ML feature values into 3 human-readable reasons.
 * These merge with the extension's heuristic reasons in the popup.
 */
function buildSignalLabels(features) {
  if (!features) return []

  const EVALUATORS = [
    [f => f.domain_age_days >= 0  && f.domain_age_days < 7,   f => `Domain registered only ${f.domain_age_days} day(s) ago`],
    [f => f.domain_age_days >= 7  && f.domain_age_days < 30,  f => `Domain is only ${f.domain_age_days} days old`],
    [f => f.cert_age_days  >= 0  && f.cert_age_days  < 7,    f => `SSL certificate issued ${f.cert_age_days} day(s) ago`],
    [f => f.min_brand_distance > 0 && f.min_brand_distance <= 2, () => 'Domain closely resembles a known brand'],
    [f => f.title_brand_mismatch === 1,   () => 'Page title claims to be a known brand'],
    [f => f.form_action_external === 1,   () => 'Login form submits credentials to external domain'],
    [f => f.favicon_mismatch === 1,       () => 'Favicon loads from a different domain'],
    [f => f.external_resource_ratio > 0.8,f => `${Math.round(f.external_resource_ratio * 100)}% of resources load from external domains`],
    [f => f.has_ip_in_host === 1,         () => 'URL uses an IP address instead of a domain name'],
    [f => f.num_brand_keywords >= 2,      f => `URL contains ${f.num_brand_keywords} brand keywords`],
    [f => f.suspicious_tld === 1,         () => 'Domain uses a TLD commonly associated with phishing'],
  ]

  const signals = []
  for (const [predicate, label] of EVALUATORS) {
    try {
      if (predicate(features)) signals.push(label(features))
    } catch { /* skip malformed feature */ }
    if (signals.length >= 3) break
  }
  return signals
}

export const analyzeRoute = router
