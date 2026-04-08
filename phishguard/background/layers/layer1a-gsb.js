/**
 * layers/layer1a-gsb.js
 *
 * Layer 1A: Google Safe Browsing API v4 — Lookup API
 *
 * WHY LOOKUP API (not Update API)?
 * The Update API is the hash-prefix protocol used by Chrome itself.
 * It requires maintaining a local threat database (300MB+) with
 * periodic diffs — impractical for a browser extension.
 *
 * The Lookup API sends URLs to Google's servers directly.
 * Google explicitly supports this for extensions and security tools.
 * Privacy implication: Google sees the URLs you check. This MUST be
 * disclosed in your privacy policy (which we will do in Milestone 6).
 *
 * API ENDPOINT:
 *   POST https://safebrowsing.googleapis.com/v4/threatMatches:find
 *
 * THREAT TYPES WE CHECK:
 *   MALWARE, SOCIAL_ENGINEERING (phishing), UNWANTED_SOFTWARE,
 *   POTENTIALLY_HARMFUL_APPLICATION
 *
 * CACHING STRATEGY:
 *   GSB results are cached for 1 hour in chrome.storage.local.
 *   The GSB API spec recommends a minimum cache duration of 30 minutes.
 *   We use 1 hour to reduce API quota usage.
 *   Negative results (safe) are also cached — most revisited URLs are safe.
 *
 * API KEY STRATEGY (Milestone 1 → V2 migration path):
 *   MVP: API key stored in config, sent directly from extension.
 *       Risk is low — GSB keys have usage quotas and aren't secret.
 *       Set quota limits in Google Cloud Console.
 *   V2: Route through your own backend → key never leaves your server.
 *       Requires only changing GSB_ENDPOINT constant below.
 *
 * RATE LIMITING:
 *   Free tier: 10,000 requests/day
 *   We mitigate with: caching + deduplication + skip for allowlisted domains
 *   At 100 daily active users visiting 20 pages each = 2000 uncached checks/day
 *   Well within free tier for early launch.
 */

import { cacheGet, cacheSet, cacheKey, CACHE_TTL } from '../cache/store.js'

// ─── Configuration ────────────────────────────────────────────────────────────
//
// HOW TO GET YOUR GSB API KEY:
//   1. Go to console.cloud.google.com
//   2. Create a project (or use existing)
//   3. Enable "Safe Browsing API"
//   4. Create credentials → API Key
//   5. Set API restrictions: only allow "Safe Browsing API"
//   6. Set quota: Applications → default 10,000/day
//   7. Replace the empty string below with your key
//
// IMPORTANT: For Milestone 1 testing without a key, the layer degrades
// gracefully — returns null and the heuristic layers still run.
//
const GSB_API_KEY = '' // ← paste your key here

const GSB_ENDPOINT =
  `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_API_KEY}`

// Threat types to check against — covers phishing, malware, and PUAs
const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',        // This is the phishing category
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
]

// Platform types — we check all
const PLATFORM_TYPES = ['ANY_PLATFORM']

// Entry types — URL is what we're submitting
const THREAT_ENTRY_TYPES = ['URL']

// Request timeout — GSB is usually fast but we don't want to block
const REQUEST_TIMEOUT_MS = 3000

// ─── Main Export ─────────────────────────────────────────────────────────────

/**
 * Check a URL against Google Safe Browsing.
 *
 * @param {string} url — the full URL to check
 * @returns {Promise<GSBResult|null>}
 *
 * @typedef {object} GSBResult
 * @property {boolean} isPhishing — true if URL is a known threat
 * @property {string|null} threatType — e.g., 'SOCIAL_ENGINEERING'
 * @property {boolean} fromCache — true if result came from cache
 */
export async function checkGSB(url) {
  // Skip if no API key configured — degrade gracefully
  if (!GSB_API_KEY) {
    return null
  }

  // Normalize URL for consistent cache keys
  const normalizedUrl = normalizeUrl(url)
  if (!normalizedUrl) return null

  const key = cacheKey('gsb', normalizedUrl)

  // ── Cache check ──────────────────────────────────────────────────────────
  const cached = await cacheGet(key)
  if (cached !== null) {
    return { ...cached, fromCache: true }
  }

  // ── API call ─────────────────────────────────────────────────────────────
  const result = await fetchGSB(normalizedUrl)

  // Cache both positive and negative results
  // Caching negatives is important — avoids re-checking safe pages on every visit
  if (result !== null) {
    await cacheSet(key, result, CACHE_TTL.GSB_RESULT)
  }

  return result
}

// ─── API Call ─────────────────────────────────────────────────────────────────

/**
 * Make the actual GSB API request.
 * Returns null on any error — errors must never surface to the user.
 *
 * @param {string} url
 * @returns {Promise<{isPhishing: boolean, threatType: string|null}|null>}
 */
async function fetchGSB(url) {
  const requestBody = {
    client: {
      clientId:      'phishguard-extension',
      clientVersion: '0.1.0',
    },
    threatInfo: {
      threatTypes:      THREAT_TYPES,
      platformTypes:    PLATFORM_TYPES,
      threatEntryTypes: THREAT_ENTRY_TYPES,
      threatEntries:    [{ url }],
    },
  }

  try {
    const controller = new AbortController()
    const timeoutId  = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)

    const response = await fetch(GSB_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(requestBody),
      signal:  controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      // 400 = bad request (malformed URL), 403 = bad API key, 429 = quota exceeded
      console.warn(`[PhishGuard] GSB API error: ${response.status} ${response.statusText}`)
      return null
    }

    const data = await response.json()

    // GSB returns empty object {} if URL is safe (no matches)
    // Returns { matches: [...] } if threat found
    if (!data.matches || data.matches.length === 0) {
      return { isPhishing: false, threatType: null }
    }

    // Extract the most severe threat type from matches
    const threatType = extractPrimaryThreat(data.matches)

    return {
      isPhishing: true,
      threatType,
      // Include match details for UI display
      matchCount: data.matches.length,
    }

  } catch (err) {
    if (err.name === 'AbortError') {
      console.warn('[PhishGuard] GSB request timed out')
    } else {
      console.warn('[PhishGuard] GSB request failed:', err.message)
    }
    // Always return null on error — heuristic layers handle it
    return null
  }
}

// ─── URL Normalization ────────────────────────────────────────────────────────

/**
 * Normalize a URL before sending to GSB.
 *
 * GSB requires URLs in a specific canonical form.
 * Key steps: lowercase hostname, remove fragments, resolve path.
 *
 * Full GSB canonicalization spec:
 * https://developers.google.com/safe-browsing/v4/urls-hashing
 *
 * We implement a simplified version sufficient for the Lookup API.
 *
 * @param {string} rawUrl
 * @returns {string|null}
 */
function normalizeUrl(rawUrl) {
  try {
    const url = new URL(rawUrl)

    // Lowercase the hostname
    url.hostname = url.hostname.toLowerCase()

    // Remove fragment — GSB doesn't check fragments
    url.hash = ''

    // Remove default ports
    if ((url.protocol === 'http:'  && url.port === '80') ||
        (url.protocol === 'https:' && url.port === '443')) {
      url.port = ''
    }

    return url.toString()
  } catch {
    return null
  }
}

// ─── Threat Priority ──────────────────────────────────────────────────────────

/**
 * Extract the most relevant threat type from a list of GSB matches.
 * Prioritizes phishing (SOCIAL_ENGINEERING) over malware for our use case.
 *
 * @param {Array} matches — GSB match objects
 * @returns {string} threat type label
 */
function extractPrimaryThreat(matches) {
  const priority = [
    'SOCIAL_ENGINEERING',             // phishing — most relevant to us
    'MALWARE',                        // malware — also critical
    'UNWANTED_SOFTWARE',
    'POTENTIALLY_HARMFUL_APPLICATION',
  ]

  for (const type of priority) {
    if (matches.some(m => m.threatType === type)) {
      return type
    }
  }

  // Fallback to first match type
  return matches[0]?.threatType || 'UNKNOWN_THREAT'
}

// ─── Threat Type → Human Label ────────────────────────────────────────────────

/**
 * Convert a GSB threat type string to a human-readable label.
 * Used in the popup and interstitial UI.
 *
 * @param {string} threatType
 * @returns {string}
 */
export function threatTypeLabel(threatType) {
  const labels = {
    'SOCIAL_ENGINEERING':             'Known phishing site (Google Safe Browsing)',
    'MALWARE':                        'Known malware distribution site (Google Safe Browsing)',
    'UNWANTED_SOFTWARE':              'Distributes unwanted software (Google Safe Browsing)',
    'POTENTIALLY_HARMFUL_APPLICATION':'Contains potentially harmful content (Google Safe Browsing)',
    'UNKNOWN_THREAT':                 'Known dangerous site (Google Safe Browsing)',
  }
  return labels[threatType] || 'Known threat (Google Safe Browsing)'
}
