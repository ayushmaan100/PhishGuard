/**
 * layers/layer2a-domain.js
 *
 * Layer 2A: Domain Intelligence
 *
 * Three parallel checks, each with 800ms hard timeout:
 *
 *   1. Domain Age    via RDAP (rdap.org) — free, no key, ICANN-standard
 *   2. Cert Age      via crt.sh          — free, no key, CT log query
 *   3. Tranco Rank   via bundled JSON    — zero latency, top 10K
 *
 * WHY THESE SIGNALS CATCH ZERO-DAY PHISHING:
 *   Phishing infrastructure is always new. A domain registered yesterday,
 *   with a cert issued today, and no Tranco ranking is a strong fingerprint
 *   of disposable phishing infrastructure — even when the URL looks innocent.
 *
 * OUTPUT CONTRACT (matches scorer.js domain signal expectations):
 *   { age_days: number|null, cert_age_days: number|null, tranco_rank: number|null }
 */

import { cacheGet, cacheSet, cacheKey, CACHE_TTL } from '../cache/store.js'
import { extractRegisteredDomain }                  from '../engine/allowlist.js'

const TIMEOUT_MS = 800

// ─── Main Export ─────────────────────────────────────────────────────────────

export async function checkDomainIntel(url) {
  let hostname
  try {
    hostname = new URL(url).hostname
  } catch {
    return nullResult()
  }

  const domain = extractRegisteredDomain(hostname)
  const key    = cacheKey('domain_intel', domain)
  const cached = await cacheGet(key)
  if (cached !== null) return { ...cached, fromCache: true }

  // All three run in parallel — total wait = slowest of the three
  const [ageResult, certResult, trancoResult] = await Promise.allSettled([
    getDomainAge(domain),
    getCertAge(domain),
    getTrancoRank(domain),
  ])

  const result = {
    age_days:      ageResult.status  === 'fulfilled' ? ageResult.value  : null,
    cert_age_days: certResult.status === 'fulfilled' ? certResult.value : null,
    tranco_rank:   trancoResult.status === 'fulfilled' ? trancoResult.value : null,
    checkedAt:     Date.now(),
  }

  // Only cache if we got at least one real data point
  // Don't cache all-null (all APIs timed out) — retry next visit
  const hasData = result.age_days !== null ||
                  result.cert_age_days !== null ||
                  result.tranco_rank !== null

  if (hasData) await cacheSet(key, result, CACHE_TTL.DOMAIN_INTEL)

  return result
}

// ─── 1. Domain Age via RDAP ───────────────────────────────────────────────────

/**
 * RDAP is the modern ICANN-standard replacement for WHOIS.
 * rdap.org is a free public proxy that routes to each registrar's RDAP server.
 * Returns structured JSON — no brittle text parsing needed.
 *
 * We look for the 'registration' event date in the events array.
 */
async function getDomainAge(domain) {
  try {
    const res = await fetchWithTimeout(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { headers: { 'Accept': 'application/json' } }
    )
    if (!res.ok) return null

    const data   = await res.json()
    const events = data.events || []
    const regEvt = events.find(e => e.eventAction === 'registration')

    if (!regEvt?.eventDate) return null

    const registered = new Date(regEvt.eventDate)
    if (isNaN(registered.getTime())) return null

    const ageDays = Math.floor((Date.now() - registered.getTime()) / 86_400_000)
    return ageDays >= 0 ? ageDays : null

  } catch (err) {
    if (err.name !== 'AbortError') console.debug('[PhishGuard] RDAP:', err.message)
    return null
  }
}

// ─── 2. Certificate Age via crt.sh ───────────────────────────────────────────

/**
 * crt.sh queries Certificate Transparency logs.
 * Every publicly trusted SSL cert is logged here.
 * Run by Sectigo — free, reliable, no auth.
 *
 * We find the most recently issued cert and compute its age.
 * A cert issued in the last 3 days on a login page = major red flag.
 * Legitimate businesses don't get new certs daily.
 */
async function getCertAge(domain) {
  try {
    const res = await fetchWithTimeout(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`
    )
    if (!res.ok) return null

    const certs = await res.json()
    if (!Array.isArray(certs) || certs.length === 0) return null

    // Find the most recently logged certificate
    const newest = certs.reduce((latest, cert) => {
      const ct = new Date(cert.entry_timestamp).getTime()
      const lt = new Date(latest.entry_timestamp).getTime()
      return ct > lt ? cert : latest
    })

    if (!newest?.entry_timestamp) return null

    const issuedAt = new Date(newest.entry_timestamp)
    if (isNaN(issuedAt.getTime())) return null

    const ageDays = Math.floor((Date.now() - issuedAt.getTime()) / 86_400_000)
    return ageDays >= 0 ? ageDays : null

  } catch (err) {
    if (err.name !== 'AbortError') console.debug('[PhishGuard] crt.sh:', err.message)
    return null
  }
}

// ─── 3. Tranco Rank via Bundled JSON ─────────────────────────────────────────

// Module-level rank map — safe to cache since it's static reference data
let trancoMap = null
let trancoLoadPromise = null

/**
 * Get the Tranco top-site rank for a domain.
 * 1 = most popular globally, 10000 = boundary of bundled list.
 * Returns null for anything outside the top 10K.
 *
 * Tranco combines Alexa, Majestic, Umbrella and Quantcast for a stable,
 * manipulation-resistant ranking. Much better signal than Alexa alone.
 *
 * The bundled JSON is an ordered array — index + 1 = rank.
 * Zero API calls, zero network latency after first load.
 */
async function getTrancoRank(domain) {
  try {
    const map = await loadTrancoMap()
    if (!map) return null

    // Try exact domain
    if (map[domain] !== undefined) return map[domain]

    // Try without www prefix
    const bare = domain.replace(/^www\./, '')
    if (map[bare] !== undefined) return map[bare]

    return null  // Not in top 10K
  } catch {
    return null
  }
}

async function loadTrancoMap() {
  if (trancoMap) return trancoMap
  if (trancoLoadPromise) return trancoLoadPromise

  trancoLoadPromise = (async () => {
    try {
      const url      = chrome.runtime.getURL('assets/data/tranco-10k.json')
      const response = await fetch(url)
      const domains  = await response.json()  // ordered array

      // Build rank map: { "google.com": 1, "youtube.com": 2, ... }
      const map = {}
      domains.forEach((d, i) => { map[d] = i + 1 })

      trancoMap = map
      return trancoMap
    } catch (err) {
      console.warn('[PhishGuard] Tranco load failed:', err)
      return null
    }
  })()

  return trancoLoadPromise
}

// ─── Utilities ────────────────────────────────────────────────────────────────

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController()
  const timeoutId  = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } finally {
    clearTimeout(timeoutId)
  }
}

function nullResult() {
  return { age_days: null, cert_age_days: null, tranco_rank: null }
}
