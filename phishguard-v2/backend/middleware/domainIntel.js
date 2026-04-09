/**
 * backend/middleware/domainIntel.js
 *
 * Server-side domain intelligence.
 * Server-side caching means ALL users share one cache entry per domain —
 * cache hit rate is dramatically higher than per-user extension caching.
 *
 * In V2 the backend handles RDAP + crt.sh (extension still does Tranco
 * via its bundled JSON). The backend result is returned to the extension
 * alongside the ML score in a single API response.
 */

import { cache } from './cache.js'

const TIMEOUT_MS = {
  RDAP: 1500,
  CERT: 1200,
}

const TTL_MS = {
  DOMAIN_AGE: 24 * 60 * 60_000,  // 24 hours
  CERT_AGE:    6 * 60 * 60_000,  //  6 hours (certs renew more often)
}

// ── RDAP domain age ───────────────────────────────────────────────────────────

/**
 * Fetch domain registration age in days via RDAP.
 * @param {string} hostname  e.g. "paypa1.com" or "mail.evil.com"
 * @returns {Promise<number|null>}
 */
export async function rdapDomainAge(hostname) {
  const domain   = extractApexDomain(hostname)
  const cacheKey = `rdap:${domain}`

  const cached = await cache.get(cacheKey)
  if (cached !== null) return cached

  const result = await withTimeout(
    () => fetchRdap(domain),
    TIMEOUT_MS.RDAP,
    null,
  )

  // Cache even null results for a shorter window to avoid hammering RDAP
  await cache.set(cacheKey, result, result !== null ? TTL_MS.DOMAIN_AGE : 5 * 60_000)
  return result
}

async function fetchRdap(domain) {
  try {
    const res = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { headers: { 'Accept': 'application/json' } },
    )
    if (!res.ok) return null

    const data   = await res.json()
    const events = Array.isArray(data.events) ? data.events : []
    const regEvt = events.find(e => e.eventAction === 'registration')

    if (!regEvt?.eventDate) return null

    const registered = new Date(regEvt.eventDate)
    if (isNaN(registered.getTime())) return null

    const ageDays = Math.floor((Date.now() - registered.getTime()) / 86_400_000)
    return ageDays >= 0 ? ageDays : null

  } catch (err) {
    console.debug('[DomainIntel] RDAP fetch error:', err.message)
    return null
  }
}

// ── crt.sh certificate age ────────────────────────────────────────────────────

/**
 * Fetch age of the most recently issued SSL cert in days via crt.sh.
 * @param {string} hostname
 * @returns {Promise<number|null>}
 */
export async function certAge(hostname) {
  const domain   = extractApexDomain(hostname)
  const cacheKey = `cert:${domain}`

  const cached = await cache.get(cacheKey)
  if (cached !== null) return cached

  const result = await withTimeout(
    () => fetchCert(domain),
    TIMEOUT_MS.CERT,
    null,
  )

  await cache.set(cacheKey, result, result !== null ? TTL_MS.CERT_AGE : 5 * 60_000)
  return result
}

async function fetchCert(domain) {
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
    )
    if (!res.ok) return null

    const certs = await res.json()
    if (!Array.isArray(certs) || certs.length === 0) return null

    const newest = certs.reduce((latest, cert) => {
      const ct = new Date(cert.entry_timestamp).getTime()
      const lt = new Date(latest.entry_timestamp).getTime()
      return isNaN(ct) ? latest : ct > lt ? cert : latest
    })

    if (!newest?.entry_timestamp) return null

    const issuedAt = new Date(newest.entry_timestamp)
    if (isNaN(issuedAt.getTime())) return null

    const ageDays = Math.floor((Date.now() - issuedAt.getTime()) / 86_400_000)
    return ageDays >= 0 ? ageDays : null

  } catch (err) {
    console.debug('[DomainIntel] crt.sh fetch error:', err.message)
    return null
  }
}

// ── Utilities ──────────────────────────────────────────────────────────────────

/** Extract apex domain (eTLD+1) from a hostname. */
function extractApexDomain(hostname) {
  const parts = hostname.replace(/^www\./, '').split('.')
  const knownTwoPartTLDs = new Set([
    'co.uk','co.in','co.jp','com.au','com.br','org.uk','net.uk',
  ])
  if (parts.length >= 3) {
    const possible = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`
    if (knownTwoPartTLDs.has(possible)) {
      return `${parts[parts.length - 3]}.${possible}`
    }
  }
  return parts.length >= 2
    ? `${parts[parts.length - 2]}.${parts[parts.length - 1]}`
    : hostname
}

/**
 * Run an async fn with a timeout. Returns fallback on timeout or error.
 * @template T
 * @param {() => Promise<T>} fn
 * @param {number}           timeoutMs
 * @param {T}                fallback
 * @returns {Promise<T>}
 */
async function withTimeout(fn, timeoutMs, fallback) {
  let timer
  const timeoutPromise = new Promise(resolve => {
    timer = setTimeout(() => resolve(fallback), timeoutMs)
  })
  try {
    const result = await Promise.race([fn(), timeoutPromise])
    clearTimeout(timer)
    return result ?? fallback
  } catch {
    clearTimeout(timer)
    return fallback
  }
}
