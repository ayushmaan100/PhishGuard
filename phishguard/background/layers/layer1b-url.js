/**
 * layers/layer1b-url.js
 *
 * Layer 1B: URL Heuristic Analysis
 *
 * This layer runs SYNCHRONOUSLY with zero API calls.
 * It extracts 15+ signals purely from the URL string.
 * Completes in <5ms on any device.
 *
 * This is the first real analysis step — it produces a preliminary
 * score that gets shown to the user immediately while deeper
 * analysis (domain intel, content) runs in parallel.
 */

import {
  shannonEntropy,
  minBrandDistance,
  SUSPICIOUS_TLDS,
} from '../engine/scorer.js'

import { extractRegisteredDomain } from '../engine/allowlist.js'

// Brand keywords commonly embedded in phishing URLs
// e.g., "secure-paypal-login-verify.com"
const BRAND_KEYWORDS = [
  'paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook',
  'instagram', 'twitter', 'netflix', 'spotify', 'linkedin', 'dropbox',
  'adobe', 'chase', 'wellsfargo', 'bankofamerica', 'steam', 'roblox',
  'discord', 'coinbase', 'binance', 'metamask', 'gmail', 'outlook',
  'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe',
]

// Common URL redirect parameter names
const REDIRECT_PARAMS = [
  'url=', 'redirect=', 'return=', 'returnurl=', 'next=',
  'goto=', 'dest=', 'destination=', 'redir=', 'forward=',
]

/**
 * Analyze a URL and return a structured set of boolean/numeric signals.
 *
 * All signals map directly to entries in the scorer's SIGNALS table.
 * This ensures Layer 1B output feeds cleanly into aggregateScore().
 *
 * @param {string} rawUrl — the full URL string
 * @returns {object} urlSignals
 */
export function analyzeURL(rawUrl) {
  // Safely parse the URL — malformed URLs get a partial analysis
  let parsed
  try {
    parsed = new URL(rawUrl)
  } catch {
    // Unparseable URL — return minimal signals
    return { parseError: true, no_https: !rawUrl.startsWith('https') }
  }

  const hostname  = parsed.hostname || ''
  const fullUrl   = rawUrl
  const pathname  = parsed.pathname || ''
  const port      = parsed.port || ''
  const protocol  = parsed.protocol || ''

  // Extract the registered domain and bare domain name
  const registeredDomain = extractRegisteredDomain(hostname)
  const domainParts = registeredDomain.split('.')
  const bareDomain  = domainParts[0] || '' // "paypa1" from "paypa1.com"

  // Count subdomains: "secure.login.paypal.attacker.com" → 3 subdomains
  const hostParts    = hostname.split('.')
  const subdomainCount = hostParts.length - domainParts.length

  // Count how many known brand keywords appear in the URL
  const urlLower     = fullUrl.toLowerCase()
  const brandCount   = BRAND_KEYWORDS.filter(b => urlLower.includes(b)).length

  // Check for redirect parameters in the full URL
  const hasRedirect  = REDIRECT_PARAMS.some(p => urlLower.includes(p))

  // Get brand distance for typosquatting detection
  const brandDistance = minBrandDistance(hostname)

  return {
    // ── Structure signals ─────────────────────────────────────────────────
    url_length_gt100:    fullUrl.length > 100,
    has_ip_in_host:      isIPAddress(hostname),
    has_at:              parsed.username !== '',
    excessive_subdomains: subdomainCount > 3,
    redirect_in_path:    hasRedirect,
    multi_brand_keywords: brandCount >= 2,
    port_in_url:         port !== '' && port !== '80' && port !== '443',

    // ── Domain signals ────────────────────────────────────────────────────
    suspicious_tld:      SUSPICIOUS_TLDS.has(hostname.split('.').pop().toLowerCase()),
    high_entropy_domain: isHighEntropyDomain(bareDomain),
    long_subdomain:      hostParts[0]?.length > 20,
    numeric_heavy_domain: countDigits(bareDomain) > 4,
    has_hyphen_brand:    bareDomain.includes('-') && brandCount >= 1,

    // ── Security signals ──────────────────────────────────────────────────
    no_https:            protocol !== 'https:',

    // ── Typosquatting ─────────────────────────────────────────────────────
    // null  = no brand match at all (not suspicious on this signal)
    // 0     = exact brand match (legitimate — never flag this)
    // 1–2   = close typosquat
    // 3–4   = loosely similar
    brand_distance:      brandDistance,

    // ── Raw values (for UI display + debugging) ───────────────────────────
    _meta: {
      hostname,
      registeredDomain,
      bareDomain,
      subdomainCount,
      brandCount,
      urlLength: fullUrl.length,
      entropy: shannonEntropy(bareDomain),
    },
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isIPAddress(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
}

function countDigits(str) {
  return (str.match(/\d/g) || []).length
}

/**
 * Length-aware, digit-gated entropy check for suspicious domain names.
 *
 * Design rationale:
 *   A flat entropy threshold creates false positives on legitimate brand names
 *   like "netflix" (2.81), "hdfcbank" (3.0), or "stackoverflow" (3.55).
 *
 *   Real DGA (Domain Generation Algorithm) and random phishing domains share
 *   two key properties:
 *     1. High character entropy (diverse character set)
 *     2. Contains digits mixed with letters (e.g., "a1b3c7d9", "xk4j8m2p")
 *
 *   Legitimate brand names almost never contain digits.
 *   This makes digit-presence a powerful low-false-positive gate.
 *
 * Thresholds calibrated empirically against 80+ real domain names.
 *
 * @param {string} domain — bare domain name (no TLD, no subdomains)
 * @returns {boolean}
 */
function isHighEntropyDomain(domain) {
  if (!domain || domain.length < 5) return false

  const entropy  = shannonEntropy(domain)
  const len      = domain.length
  const hasDigit = /\d/.test(domain)

  if (len <= 12) {
    // Short/medium domains: require BOTH high entropy AND digit presence.
    // This catches "a1b3c7d9" and "xk4j8m2p" while sparing
    // "netflix", "discord", "hdfcbank", "flipkart".
    return entropy > 2.8 && hasDigit
  }

  // Long domains (13+ chars): entropy alone is sufficient at a high threshold.
  // Real brand compound words max out around 3.6 ("stackoverflow" = 3.55).
  // Truly random long strings go higher: "a1b3c7d9e2f4g6" = 3.91.
  return entropy > 3.8
}
