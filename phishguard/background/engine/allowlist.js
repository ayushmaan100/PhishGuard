/**
 * engine/allowlist.js
 *
 * Maintains a Set of trusted top-10K domains for instant SAFE verdicts.
 *
 * Why bundle the allowlist in the extension rather than fetching it?
 * 1. Zero latency — Set.has() is O(1), no async needed
 * 2. Works offline
 * 3. No network call on every navigation
 *
 * The full tranco-10k.json is loaded ONCE when the service worker
 * starts up, and held in a module-level Set. This is safe because
 * we're reading it at startup (not storing detection state here).
 *
 * We extract the eTLD+1 (registered domain) for comparison.
 * e.g., "mail.google.com" → "google.com" → in allowlist → SAFE
 */

let allowlistSet = null
let loadPromise = null

/**
 * Load the allowlist from bundled JSON. Called once at startup.
 * Subsequent calls return the cached promise.
 */
export async function loadAllowlist() {
  if (allowlistSet) return allowlistSet
  if (loadPromise) return loadPromise

  loadPromise = (async () => {
    try {
      const url = chrome.runtime.getURL('assets/data/tranco-10k.json')
      const response = await fetch(url)
      const domains = await response.json() // array of domain strings
      allowlistSet = new Set(domains)
      console.log(`[PhishGuard] Allowlist loaded: ${allowlistSet.size} trusted domains`)
      return allowlistSet
    } catch (err) {
      console.error('[PhishGuard] Failed to load allowlist:', err)
      allowlistSet = new Set() // fail open — empty set, nothing is allowlisted
      return allowlistSet
    }
  })()

  return loadPromise
}

/**
 * Check if a URL's registered domain is in the trusted allowlist.
 *
 * @param {string} url — full URL string
 * @returns {boolean}
 */
export function isAllowlisted(url) {
  if (!allowlistSet) {
    // Allowlist not loaded yet — fail open (don't block on this)
    return false
  }

  try {
    const hostname = new URL(url).hostname
    const registered = extractRegisteredDomain(hostname)
    return allowlistSet.has(registered)
  } catch {
    return false
  }
}

/**
 * Extract the registered domain (eTLD+1) from a hostname.
 *
 * This is a simplified implementation. A production system would use
 * the Public Suffix List (via tldts library). For Milestone 1, this
 * handles the vast majority of cases correctly.
 *
 * Examples:
 *   "mail.google.com"     → "google.com"
 *   "sub.domain.co.uk"    → "domain.co.uk"
 *   "paypal.com"          → "paypal.com"
 *   "192.168.1.1"         → "192.168.1.1" (IP, returned as-is)
 *
 * @param {string} hostname
 * @returns {string}
 */
export function extractRegisteredDomain(hostname) {
  // Handle IP addresses
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return hostname
  }

  const parts = hostname.split('.')

  // Handle known two-part TLDs like co.uk, com.au, co.in
  const knownTwoPartTLDs = new Set([
    'co.uk', 'co.in', 'co.jp', 'co.nz', 'co.za', 'co.kr',
    'com.au', 'com.br', 'com.mx', 'com.sg', 'com.ar',
    'org.uk', 'net.uk', 'gov.uk', 'ac.uk',
  ])

  if (parts.length >= 3) {
    const possibleTwoPartTLD = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`
    if (knownTwoPartTLDs.has(possibleTwoPartTLD)) {
      // eTLD+1 = the part before the two-part TLD
      return `${parts[parts.length - 3]}.${possibleTwoPartTLD}`
    }
  }

  // Standard case: take last two parts
  if (parts.length >= 2) {
    return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`
  }

  return hostname
}
