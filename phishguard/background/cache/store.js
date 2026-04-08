/**
 * cache/store.js
 *
 * A TTL-aware key-value store backed by chrome.storage.local.
 * Every value is wrapped with a timestamp so we can expire it.
 *
 * Why chrome.storage.local and not in-memory?
 * Service workers in MV3 are EPHEMERAL — they spin down after ~30s
 * of inactivity. Any module-level variable you set will be GONE the
 * next time the service worker wakes up. chrome.storage.local persists
 * across service worker restarts.
 */

export const CACHE_TTL = {
  GSB_RESULT:       1  * 60 * 60 * 1000,   // 1 hour
  DOMAIN_INTEL:     24 * 60 * 60 * 1000,   // 24 hours
  CONTENT_ANALYSIS: 30 * 60 * 1000,        // 30 minutes
  URL_ANALYSIS:     30 * 60 * 1000,        // 30 minutes
  USER_VISIT:       Infinity,              // permanent
}

/**
 * Retrieve a cached value. Returns null if missing or expired.
 * @param {string} key
 * @returns {Promise<any|null>}
 */
export async function cacheGet(key) {
  try {
    const result = await chrome.storage.local.get(key)
    const entry = result[key]

    if (!entry) return null

    // Check expiry — Infinity TTL entries never expire
    if (entry.expiresAt !== Infinity && Date.now() > entry.expiresAt) {
      // Expired — clean it up asynchronously, don't block
      chrome.storage.local.remove(key).catch(() => {})
      return null
    }

    return entry.value
  } catch (err) {
    console.warn('[PhishGuard] Cache read error:', err)
    return null
  }
}

/**
 * Store a value with a TTL.
 * @param {string} key
 * @param {any} value
 * @param {number} ttlMs  — use CACHE_TTL constants
 */
export async function cacheSet(key, value, ttlMs) {
  try {
    const expiresAt = ttlMs === Infinity ? Infinity : Date.now() + ttlMs
    await chrome.storage.local.set({
      [key]: { value, expiresAt, cachedAt: Date.now() }
    })
  } catch (err) {
    console.warn('[PhishGuard] Cache write error:', err)
  }
}

/**
 * Remove a specific key from cache.
 * @param {string} key
 */
export async function cacheDelete(key) {
  try {
    await chrome.storage.local.remove(key)
  } catch (err) {
    console.warn('[PhishGuard] Cache delete error:', err)
  }
}

/**
 * Build a namespaced cache key.
 * Format: "cache:{namespace}:{normalizedValue}"
 * e.g., "cache:gsb:https://example.com"
 */
export function cacheKey(namespace, value) {
  return `cache:${namespace}:${value}`
}

/**
 * Increment a user visit counter for a given hostname.
 * Used by the scorer to give a trust bonus to frequently visited sites.
 * @param {string} hostname
 * @returns {Promise<number>} new visit count
 */
export async function incrementVisitCount(hostname) {
  const key = cacheKey('visits', hostname)
  const current = await cacheGet(key) || 0
  const next = current + 1
  await cacheSet(key, next, Infinity)
  return next
}

/**
 * Get visit count for a hostname.
 * @param {string} hostname
 * @returns {Promise<number>}
 */
export async function getVisitCount(hostname) {
  const key = cacheKey('visits', hostname)
  return (await cacheGet(key)) || 0
}

/**
 * Add a domain to the user's personal whitelist.
 * Whitelisted domains always return SAFE, regardless of signals.
 * @param {string} hostname
 */
export async function addToWhitelist(hostname) {
  const key = cacheKey('whitelist', hostname)
  await cacheSet(key, true, Infinity)
}

/**
 * Check if a domain is in the user's personal whitelist.
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
export async function isWhitelisted(hostname) {
  const key = cacheKey('whitelist', hostname)
  return (await cacheGet(key)) === true
}
