/**
 * background/api/client.js
 *
 * Shared HTTP client utility used by all API-calling layers.
 *
 * Provides:
 *   - fetchWithTimeout: wraps fetch with AbortController timeout
 *   - retryFetch: exponential backoff for transient failures
 *
 * Design: all external HTTP calls go through these utilities.
 * This gives us a single place to add:
 *   - Request logging (dev mode)
 *   - Global rate limiting
 *   - Error normalization
 */

/**
 * Fetch a URL with a hard timeout.
 * On timeout, throws an AbortError (name === 'AbortError').
 * On other failure, throws the original error.
 *
 * @param {string} url
 * @param {RequestInit & { timeout?: number }} options
 * @returns {Promise<Response>}
 */
export async function fetchWithTimeout(url, options = {}) {
  const { timeout = 3000, ...fetchOptions } = options

  const controller = new AbortController()
  const timeoutId  = setTimeout(() => controller.abort(), timeout)

  try {
    const response = await fetch(url, {
      ...fetchOptions,
      signal: controller.signal,
    })
    return response
  } finally {
    clearTimeout(timeoutId)
  }
}

/**
 * Fetch with automatic retry on transient failures (5xx, network errors).
 * Uses exponential backoff: 200ms, 400ms, 800ms.
 *
 * Does NOT retry on:
 *   - 4xx errors (client errors — retrying won't help)
 *   - AbortError (timeout — retrying would compound the delay)
 *
 * @param {string} url
 * @param {RequestInit & { timeout?: number }} options
 * @param {number} maxRetries — default 2
 * @returns {Promise<Response>}
 */
export async function retryFetch(url, options = {}, maxRetries = 2) {
  let lastError

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetchWithTimeout(url, options)

      // Don't retry client errors
      if (response.status >= 400 && response.status < 500) {
        return response
      }

      // Retry server errors (5xx)
      if (response.status >= 500 && attempt < maxRetries) {
        await sleep(200 * Math.pow(2, attempt)) // 200ms, 400ms, 800ms
        continue
      }

      return response
    } catch (err) {
      lastError = err

      // Don't retry timeouts
      if (err.name === 'AbortError') throw err

      if (attempt < maxRetries) {
        await sleep(200 * Math.pow(2, attempt))
        continue
      }
    }
  }

  throw lastError
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}
