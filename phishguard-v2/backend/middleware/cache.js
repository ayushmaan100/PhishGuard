/**
 * backend/middleware/cache.js
 *
 * TTL-aware cache layer.
 * Uses Redis when REDIS_URL is set, falls back to in-memory Map.
 *
 * GRACEFUL DEGRADATION:
 *   No Redis → in-memory cache (works fine for single-process deployment)
 *   Redis down → falls back to in-memory automatically
 *   Cache write fail → logged, never throws (cache is non-critical)
 *
 * WHY NOT TOP-LEVEL AWAIT FOR REDIS:
 *   Top-level await in ESM is valid, but dynamic Redis connection on
 *   module load makes testing hard and causes issues on some hosts.
 *   Instead: lazy connect on first use, with a connection promise.
 */

const inMemoryStore = new Map()

// ── Redis connection (lazy, optional) ─────────────────────────────────────────
let _redisClient   = null
let _connectPromise = null

async function getRedis() {
  if (_redisClient?.isReady) return _redisClient
  if (!process.env.REDIS_URL)  return null  // not configured

  if (_connectPromise) {
    try { await _connectPromise } catch { return null }
    return _redisClient?.isReady ? _redisClient : null
  }

  _connectPromise = (async () => {
    try {
      const { createClient } = await import('redis')
      _redisClient = createClient({ url: process.env.REDIS_URL })

      _redisClient.on('error', (err) => {
        if (err.code !== 'ECONNREFUSED') {
          console.warn('[Cache] Redis error:', err.message)
        }
      })

      await _redisClient.connect()
      console.log('[Cache] Redis connected')
    } catch (err) {
      console.log('[Cache] Redis unavailable, using in-memory cache:', err.message)
      _redisClient = null
    }
  })()

  try { await _connectPromise } catch { return null }
  return _redisClient?.isReady ? _redisClient : null
}

// ── Cache interface ────────────────────────────────────────────────────────────

export const cache = {

  /**
   * Get a cached value. Returns null if missing, expired, or on error.
   * @param {string} key
   * @returns {Promise<any|null>}
   */
  async get(key) {
    try {
      const redis = await getRedis()
      if (redis) {
        const raw = await redis.get(key)
        return raw ? JSON.parse(raw) : null
      }

      const entry = inMemoryStore.get(key)
      if (!entry) return null
      if (Date.now() > entry.expiresAt) {
        inMemoryStore.delete(key)
        return null
      }
      return entry.value

    } catch (err) {
      console.debug('[Cache] get error:', err.message)
      return null
    }
  },

  /**
   * Store a value with a TTL.
   * @param {string} key
   * @param {any}    value
   * @param {number} ttlMs  milliseconds (default 30 min)
   */
  async set(key, value, ttlMs = 30 * 60_000) {
    try {
      const redis = await getRedis()
      if (redis) {
        await redis.setEx(key, Math.max(1, Math.floor(ttlMs / 1000)), JSON.stringify(value))
        return
      }

      inMemoryStore.set(key, { value, expiresAt: Date.now() + ttlMs })

      // Passive eviction when store gets large (> 10K entries)
      if (inMemoryStore.size > 10_000) {
        const now = Date.now()
        for (const [k, v] of inMemoryStore) {
          if (v.expiresAt < now) inMemoryStore.delete(k)
        }
      }
    } catch (err) {
      console.debug('[Cache] set error:', err.message)
      // Cache write failures are always non-fatal
    }
  },

  /**
   * Delete a key.
   * @param {string} key
   */
  async del(key) {
    try {
      const redis = await getRedis()
      if (redis) await redis.del(key)
      else inMemoryStore.delete(key)
    } catch { /* non-fatal */ }
  },

  /** Current in-memory store size (for health checks). */
  size() { return inMemoryStore.size },

  /** Flush the entire in-memory store (tests only). */
  _flush() { inMemoryStore.clear() },
}
