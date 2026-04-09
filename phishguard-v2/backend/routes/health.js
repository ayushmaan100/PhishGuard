/**
 * backend/routes/health.js
 * GET /health
 * Used by Railway/Render for health checks and by the extension
 * to verify backend availability before sending analysis requests.
 */

import express from 'express'
import { cache } from '../middleware/cache.js'

const router = express.Router()
const ML_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001'

router.get('/', async (req, res) => {
  const t0 = Date.now()
  let mlStatus  = 'unreachable'
  let mlVersion = null
  let mlThreshold = null

  try {
    const controller = new AbortController()
    const timer      = setTimeout(() => controller.abort(), 1000)
    const mlRes = await fetch(`${ML_URL}/health`, { signal: controller.signal })
    clearTimeout(timer)

    if (mlRes.ok) {
      const data  = await mlRes.json()
      mlStatus    = 'ok'
      mlVersion   = data.model_version ?? null
      mlThreshold = data.threshold      ?? null
    } else {
      mlStatus = 'degraded'
    }
  } catch {
    mlStatus = 'unreachable'
  }

  const overallOk = mlStatus === 'ok'

  res.status(overallOk ? 200 : 206).json({
    status:       overallOk ? 'ok' : 'degraded',
    api:          'ok',
    ml:           mlStatus,
    mlVersion,
    mlThreshold,
    cacheSize:    cache.size(),
    uptime:       Math.floor(process.uptime()),
    memoryMB:     Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    latency_ms:   Date.now() - t0,
    timestamp:    new Date().toISOString(),
  })
})

export const healthRoute = router
