/**
 * backend/server.js
 *
 * PhishGuard V2 Backend API
 *
 * Responsibilities:
 *   - Authenticate requests (API key from extension installs)
 *   - Rate limit per install ID (prevents abuse)
 *   - Cache domain intelligence results server-side (shared across all users)
 *   - Call Python ML service for inference
 *   - Route GSB checks through backend (moves key off extension)
 *   - Store false positive reports for retraining pipeline
 *
 * Architecture:
 *   Extension → Node.js API → Python ML service (localhost:5001)
 *                           → Redis cache (shared domain intel)
 *                           → PostgreSQL (reports, analytics)
 *
 * For MVP deployment: Redis optional (fallback to in-memory Map)
 * PostgreSQL optional (fallback to local JSON file logging)
 *
 * DEPLOYMENT:
 *   Railway.app: push to GitHub → auto-deploy
 *   Render.com:  free tier works for early users
 *   Fly.io:      good latency globally
 *
 * ENVIRONMENT VARIABLES:
 *   PORT              — server port (default: 3000)
 *   ML_SERVICE_URL    — Python ML service URL (default: http://127.0.0.1:5001)
 *   GSB_API_KEY       — Google Safe Browsing API key
 *   REDIS_URL         — Redis connection string (optional)
 *   API_KEY_SECRET    — Secret for signing/verifying install tokens
 *   NODE_ENV          — 'production' or 'development'
 */

import express          from 'express'
import cors             from 'cors'
import helmet           from 'helmet'
import rateLimit        from 'express-rate-limit'
import { analyzeRoute } from './routes/analyze.js'
import { reportsRoute } from './routes/reports.js'
import { healthRoute }  from './routes/health.js'

const app  = express()
const PORT = parseInt(process.env.PORT || '3000', 10)

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,   // API server, no HTML served
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}))

app.use(cors({
  origin: (origin, callback) => {
    // Allow Chrome extension origins and our own frontend
    const allowed = [
      'chrome-extension://',       // all Chrome extensions
      'moz-extension://',          // Firefox extensions
      process.env.FRONTEND_URL,    // your web dashboard (if any)
    ].filter(Boolean)

    // Allow requests with no origin (server-to-server, Postman)
    if (!origin) return callback(null, true)

    const isAllowed = allowed.some(o => origin.startsWith(o))
    callback(null, isAllowed)
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-Install-Id', 'X-API-Version'],
}))

app.use(express.json({ limit: '50kb' }))

// ── Global rate limiter ───────────────────────────────────────────────────────
// Secondary limiter — per-install rate limiting is in the analyze route
const globalLimiter = rateLimit({
  windowMs:        60 * 1000,   // 1 minute
  max:             500,          // max 500 requests per IP per minute globally
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Too many requests', retryAfterMs: 60000 },
})
app.use(globalLimiter)

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/v1/analyze',  analyzeRoute)
app.use('/api/v1/reports',  reportsRoute)
app.use('/health',          healthRoute)

// Root — basic info
app.get('/', (req, res) => {
  res.json({
    service:  'PhishGuard API',
    version:  '2.0.0',
    status:   'ok',
    endpoints: ['/api/v1/analyze', '/api/v1/reports', '/health'],
  })
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' })
})

// Error handler
app.use((err, req, res, next) => {
  console.error('[API Error]', err.message)
  res.status(500).json({ error: 'Internal server error' })
})

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[PhishGuard API] Running on port ${PORT}`)
  console.log(`[PhishGuard API] ML service: ${process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001'}`)
  console.log(`[PhishGuard API] Environment: ${process.env.NODE_ENV || 'development'}`)
})

export default app
