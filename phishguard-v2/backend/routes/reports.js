/**
 * backend/routes/reports.js
 * POST /api/v1/reports
 *
 * Receives false positive reports from the extension.
 * Stored as JSONL for easy batch processing by the retraining pipeline.
 * Each line = one JSON record = one training signal.
 *
 * The retraining script reads this file, assigns label=0 (legit) to
 * all reported URLs, and includes them in the next training run.
 */

import express from 'express'
import fs      from 'fs/promises'
import path    from 'path'
import crypto  from 'crypto'

const router = express.Router()
const REPORTS_FILE = process.env.REPORTS_FILE
  || path.join(process.cwd(), 'data', 'reports.jsonl')

router.post('/', async (req, res) => {
  try {
    const { url, verdict, score, firedSignals, reasons, installId } = req.body ?? {}

    if (!url || typeof url !== 'string' || url.length > 2048) {
      return res.status(400).json({ error: 'valid url required' })
    }

    const report = {
      id:          crypto.randomUUID(),
      url:         url.trim(),
      verdict:     typeof verdict === 'string' ? verdict : 'UNKNOWN',
      score:       typeof score   === 'number' ? score   : null,
      firedSignals:Array.isArray(firedSignals) ? firedSignals.slice(0, 30) : [],
      reasons:     Array.isArray(reasons)      ? reasons.slice(0, 10)      : [],
      // Never store raw install ID — only a short hash for dedup
      installHash: installId
        ? crypto.createHash('sha256').update(String(installId)).digest('hex').slice(0, 12)
        : null,
      reportType:  'false_positive',
      reportedAt:  new Date().toISOString(),
    }

    // Ensure directory exists
    await fs.mkdir(path.dirname(REPORTS_FILE), { recursive: true })
    await fs.appendFile(REPORTS_FILE, JSON.stringify(report) + '\n', 'utf8')

    console.log(`[Reports] Saved: ${url.slice(0, 60)} (verdict was ${report.verdict})`)
    return res.json({ ok: true, id: report.id })

  } catch (err) {
    console.error('[Reports] Error:', err.message)
    return res.status(500).json({ error: 'Failed to save report' })
  }
})

export const reportsRoute = router
