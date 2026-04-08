/**
 * engine/orchestrator.js
 *
 * The detection pipeline orchestrator.
 *
 * Coordinates all detection layers in the correct sequence:
 *   0. Allowlist check (instant)
 *   1. User whitelist check (instant)
 *   1B. URL heuristics (synchronous, <5ms) → emit preliminary verdict
 *   1A. Google Safe Browsing (async, ~100ms) — added in Milestone 3
 *   2A. Domain intelligence (async, ~300ms) — added in Milestone 4
 *   2B. Content script analysis (message-based) — added in Milestone 5
 *   Final. Aggregate all signals → emit final verdict
 *
 * In Milestone 1, only the skeleton and URL heuristics run.
 * Stubs are in place for all future layers so the architecture
 * is correct from day one.
 */

import { isAllowlisted }                from './allowlist.js'
import { isWhitelisted, getVisitCount } from '../cache/store.js'
import { analyzeURL }                   from '../layers/layer1b-url.js'
import { aggregateScore, preliminaryVerdict } from './scorer.js'
import { extractRegisteredDomain }      from './allowlist.js'
import { checkGSB as gsbCheck }         from '../layers/layer1a-gsb.js'
import { checkDomainIntel as domainCheck } from '../layers/layer2a-domain.js'
import { checkML as mlCheck }              from '../layers/layer3-ml.js'

// Pending content script results, keyed by tabId.
// When the content script sends its analysis, we store it here
// so the orchestrator can pick it up when aggregating.
const pendingContentResults = new Map()

// Active analysis promises, keyed by tabId.
// Prevents duplicate analyses if multiple navigation events fire.
const activeAnalyses = new Map()

/**
 * Main entry point — analyze a URL for a given tab.
 *
 * Emits results via the onResult callback at two points:
 *   1. Preliminary verdict (fast, from URL heuristics only)
 *   2. Final verdict (after all available layers complete)
 *
 * @param {string}   url
 * @param {number}   tabId
 * @param {function} onResult — called with (tabId, result) on each verdict
 */
export async function analyzeNavigation(url, tabId, onResult) {
  // Cancel any in-progress analysis for this tab
  if (activeAnalyses.has(tabId)) {
    activeAnalyses.get(tabId).cancelled = true
  }

  const analysis = { cancelled: false }
  activeAnalyses.set(tabId, analysis)

  try {
    // ── Skip non-web URLs (chrome://, file://, about:, extensions, etc.) ──
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      onResult(tabId, { verdict: 'SAFE', score: 0, reasons: [], preliminary: false, skipped: true })
      return
    }

    // ── Step 0: Allowlist check ────────────────────────────────────────────
    if (isAllowlisted(url)) {
      onResult(tabId, {
        verdict:   'SAFE',
        score:     0,
        reasons:   ['Trusted domain (verified top site)'],
        firedSignals: [],
        preliminary: false,
        source:    'allowlist',
      })
      return
    }

    // ── Step 1: User personal whitelist ───────────────────────────────────
    const hostname = new URL(url).hostname
    const registered = extractRegisteredDomain(hostname)

    if (await isWhitelisted(registered)) {
      onResult(tabId, {
        verdict:   'SAFE',
        score:     0,
        reasons:   ['You have marked this site as trusted'],
        firedSignals: [],
        preliminary: false,
        source:    'user_whitelist',
      })
      return
    }

    // ── Step 1B: URL heuristics — synchronous, emit immediately ──────────
    const urlSignals  = analyzeURL(url)
    const visitCount  = await getVisitCount(registered)
    const preliminary = preliminaryVerdict(urlSignals)

    // Emit preliminary result immediately — badge updates within ~5ms
    onResult(tabId, { ...preliminary, preliminary: true, url })

    if (analysis.cancelled) return

    // ── Step 1A: Google Safe Browsing — Milestone 3 ───────────────────────
    // Stub: returns null for now. Layer is wired in — just no-ops.
    const gsbResult = await checkGSB(url)
    if (analysis.cancelled) return

    // If GSB says DANGEROUS, short-circuit immediately
    if (gsbResult?.isPhishing) {
      const finalResult = aggregateScore(
        { url: urlSignals, gsb: gsbResult, domain: null, content: null },
        visitCount
      )
      onResult(tabId, { ...finalResult, preliminary: false, url })
      return
    }

    // ── Steps 2A + 2B + 3: Run in parallel ──────────────────────────────────
    // Layer 2A (domain intel) + Layer 2B (content script) run simultaneously.
    // Layer 3 (ML backend) runs in parallel with the content script.
    // Content script result is sent to ML backend when available.
    const [domainResult, contentResult] = await Promise.allSettled([
      checkDomainIntel(url),
      waitForContentScript(tabId, 800),
    ])

    if (analysis.cancelled) return

    const domainData  = domainResult.status  === 'fulfilled' ? domainResult.value  : null
    const contentData = contentResult.status === 'fulfilled' ? contentResult.value : null

    // ── Layer 3: ML backend (V2) ───────────────────────────────────────────
    // Runs after content script is available so content signals enrich ML features.
    // Times out at 2.5s — extension never blocks waiting for backend.
    // Returns null if backend unreachable — heuristics still fire.
    const mlResult = await checkML(url, contentData).catch(() => null)

    if (analysis.cancelled) return

    // ── Final: Aggregate all signals ──────────────────────────────────────
    // If backend returned enriched domain intel, prefer it over
    // the extension's RDAP result (backend has shared cache).
    const finalDomainIntel = mlResult?.domainIntel ?? domainData

    const allSignals = {
      url:     urlSignals,
      gsb:     gsbResult,
      domain:  finalDomainIntel,
      content: contentData,
      ml:      mlResult,
    }

    const finalResult = aggregateScore(allSignals, visitCount)
    onResult(tabId, { ...finalResult, preliminary: false, url })

  } catch (err) {
    console.error('[PhishGuard] Analysis error:', err)
    // On unexpected error, fail open — show SAFE with a warning in dev mode
    onResult(tabId, {
      verdict:   'SAFE',
      score:     0,
      reasons:   [],
      firedSignals: [],
      preliminary: false,
      error:     err.message,
    })
  } finally {
    if (activeAnalyses.get(tabId) === analysis) {
      activeAnalyses.delete(tabId)
    }
  }
}

/**
 * Receive and store a content analysis result from a content script.
 * Called by the service worker's message listener.
 *
 * @param {number} tabId
 * @param {object} contentAnalysis
 */
export function receiveContentResult(tabId, contentAnalysis) {
  const pending = pendingContentResults.get(tabId)
  if (pending) {
    pending.resolve(contentAnalysis)
    pendingContentResults.delete(tabId)
  }
}

/**
 * Wait for the content script to send its analysis for a given tab.
 * Resolves when the result arrives or when the timeout fires.
 *
 * @param {number} tabId
 * @param {number} timeoutMs — max wait time
 * @returns {Promise<object|null>}
 */
function waitForContentScript(tabId, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingContentResults.delete(tabId)
      resolve(null) // Timeout — no content result, proceed without it
    }, timeoutMs)

    pendingContentResults.set(tabId, {
      resolve: (result) => {
        clearTimeout(timer)
        resolve(result)
      }
    })
  })
}

// ─── Layer Stubs (implemented in future milestones) ──────────────────────────

/**
 * Layer 1A: Google Safe Browsing check.
 * Fully implemented in Milestone 2.
 * Delegates to layer1a-gsb.js which handles API call, caching, and timeouts.
 */
async function checkGSB(url) {
  return gsbCheck(url)
}

/**
 * Layer 2A: Domain intelligence — RDAP age, crt.sh cert age, Tranco rank.
 * Fully implemented in Milestone 3.
 */
async function checkDomainIntel(url) {
  return domainCheck(url)
}

/**
 * Layer 3: ML backend scoring (V2).
 * Returns { mlScore, mlPoints, mlSignals, domainIntel } or null.
 */
async function checkML(url, contentData) {
  return mlCheck(url, contentData)
}
