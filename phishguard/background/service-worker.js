/**
 * background/service-worker.js
 *
 * The main entry point for PhishGuard's background logic.
 *
 * Responsibilities:
 *   1. Listen for navigation events (every tab, every URL change)
 *   2. Trigger the detection pipeline for each navigation
 *   3. Update the extension badge based on verdict
 *   4. Handle messages from content scripts and popup
 *   5. Manage tab state (current verdict per tab)
 *
 * MV3 SERVICE WORKER CONSTRAINTS:
 *   - This script is ephemeral — Chrome can terminate it at any time
 *   - Never store critical state in module-level variables (use chrome.storage)
 *   - The service worker re-registers its event listeners every time it wakes
 *   - chrome.storage.local IS persistent across service worker restarts
 */

import { loadAllowlist }           from './engine/allowlist.js'
import { analyzeNavigation, receiveContentResult } from './engine/orchestrator.js'
import { incrementVisitCount }     from './cache/store.js'

// ─── Tab State ───────────────────────────────────────────────────────────────
// Stores the most recent analysis result for each tab.
// This is module-level (in-memory) because it only needs to survive as long
// as the service worker is alive — the popup reads it synchronously.
// It resets when the service worker restarts, which is fine.
const tabResults = new Map()

// ─── Badge Configuration ─────────────────────────────────────────────────────
const BADGE = {
  SAFE:      { text: '✓',  color: '#22c55e', title: 'PhishGuard — Safe'         },
  SUSPICIOUS:{ text: '?',  color: '#eab308', title: 'PhishGuard — Suspicious'   },
  HIGH_RISK: { text: '!',  color: '#f97316', title: 'PhishGuard — High Risk'    },
  DANGEROUS: { text: '✕',  color: '#ef4444', title: 'PhishGuard — DANGEROUS'    },
  CHECKING:  { text: '…',  color: '#64748b', title: 'PhishGuard — Checking...'  },
  SKIPPED:   { text: '',   color: '#64748b', title: 'PhishGuard'                },
}

// ─── Startup ──────────────────────────────────────────────────────────────────
// Load the allowlist when the service worker starts.
// This runs every time the service worker wakes up — loadAllowlist()
// is idempotent and returns the cached Set on subsequent calls.
loadAllowlist().then(() => {
  console.log('[PhishGuard] Service worker ready')
})

// ─── Navigation Listener ─────────────────────────────────────────────────────
/**
 * onCommitted fires when a navigation is committed — meaning the browser
 * has decided to navigate to the URL and the page is starting to load.
 * This is the right event for us because:
 *   - It fires before the page renders (we can show a warning in time)
 *   - It fires for ALL navigations including back/forward
 *   - It gives us the final URL after redirects are resolved
 *
 * We filter to main frame only (frameId === 0) — we don't want to
 * analyze iframes, which would be noisy and inaccurate.
 */
chrome.webNavigation.onCommitted.addListener(
  async (details) => {
    // Only analyze main frame navigations
    if (details.frameId !== 0) return

    const { url, tabId } = details

    // Check if protection is enabled
    const { enabled } = await chrome.storage.local.get('enabled')
    if (enabled === false) {
      updateBadge(tabId, 'SKIPPED')
      return
    }

    // Show "checking" badge immediately
    updateBadge(tabId, 'CHECKING')

    // Track user visits to this domain (for trust bonus in scorer)
    try {
      const hostname = new URL(url).hostname
      await incrementVisitCount(hostname)
    } catch { /* ignore invalid URLs */ }

    // Run the full detection pipeline
    await analyzeNavigation(url, tabId, (tid, result) => {
      // Store result for popup to read
      tabResults.set(tid, { ...result, url, timestamp: Date.now() })

      // Update badge
      if (result.skipped) {
        updateBadge(tid, 'SKIPPED')
      } else {
        updateBadge(tid, result.verdict)
      }

      // If final verdict (not preliminary) and HIGH_RISK/DANGEROUS,
      // redirect to interstitial warning page
      // (only for non-preliminary verdicts to avoid flashing)
      if (!result.preliminary && shouldShowInterstitial(result.verdict)) {
        showInterstitial(tid, url, result)
      }
    })
  },
  { url: [{ schemes: ['http', 'https'] }] }
)

/**
 * onHistoryStateUpdated fires when a Single-Page App (SPA) changes
 * the URL via history.pushState() without a real navigation.
 * Examples: navigating between pages on Twitter, YouTube, Gmail.
 *
 * Without this listener, we'd miss all navigation in SPAs.
 */
chrome.webNavigation.onHistoryStateUpdated.addListener(
  async (details) => {
    if (details.frameId !== 0) return
    const { url, tabId } = details

    updateBadge(tabId, 'CHECKING')

    await analyzeNavigation(url, tabId, (tid, result) => {
      tabResults.set(tid, { ...result, url, timestamp: Date.now() })
      updateBadge(tid, result.skipped ? 'SKIPPED' : result.verdict)
    })
  },
  { url: [{ schemes: ['http', 'https'] }] }
)

/**
 * When a tab is closed, clean up its stored result.
 * Prevents unbounded memory growth.
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId)
})

// ─── Message Handler ─────────────────────────────────────────────────────────
/**
 * Central message dispatcher.
 * All components (content script, popup, interstitial) communicate
 * with the service worker through here.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {

    // Content script sends its DOM analysis results
    case 'CONTENT_ANALYSIS': {
      const tabId = sender.tab?.id
      if (tabId !== undefined) {
        receiveContentResult(tabId, message.payload)
      }
      sendResponse({ ok: true })
      break
    }

    // Popup requests the current result for the active tab
    case 'GET_TAB_RESULT': {
      const result = tabResults.get(message.tabId) || null
      sendResponse({ result })
      break
    }

    // User requests a re-scan of the current tab
    case 'RESCAN': {
      const { tabId, url } = message
      updateBadge(tabId, 'CHECKING')
      analyzeNavigation(url, tabId, (tid, result) => {
        tabResults.set(tid, { ...result, url, timestamp: Date.now() })
        updateBadge(tid, result.skipped ? 'SKIPPED' : result.verdict)
      }).catch(console.error)
      sendResponse({ ok: true })
      break
    }

    // Interstitial: user chose to proceed despite warning
    case 'PROCEED_ANYWAY': {
      // Nothing to do in service worker — tab already on the target page
      // Just acknowledge so the interstitial can close
      sendResponse({ ok: true })
      break
    }

    // Settings page changed a setting
    case 'SETTINGS_CHANGED': {
      // Currently handled by storage listeners — just acknowledge
      sendResponse({ ok: true })
      break
    }

    // Popup: user wants to whitelist current domain
    case 'WHITELIST_DOMAIN': {
      const { hostname } = message
      import('./cache/store.js').then(({ addToWhitelist }) => {
        addToWhitelist(hostname).then(() => {
          sendResponse({ ok: true })
        })
      })
      return true // keep channel open for async response
    }

    default:
      console.warn('[PhishGuard] Unknown message type:', message.type)
      sendResponse({ error: 'Unknown message type' })
  }

  // Return true for any async message handlers
  return false
})

// ─── Badge Utilities ──────────────────────────────────────────────────────────

/**
 * Update the extension badge for a specific tab.
 * The badge is the small colored indicator on the extension icon.
 *
 * @param {number} tabId
 * @param {string} verdictOrState — key into BADGE config
 */
function updateBadge(tabId, verdictOrState) {
  const config = BADGE[verdictOrState] || BADGE.CHECKING

  chrome.action.setBadgeText({ text: config.text, tabId }).catch(() => {})
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId }).catch(() => {})
  chrome.action.setTitle({ title: config.title, tabId }).catch(() => {})
}

// ─── Interstitial ─────────────────────────────────────────────────────────────

/**
 * Only show interstitial for HIGH_RISK and DANGEROUS verdicts.
 * SUSPICIOUS gets a non-blocking popup warning instead.
 */
function shouldShowInterstitial(verdict) {
  return verdict === 'HIGH_RISK' || verdict === 'DANGEROUS'
}

/**
 * Redirect the tab to our interstitial warning page.
 * The interstitial receives the blocked URL and analysis result
 * via chrome.storage.session (ephemeral — cleared when browser closes).
 *
 * @param {number} tabId
 * @param {string} originalUrl
 * @param {object} result
 */
async function showInterstitial(tabId, originalUrl, result) {
  try {
    // Store the blocked result so interstitial can read it
    await chrome.storage.session.set({
      [`interstitial:${tabId}`]: {
        url: originalUrl,
        result,
        timestamp: Date.now(),
      }
    })

    // Redirect to our warning page
    const interstitialUrl = chrome.runtime.getURL(
      `interstitial/interstitial.html?tabId=${tabId}`
    )
    await chrome.tabs.update(tabId, { url: interstitialUrl })
  } catch (err) {
    console.error('[PhishGuard] Failed to show interstitial:', err)
  }
}

// ─── Installation Handler ─────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[PhishGuard] Extension installed — first run')
    // Open onboarding page in a new tab
    chrome.tabs.create({
      url: chrome.runtime.getURL('onboarding/onboarding.html')
    })
    // Set defaults
    chrome.storage.local.set({
      enabled:         true,
      showInterstitial:true,
      gsbEnabled:      true,
      sensitivity:     2,
      whitelist:       [],
      onboardingComplete: false,
    })
  } else if (details.reason === 'update') {
    console.log(`[PhishGuard] Updated to ${chrome.runtime.getManifest().version}`)
  }
})
