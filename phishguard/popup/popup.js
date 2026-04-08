/**
 * popup/popup.js — PhishGuard Popup Controller v2
 *
 * Improvements in Milestone 5:
 *   - Settings button → opens settings page
 *   - Score bar with animated fill
 *   - Enable/disable guard (shows disabled state)
 *   - False positive reporting stored locally for V2 backend
 *   - Cleaner preliminary → final transition
 *   - Whitelist confirmation flow
 */

;(async function () {
  'use strict'

  // ── Get current tab ────────────────────────────────────────────────────
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab) { showEmpty(); return }

  const tabId  = tab.id
  const tabUrl = tab.url || ''

  // ── Check if protection is enabled ────────────────────────────────────
  const prefs = await chrome.storage.local.get(['enabled'])
  if (prefs.enabled === false) {
    showDisabled()
    wireButtons(tabId, tabUrl, null)
    return
  }

  // ── Request result from service worker ────────────────────────────────
  showLoading(tabUrl)

  let result = null
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId })
    result = response?.result
  } catch (err) {
    console.error('[PhishGuard Popup]', err)
  }

  if (!result) { showEmpty(); wireButtons(tabId, tabUrl, null); return }

  renderResult(result, tabUrl)
  wireButtons(tabId, tabUrl, result)

  // ── Render ─────────────────────────────────────────────────────────────
  function renderResult(result, url) {
    hideAll()

    const verdict = result.verdict || 'SAFE'
    const score   = result.score   || 0
    const reasons = result.reasons || []
    const shortUrl = fmt(url)

    const MAP = {
      SAFE:      'state-safe',
      SUSPICIOUS:'state-suspicious',
      HIGH_RISK: 'state-high-risk',
      DANGEROUS: 'state-dangerous',
    }

    const stateId = MAP[verdict] || 'state-safe'
    show(stateId)

    // URL label in card
    setText(`${stateId.replace('state-','')}-url`, shortUrl)

    // Score number on card (not for SAFE)
    if (verdict !== 'SAFE') {
      setText(`${stateId.replace('state-','')}-score`, score)
    }

    // Score bar
    if (verdict !== 'SAFE') {
      show('score-bar-section')
      renderScoreBar(score, verdict)
    }

    // Reasons
    if (verdict !== 'SAFE' && reasons.length > 0) {
      renderReasons(reasons, verdict)
    }

    // Preliminary banner
    if (result.preliminary) show('preliminary-banner')
  }

  function renderScoreBar(score, verdict) {
    const COLORS = {
      SUSPICIOUS: '#eab308',
      HIGH_RISK:  '#f97316',
      DANGEROUS:  '#ef4444',
    }
    const fill    = document.getElementById('score-bar-fill')
    const valEl   = document.getElementById('score-bar-value')
    // Cap visual at 100%
    const pct     = Math.min(100, Math.round((score / 100) * 100))
    fill.style.width      = `${pct}%`
    fill.style.background = COLORS[verdict] || '#eab308'
    valEl.textContent     = `${score} / 100`
    valEl.style.color     = COLORS[verdict] || '#eab308'
  }

  function renderReasons(reasons, verdict) {
    const DOTS = {
      SUSPICIOUS: '#eab308',
      HIGH_RISK:  '#f97316',
      DANGEROUS:  '#ef4444',
    }
    const section = document.getElementById('reasons-section')
    const list    = document.getElementById('reasons-list')
    list.innerHTML = ''
    reasons.forEach(reason => {
      const li = document.createElement('li')
      li.innerHTML = `<span class="reason-dot" style="background:${DOTS[verdict] || '#eab308'}"></span>
                      <span>${esc(reason)}</span>`
      list.appendChild(li)
    })
    section.style.display = 'block'
  }

  // ── State helpers ──────────────────────────────────────────────────────
  function showLoading(url) {
    hideAll(); show('state-loading')
    setText('loading-url', fmt(url))
  }

  function showEmpty()    { hideAll(); show('state-empty') }
  function showDisabled() { hideAll(); show('state-disabled') }

  function hideAll() {
    ['state-loading','state-safe','state-suspicious','state-high-risk',
     'state-dangerous','state-empty','state-disabled',
     'score-bar-section','reasons-section','preliminary-banner',
    ].forEach(hide)
  }

  // ── Button wiring ──────────────────────────────────────────────────────
  function wireButtons(tabId, tabUrl, result) {

    // Settings
    document.getElementById('btn-settings').addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('settings/settings.html') })
      window.close()
    })

    // Enable button (shown in disabled state)
    document.getElementById('btn-enable')?.addEventListener('click', async () => {
      await chrome.storage.local.set({ enabled: true })
      chrome.runtime.sendMessage({ type: 'SETTINGS_CHANGED', key: 'enabled', value: true })
      window.close()
    })

    // Re-scan
    document.getElementById('btn-rescan').addEventListener('click', async () => {
      if (!tabUrl.startsWith('http')) return
      showLoading(tabUrl)
      await chrome.runtime.sendMessage({ type: 'RESCAN', tabId, url: tabUrl })
      window.close()
    })

    // Trust site (whitelist)
    document.getElementById('btn-whitelist').addEventListener('click', async () => {
      try {
        const hostname = new URL(tabUrl).hostname
        await chrome.runtime.sendMessage({ type: 'WHITELIST_DOMAIN', hostname })
        showToast(`${hostname} marked as trusted`)
        setTimeout(() => window.close(), 1400)
      } catch (err) {
        console.error('[PhishGuard Popup] Whitelist error:', err)
      }
    })

    // Report false positive
    document.getElementById('btn-report').addEventListener('click', async () => {
      await storeFalsePositiveReport(tabUrl, result)
      showToast('Report saved — thank you!')
      setTimeout(() => window.close(), 1400)
    })
  }

  // ── False positive reporting ───────────────────────────────────────────
  /**
   * Store a false positive report locally.
   * In V2 this queue will be flushed to the backend ML training pipeline.
   * Reports are stored as: reports:[timestamp] → { url, verdict, signals, reportedAt }
   */
  async function storeFalsePositiveReport(url, result) {
    const report = {
      url,
      verdict:     result?.verdict    || 'UNKNOWN',
      score:       result?.score      || 0,
      firedSignals: result?.firedSignals || [],
      reasons:     result?.reasons    || [],
      reportedAt:  Date.now(),
      userAgent:   navigator.userAgent.slice(0, 120),
    }
    const key = `report:${Date.now()}`
    await chrome.storage.local.set({ [key]: report })

    // Also track report count for future badge/notification
    const { reportCount = 0 } = await chrome.storage.local.get('reportCount')
    await chrome.storage.local.set({ reportCount: reportCount + 1 })
  }

  // ── Toast ──────────────────────────────────────────────────────────────
  function showToast(msg) {
    const existing = document.querySelector('.popup-toast')
    if (existing) existing.remove()
    const el = document.createElement('div')
    el.className = 'popup-toast'
    el.textContent = msg
    el.style.cssText = `
      position:fixed;bottom:52px;left:50%;transform:translateX(-50%);
      background:#1e2333;border:1px solid #2e3649;color:#e8eaf0;
      padding:7px 14px;border-radius:6px;font-size:12px;
      white-space:nowrap;z-index:100;animation:fadeIn 0.2s ease;
    `
    document.body.appendChild(el)
    setTimeout(() => el?.remove(), 2000)
  }

  // ── Utilities ──────────────────────────────────────────────────────────
  function show(id) { const el=document.getElementById(id); if(el) el.style.display='' }
  function hide(id) { const el=document.getElementById(id); if(el) el.style.display='none' }
  function setText(id, text) { const el=document.getElementById(id); if(el) el.textContent=text }
  function esc(str) { return String(str).replace(/</g,'&lt;').replace(/>/g,'&gt;') }
  function fmt(url) {
    try {
      const p = new URL(url)
      const d = p.hostname + (p.pathname !== '/' ? p.pathname : '')
      return d.length > 38 ? d.slice(0,36)+'…' : d
    } catch { return url.slice(0,38) }
  }

})()
