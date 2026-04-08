/**
 * engine/scorer.js
 *
 * The scoring engine — the heart of PhishGuard's detection logic.
 *
 * DESIGN PRINCIPLES:
 * 1. No single signal triggers HIGH_RISK or DANGEROUS alone
 * 2. Missing data (API timeout) never penalizes a site
 * 3. User visit history provides a trust bonus
 * 4. Every verdict comes with human-readable reasons
 * 5. GSB blacklist hit is an immediate DANGEROUS override
 */

// ─── Signal Weight Table ────────────────────────────────────────────────────
//
// Each signal has:
//   points   — how much risk score it contributes
//   category — used for the "3 categories required" combination rule
//   label    — human-readable reason shown in UI
//
const SIGNALS = {
  // Blacklist (override category — one hit = DANGEROUS)
  gsb_blacklist: {
    points: 100,
    category: 'blacklist',
    label: 'Listed as a known phishing site (Google Safe Browsing)',
  },

  // URL signals
  ip_in_url: {
    points: 20,
    category: 'url',
    label: 'URL uses an IP address instead of a domain name',
  },
  at_symbol_in_url: {
    points: 15,
    category: 'url',
    label: 'URL contains @ symbol (used to disguise the real destination)',
  },
  no_https: {
    points: 15,
    category: 'url',
    label: 'Site does not use a secure HTTPS connection',
  },
  brand_typosquat_lte2: {
    points: 25,
    category: 'url',
    label: 'Domain name closely resembles a well-known brand (possible typosquatting)',
  },
  brand_typosquat_lte4: {
    points: 12,
    category: 'url',
    label: 'Domain name is similar to a well-known brand',
  },
  excessive_subdomains: {
    points: 10,
    category: 'url',
    label: 'Unusually large number of subdomains in URL',
  },
  suspicious_tld: {
    points: 12,
    category: 'url',
    label: 'Domain uses a TLD commonly associated with phishing',
  },
  high_entropy_domain: {
    points: 10,
    category: 'url',
    label: 'Domain name appears randomly generated',
  },
  url_length_gt100: {
    points: 8,
    category: 'url',
    label: 'Unusually long URL',
  },
  redirect_in_path: {
    points: 12,
    category: 'url',
    label: 'URL contains redirect parameters',
  },
  multi_brand_keywords: {
    points: 10,
    category: 'url',
    label: 'URL contains multiple brand names (unusual for legitimate sites)',
  },
  port_in_url: {
    points: 8,
    category: 'url',
    label: 'URL uses a non-standard port',
  },
  long_subdomain: {
    points: 8,
    category: 'url',
    label: 'Unusually long subdomain',
  },
  numeric_heavy_domain: {
    points: 8,
    category: 'url',
    label: 'Domain contains excessive numbers',
  },

  // Domain intelligence signals (Layer 2A — added in Milestone 4)
  domain_age_lt_7: {
    points: 30,
    category: 'domain',
    label: 'Domain was registered less than 7 days ago',
  },
  domain_age_lt_30: {
    points: 15,
    category: 'domain',
    label: 'Domain was registered less than 30 days ago',
  },
  cert_age_lt_7: {
    points: 12,
    category: 'domain',
    label: 'SSL certificate was issued less than 7 days ago',
  },
  tranco_unranked: {
    points: 5,
    category: 'domain',
    label: 'Site has no established web presence ranking',
  },

  // Content signals (Layer 2B — added in Milestone 4)
  login_form_ext_action: {
    points: 28,
    category: 'content',
    label: 'Login form submits credentials to an external domain',
  },
  password_field: {
    points: 8,
    category: 'content',
    label: 'Page requests password input',
  },
  favicon_mismatch: {
    points: 15,
    category: 'content',
    label: 'Page favicon loads from a different domain (impersonation indicator)',
  },
  external_res_gt80pct: {
    points: 10,
    category: 'content',
    label: 'Most page resources load from external domains (common in cloned pages)',
  },
  title_brand_mismatch: {
    points: 25,
    category: 'content',
    label: 'Page title claims to be a known brand but the domain does not match',
  },
  meta_refresh_external: {
    points: 20,
    category: 'content',
    label: 'Page automatically redirects to an external domain',
  },
  password_without_https: {
    points: 15,
    category: 'content',
    label: 'Page collects passwords without a secure HTTPS connection',
  },
  suspicious_iframe: {
    points: 12,
    category: 'content',
    label: 'Page contains a hidden or full-screen external iframe',
  },

  // ML signals (Layer 3 — V2 backend, added in Milestone 8)
  // Points are pre-computed by layer3-ml.js scoreToPoints()
  // and injected as a single 'ml' signal block.
  ml_high_confidence: {
    points: 35,
    category: 'ml',
    label: 'Machine learning model flagged this as high-confidence phishing',
  },
  ml_medium_confidence: {
    points: 25,
    category: 'ml',
    label: 'Machine learning model flagged this as likely phishing',
  },
  ml_low_confidence: {
    points: 15,
    category: 'ml',
    label: 'Machine learning model identified phishing characteristics',
  },
}

// ─── Verdict Thresholds ─────────────────────────────────────────────────────
const THRESHOLDS = {
  DANGEROUS:  71,
  HIGH_RISK:  46,
  SUSPICIOUS: 21,
}

// ─── Suspicious TLDs ────────────────────────────────────────────────────────
// These TLDs are historically overrepresented in phishing infrastructure.
// This list is not exhaustive — update it as patterns evolve.
export const SUSPICIOUS_TLDS = new Set([
  'xyz', 'tk', 'ml', 'ga', 'cf', 'gq',     // free TLDs heavily abused
  'top', 'click', 'link', 'download',        // action-oriented TLDs
  'support', 'help', 'secure', 'login',      // trust-baiting TLDs
  'online', 'site', 'website', 'space',      // cheap generic TLDs
  'live', 'stream', 'pw', 'cc',              // commonly abused
])

// ─── Brand List ─────────────────────────────────────────────────────────────
// Top brands targeted by phishing. Used for typosquatting detection.
// Loaded from assets/data/brands-500.json in production.
// Milestone 1 uses a small hardcoded list — expanded in Milestone 2.
const TOP_BRANDS = [
  'paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook',
  'instagram', 'twitter', 'netflix', 'spotify', 'linkedin', 'dropbox',
  'adobe', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
  'steam', 'roblox', 'discord', 'whatsapp', 'telegram', 'gmail',
  'outlook', 'yahoo', 'ebay', 'walmart', 'target', 'coinbase',
  'binance', 'crypto', 'blockchain', 'metamask', 'opensea',
  'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'upi',
]

// ─── Core Scoring Function ──────────────────────────────────────────────────

/**
 * Aggregate all available signals into a final verdict.
 *
 * @param {object} signals — output from all detection layers
 * @param {number} visitCount — how many times user has visited this domain
 * @returns {object} { verdict, score, reasons, firedSignals, preliminary }
 */
export function aggregateScore(signals, visitCount = 0) {
  const { url: urlSignals, gsb, domain, content, ml } = signals
  const mlReasons = []

  // ── GSB blacklist is an immediate DANGEROUS override ──────────────────────
  if (gsb?.isPhishing) {
    const gsbLabel = gsb.threatType
      ? threatTypeToLabel(gsb.threatType)
      : SIGNALS.gsb_blacklist.label
    return {
      verdict:       'DANGEROUS',
      score:         100,
      reasons:       [gsbLabel],
      firedSignals:  ['gsb_blacklist'],
      preliminary:   false,
      gsbThreatType: gsb.threatType || null,
    }
  }

  // ── Score all available signals ───────────────────────────────────────────
  const firedSignals = []

  // Helper: fire a signal if condition is true and signal exists
  function fire(signalKey, condition) {
    if (condition && SIGNALS[signalKey]) {
      firedSignals.push(signalKey)
    }
  }

  // URL signals (always available)
  if (urlSignals) {
    fire('ip_in_url',           urlSignals.has_ip_in_host)
    fire('at_symbol_in_url',    urlSignals.has_at)
    fire('no_https',            urlSignals.no_https)
    fire('excessive_subdomains', urlSignals.excessive_subdomains)
    fire('suspicious_tld',      urlSignals.suspicious_tld)
    fire('high_entropy_domain', urlSignals.high_entropy_domain)
    fire('url_length_gt100',    urlSignals.url_length_gt100)
    fire('redirect_in_path',    urlSignals.redirect_in_path)
    fire('multi_brand_keywords', urlSignals.multi_brand_keywords)
    fire('port_in_url',         urlSignals.port_in_url)
    fire('long_subdomain',      urlSignals.long_subdomain)
    fire('numeric_heavy_domain', urlSignals.numeric_heavy_domain)

    // Typosquatting: V1 only flags distance 1–2 (clear typosquats)
    // Distance 3–4 deferred to V2 ML model to avoid false positives
    if (urlSignals.brand_distance !== null && urlSignals.brand_distance !== undefined) {
      if (urlSignals.brand_distance >= 1 && urlSignals.brand_distance <= 2) {
        fire('brand_typosquat_lte2', true)
      }
    }
  }

  // Domain intelligence signals (available after Milestone 4)
  if (domain) {
    fire('domain_age_lt_7',  domain.age_days !== null && domain.age_days < 7)
    fire('domain_age_lt_30', domain.age_days !== null && domain.age_days >= 7 && domain.age_days < 30)
    fire('cert_age_lt_7',    domain.cert_age_days !== null && domain.cert_age_days < 7)
    fire('tranco_unranked',  domain.tranco_rank === null)
  }

  // Content signals (Layer 2B)
  if (content) {
    fire('login_form_ext_action',  content.formActionExternal)
    fire('password_field',         content.hasPasswordField)
    fire('favicon_mismatch',       content.faviconMismatch)
    fire('external_res_gt80pct',   content.externalResourceRatio > 0.8)
    fire('title_brand_mismatch',   content.titleBrandMismatch)
    fire('meta_refresh_external',  content.metaRefreshExternal)
    fire('password_without_https', content.passwordWithoutHttps)
    fire('suspicious_iframe',      content.suspiciousIframe)
  }

  // ML signals (Layer 3 — V2 backend)
  // mlPoints already computed by scoreToPoints() in layer3-ml.js
  const mlPoints = ml?.mlPoints ?? 0
  if (ml && mlPoints >= 35) {
    firedSignals.push('ml_high_confidence')
    // Add ML-specific reasons to the front (most authoritative signal)
    if (Array.isArray(ml.mlSignals) && ml.mlSignals.length > 0) {
      ml.mlSignals.slice(0, 2).forEach(s => mlReasons.push(s))
    }
  } else if (ml && mlPoints >= 25) {
    firedSignals.push('ml_medium_confidence')
    if (Array.isArray(ml.mlSignals) && ml.mlSignals.length > 0) {
      mlReasons.push(ml.mlSignals[0])
    }
  } else if (ml && mlPoints >= 15) {
    firedSignals.push('ml_low_confidence')
  }

  // ── Calculate raw score ───────────────────────────────────────────────────
  // ML points are pre-computed and stored via firedSignals entry.
  // Standard signals use SIGNALS table; ml_* signals use their weights.
  let totalScore = firedSignals.reduce((sum, key) => sum + (SIGNALS[key]?.points ?? 0), 0)

  // ── Combination rule enforcement ──────────────────────────────────────────
  // HIGH_RISK or DANGEROUS requires signals from at least 3 different categories.
  // Categories: 'url', 'domain', 'content', 'ml' — 4 possible in V2.
  // ML alone cannot push a safe URL into HIGH_RISK (needs corroboration).
  const categories = new Set(firedSignals.map(k => SIGNALS[k]?.category).filter(Boolean))
  if (totalScore > 45 && categories.size < 3) {
    totalScore = Math.min(totalScore, 45) // cap at top of SUSPICIOUS range
  }

  // ── User history trust bonus ──────────────────────────────────────────────
  // Frequent visits are a strong signal that the user trusts this site.
  // We reduce the score by 30% for sites visited more than 5 times.
  if (visitCount > 5) {
    totalScore = Math.floor(totalScore * 0.70)
  } else if (visitCount > 2) {
    totalScore = Math.floor(totalScore * 0.85)
  }

  // ── Build reason list (top 3 by severity) ────────────────────────────────
  // Build reasons: ML reasons first (most specific), then top heuristic signals
  const heuristicReasons = firedSignals
    .filter(k => SIGNALS[k]?.category !== 'ml')
    .sort((a, b) => (SIGNALS[b]?.points ?? 0) - (SIGNALS[a]?.points ?? 0))
    .slice(0, 3 - Math.min(mlReasons.length, 2))
    .map(key => SIGNALS[key]?.label)
    .filter(Boolean)

  const reasons = [...mlReasons.slice(0, 2), ...heuristicReasons].slice(0, 3)

  const verdict = scoreToVerdict(totalScore)

  return {
    verdict,
    score: totalScore,
    reasons,
    firedSignals,
    preliminary: false,
  }
}

/**
 * Produce a quick preliminary verdict from URL signals only.
 * Called immediately after Layer 1B so the badge can update
 * before domain/content signals arrive.
 *
 * @param {object} urlSignals — output from layer1b
 * @returns {object} partial verdict marked as preliminary: true
 */
export function preliminaryVerdict(urlSignals) {
  const result = aggregateScore({ url: urlSignals, gsb: null, domain: null, content: null }, 0)
  return { ...result, preliminary: true }
}

/**
 * Map a numeric score to a verdict string.
 * @param {number} score
 * @returns {'DANGEROUS'|'HIGH_RISK'|'SUSPICIOUS'|'SAFE'}
 */
export function scoreToVerdict(score) {
  if (score >= THRESHOLDS.DANGEROUS)  return 'DANGEROUS'
  if (score >= THRESHOLDS.HIGH_RISK)  return 'HIGH_RISK'
  if (score >= THRESHOLDS.SUSPICIOUS) return 'SUSPICIOUS'
  return 'SAFE'
}

// ─── Utility: Shannon Entropy ────────────────────────────────────────────────
/**
 * Calculate Shannon entropy of a string.
 * High entropy = string looks random = suspicious domain name.
 * Normal English words score ~2.5–3.5. Random strings score 3.8+.
 *
 * @param {string} str
 * @returns {number}
 */
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0
  const freq = {}
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1
  }
  return Object.values(freq).reduce((entropy, count) => {
    const p = count / str.length
    return entropy - p * Math.log2(p)
  }, 0)
}

// ─── Utility: Levenshtein Distance ──────────────────────────────────────────
/**
 * Calculate the Levenshtein edit distance between two strings.
 * Used to detect typosquatting: distance(paypa1.com, paypal.com) = 1
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function levenshtein(a, b) {
  const m = a.length, n = b.length
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    }
  }
  return dp[m][n]
}

/**
 * Find the minimum Levenshtein distance between a hostname
 * and all known brand names.
 *
 * Returns 0 if the hostname IS a brand (legitimate — not suspicious).
 * Returns 1–2 if it closely resembles a brand (typosquatting).
 * Returns null if no brand is close enough to matter (distance > 4).
 *
 * @param {string} hostname
 * @returns {number|null}
 */
export function minBrandDistance(hostname) {
  // Handle IP addresses — no brand distance calculation
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return null

  const parts = hostname.split('.')
  const candidates = parts.slice(0, -1) // everything before TLD

  let minDist = Infinity

  for (const candidate of candidates) {
    // Skip very short candidates — too many coincidental matches
    // "at", "in", "go" would spuriously match short brand names
    if (candidate.length < 5) continue

    for (const brand of TOP_BRANDS) {
      // Skip if lengths differ too much — tighter filter (> 2 not > 3) prevents
      // coincidental matches like "example" → "apple" (len diff = 2, dist = 3)
      if (Math.abs(candidate.length - brand.length) > 2) continue

      const dist = levenshtein(candidate.toLowerCase(), brand.toLowerCase())
      if (dist < minDist) minDist = dist
    }
  }

  // Distance 0 = exact brand name = legitimate — return null (don't penalise)
  // Distance 1–2 = clear typosquat (paypa1, gooogle, micros0ft)
  // Distance 3–4 removed from V1 — too many coincidental matches on real words
  //   ("example" is dist-3 from "apple", "orange" is dist-3 from "amazon" etc.)
  //   These mild signals will be handled by the ML model in V2.
  if (minDist === 0 || minDist > 2) return null
  return minDist
}
// ─── GSB Threat Type Labels ───────────────────────────────────────────────────

/**
 * Convert a raw GSB threat type string to a human-readable reason label.
 * Used in the popup and interstitial UI to explain why a site was blocked.
 *
 * @param {string} threatType — raw GSB threatType value
 * @returns {string} human-readable label
 */
function threatTypeToLabel(threatType) {
  const labels = {
    'SOCIAL_ENGINEERING':
      'Confirmed phishing site (Google Safe Browsing)',
    'MALWARE':
      'Confirmed malware distribution site (Google Safe Browsing)',
    'UNWANTED_SOFTWARE':
      'Distributes unwanted software (Google Safe Browsing)',
    'POTENTIALLY_HARMFUL_APPLICATION':
      'Contains potentially harmful applications (Google Safe Browsing)',
  }
  return labels[threatType] || 'Confirmed dangerous site (Google Safe Browsing)'
}
