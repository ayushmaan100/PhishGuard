"""
ml/scripts/features.py

Feature extraction pipeline for PhishGuard's LightGBM model.

CRITICAL DESIGN PRINCIPLE — FEATURE PARITY:
These features MUST mirror the signals computed by the extension exactly.
If the extension computes brand_distance differently than the model was
trained on, the model's predictions will be miscalibrated.

Every feature here has a corresponding signal in:
  background/engine/scorer.js        (weight table)
  background/layers/layer1b-url.js   (URL features)
  background/layers/layer2a-domain.js (domain features)
  content/content-script.js          (content features)

The model adds on top of heuristics — it learns non-linear combinations
and subtle patterns the weighted sum misses. Feature engineering is 80%
of the work; the model selection is secondary.

FEATURES (29 total):

URL Features (always available, fast):
  url_length              — total character length of URL
  hostname_length         — length of hostname portion
  num_dots               — dots in hostname (subdomain depth proxy)
  num_hyphens            — hyphens in hostname
  num_subdomains         — count of subdomain labels
  has_ip_in_host         — hostname is an IP address (0/1)
  has_at_symbol          — username@host trick in authority (0/1)
  has_https              — protocol is HTTPS (0/1)
  url_entropy            — Shannon entropy of full URL
  domain_entropy         — Shannon entropy of bare domain name
  num_digits_domain      — digit count in domain name
  suspicious_tld         — TLD in known-bad set (0/1)
  path_length            — length of URL path
  num_params             — number of query parameters
  has_redirect_param     — URL contains redirect/return parameter (0/1)
  num_brand_keywords     — count of brand keywords in full URL
  min_brand_distance     — minimum Levenshtein distance to known brands
  has_port               — non-standard port in URL (0/1)
  long_subdomain         — longest subdomain label length

Domain Intelligence Features (from RDAP/crt.sh/Tranco):
  domain_age_days        — days since registration (-1 = unknown)
  cert_age_days          — days since newest cert issued (-1 = unknown)
  tranco_rank            — Tranco rank (0 = unranked/unknown)
  is_new_tld             — domain registered under new gTLD (0/1)

Content Features (from DOM analysis):
  has_login_form         — page has credential-collecting form (0/1)
  form_action_external   — login form posts to external domain (0/1)
  has_password_field     — page has password input (0/1)
  favicon_mismatch       — favicon loads from different domain (0/1)
  external_resource_ratio — fraction of resources from external domains
  title_brand_mismatch   — page title claims known brand, wrong domain (0/1)
"""

import math
import re
from typing import Optional
from urllib.parse import urlparse, parse_qs

# ── Brand lists (must match extension's lists exactly) ────────────────────────

TOP_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook',
    'instagram', 'twitter', 'netflix', 'spotify', 'linkedin', 'dropbox',
    'adobe', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    'steam', 'roblox', 'discord', 'whatsapp', 'telegram', 'gmail',
    'outlook', 'yahoo', 'ebay', 'walmart', 'coinbase', 'binance',
    'metamask', 'opensea', 'github', 'roblox', 'steam', 'twitch',
    'sbi', 'hdfc', 'icici', 'axis', 'paytm',
    'phonepe', 'upi',
]

BRAND_KEYWORDS = TOP_BRANDS + [
    'account', 'verify', 'secure', 'login', 'update', 'confirm',
    'banking', 'wallet', 'password', 'signin', 'credential',
]

SUSPICIOUS_TLDS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'link',
    'download', 'support', 'help', 'secure', 'login', 'online', 'site',
    'website', 'space', 'live', 'stream', 'pw', 'cc', 'work', 'party',
    'trade', 'date', 'racing', 'cricket', 'science', 'win', 'bid',
}

# New gTLDs launched after 2012 — legitimate sites prefer .com/.net/.org
NEW_GTLDS = {
    'xyz', 'app', 'dev', 'io', 'ai', 'co', 'tech', 'online', 'store',
    'shop', 'site', 'web', 'digital', 'cloud', 'network', 'systems',
    'solutions', 'services', 'agency', 'studio', 'design',
}

REDIRECT_PARAMS = {
    'url', 'redirect', 'return', 'returnurl', 'next',
    'goto', 'dest', 'destination', 'redir', 'forward',
    'continue', 'ref', 'back',
}

# ── Utility functions ─────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum(
        (count / len(s)) * math.log2(count / len(s))
        for count in freq.values()
    )

def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            if a[i-1] == b[j-1]:
                dp[j] = prev[j-1]
            else:
                dp[j] = 1 + min(prev[j], dp[j-1], prev[j-1])
    return dp[n]

def min_brand_distance(hostname: str) -> int:
    """
    Minimum Levenshtein distance from any hostname label to any known brand.
    Returns 0 if exact match (legitimate), capped at 5 (unrelated).
    """
    parts = hostname.lower().split('.')
    # Check all parts except TLD
    candidates = parts[:-1] if len(parts) > 1 else parts

    min_dist = 999
    for candidate in candidates:
        if len(candidate) < 4:  # too short to be a brand
            continue
        for brand in TOP_BRANDS:
            if abs(len(candidate) - len(brand)) > 3:
                continue
            dist = levenshtein(candidate, brand)
            if dist < min_dist:
                min_dist = dist

    return min(min_dist, 5)

def count_brand_keywords(url_lower: str) -> int:
    """Count how many brand keywords appear in the URL."""
    return sum(1 for kw in BRAND_KEYWORDS if kw in url_lower)

def extract_tld(hostname: str) -> str:
    """Extract the TLD from a hostname."""
    parts = hostname.split('.')
    return parts[-1].lower() if parts else ''

# ── Main feature extractor ────────────────────────────────────────────────────

def extract_features(
    url: str,
    domain_intel: Optional[dict] = None,
    content_signals: Optional[dict] = None,
) -> dict:
    """
    Extract all 29 features from a URL and optional enrichment data.

    Parameters
    ----------
    url : str
        Full URL string (e.g., "https://paypa1.com/login")
    domain_intel : dict, optional
        Output from domain intelligence layer:
        { age_days, cert_age_days, tranco_rank }
    content_signals : dict, optional
        Output from content script:
        { hasLoginForm, formActionExternal, hasPasswordField,
          faviconMismatch, externalResourceRatio, titleBrandMismatch }

    Returns
    -------
    dict
        Feature dict with exactly 29 keys.
        Missing data → sentinel values (-1 or 0), never NaN.
        LightGBM handles missing values natively when trained with them.
    """
    features = {}

    # ── Parse URL ─────────────────────────────────────────────────────────────
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname or ''
        scheme   = parsed.scheme or ''
        path     = parsed.path or ''
        query    = parsed.query or ''
        port     = parsed.port
    except Exception:
        # Unparseable URL — return all-zero features
        return _zero_features()

    url_lower    = url.lower()
    hostname_low = hostname.lower()
    tld          = extract_tld(hostname)
    host_parts   = hostname_low.split('.')

    # bare domain = part before TLD (may include subdomains)
    bare_domain  = host_parts[-2] if len(host_parts) >= 2 else hostname_low

    # subdomains = everything before the registered domain
    num_subdomains = max(0, len(host_parts) - 2)

    # ── URL Features ─────────────────────────────────────────────────────────

    # Length features
    features['url_length']       = len(url)
    features['hostname_length']  = len(hostname)
    features['path_length']      = len(path)

    # Structure features
    features['num_dots']         = hostname_low.count('.')
    features['num_hyphens']      = hostname_low.count('-')
    features['num_subdomains']   = num_subdomains

    # Boolean signals (0/1)
    features['has_ip_in_host']   = int(bool(
        re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname_low)
    ))
    features['has_at_symbol']    = int(bool(parsed.username))
    features['has_https']        = int(scheme == 'https')
    features['suspicious_tld']   = int(tld in SUSPICIOUS_TLDS)
    features['is_new_tld']       = int(tld in NEW_GTLDS)
    features['has_port']         = int(
        port is not None and port not in (80, 443)
    )

    # Redirect parameter detection
    params_lower = {k.lower() for k in parse_qs(query).keys()}
    features['has_redirect_param'] = int(bool(
        params_lower & REDIRECT_PARAMS
    ))
    features['num_params']       = len(parse_qs(query))

    # Entropy signals
    features['url_entropy']      = round(shannon_entropy(url), 4)
    features['domain_entropy']   = round(shannon_entropy(bare_domain), 4)

    # Digit count in domain
    features['num_digits_domain'] = sum(c.isdigit() for c in bare_domain)

    # Brand signals
    features['num_brand_keywords'] = count_brand_keywords(url_lower)
    features['min_brand_distance'] = min_brand_distance(hostname_low)

    # Longest subdomain label (long subdomains = suspicious)
    subdomain_labels = host_parts[:-2] if len(host_parts) > 2 else []
    features['long_subdomain'] = max(
        (len(s) for s in subdomain_labels), default=0
    )

    # ── Domain Intelligence Features ─────────────────────────────────────────
    # Sentinel: -1 = data unavailable (not zero — zero means "0 days old" which is real)
    # LightGBM treats -1 as a real value, but we train it with many -1s so it learns
    # that -1 ≠ 0. Alternative: use NaN and enable LightGBM's missing value handling.
    # We use -1 for compatibility with simpler models and JSON serialization.

    if domain_intel:
        features['domain_age_days'] = (
            int(domain_intel['age_days'])
            if domain_intel.get('age_days') is not None and domain_intel['age_days'] >= 0
            else -1
        )
        features['cert_age_days'] = (
            int(domain_intel['cert_age_days'])
            if domain_intel.get('cert_age_days') is not None and domain_intel['cert_age_days'] >= 0
            else -1
        )
        features['tranco_rank'] = (
            int(domain_intel['tranco_rank'])
            if domain_intel.get('tranco_rank') is not None
            else 0  # 0 = unranked
        )
    else:
        features['domain_age_days'] = -1
        features['cert_age_days']   = -1
        features['tranco_rank']     = 0

    # ── Content Features ──────────────────────────────────────────────────────
    if content_signals:
        features['has_login_form']         = int(content_signals.get('hasLoginForm', False))
        features['form_action_external']   = int(content_signals.get('formActionExternal', False))
        features['has_password_field']     = int(content_signals.get('hasPasswordField', False))
        features['favicon_mismatch']       = int(content_signals.get('faviconMismatch', False))
        features['external_resource_ratio']= float(
            content_signals.get('externalResourceRatio', 0.0)
        )
        features['title_brand_mismatch']   = int(content_signals.get('titleBrandMismatch', False))
    else:
        features['has_login_form']          = 0
        features['form_action_external']    = 0
        features['has_password_field']      = 0
        features['favicon_mismatch']        = 0
        features['external_resource_ratio'] = 0.0
        features['title_brand_mismatch']    = 0

    return features


def _zero_features() -> dict:
    """Return a safe all-zero feature vector for unparseable URLs."""
    return {
        'url_length': 0, 'hostname_length': 0, 'path_length': 0,
        'num_dots': 0, 'num_hyphens': 0, 'num_subdomains': 0,
        'has_ip_in_host': 0, 'has_at_symbol': 0, 'has_https': 0,
        'suspicious_tld': 0, 'is_new_tld': 0, 'has_port': 0,
        'has_redirect_param': 0, 'num_params': 0,
        'url_entropy': 0.0, 'domain_entropy': 0.0,
        'num_digits_domain': 0, 'num_brand_keywords': 0,
        'min_brand_distance': 5, 'long_subdomain': 0,
        'domain_age_days': -1, 'cert_age_days': -1, 'tranco_rank': 0,
        'has_login_form': 0, 'form_action_external': 0,
        'has_password_field': 0, 'favicon_mismatch': 0,
        'external_resource_ratio': 0.0, 'title_brand_mismatch': 0,
    }


# Expected feature names in training order (must match model input exactly)
FEATURE_NAMES = list(_zero_features().keys())
assert len(FEATURE_NAMES) == 29, f"Expected 29 features, got {len(FEATURE_NAMES)}"


if __name__ == '__main__':
    # Quick smoke test
    test_cases = [
        ('https://paypa1.com/login',               True,  'typosquat'),
        ('https://www.google.com/',                 False, 'legit google'),
        ('http://192.168.1.100/steal',              True,  'IP address'),
        ('https://secure-paypal-login.xyz/account', True,  'brand keywords + tld'),
        ('https://github.com/user/repo',            False, 'legit github'),
        ('https://mail.google.com/mail/u/0/',       False, 'legit gmail'),
    ]

    print(f"Feature extractor — {len(FEATURE_NAMES)} features\n")
    print(f"{'URL':<50} {'Expected':<10} {'key signals'}")
    print('-' * 90)

    for url, expected_phish, label in test_cases:
        f = extract_features(url)
        signals = []
        if f['has_ip_in_host']:    signals.append('IP')
        if f['suspicious_tld']:    signals.append('bad_tld')
        if f['min_brand_distance'] <= 2 and f['min_brand_distance'] > 0:
            signals.append(f'typosquat(d={f["min_brand_distance"]})')
        if f['num_brand_keywords'] >= 2: signals.append(f'brands({f["num_brand_keywords"]})')
        if f['domain_entropy'] > 3.2 and f['num_digits_domain'] > 0:
            signals.append('entropy')

        print(f"{url[:48]:<50} {'phish' if expected_phish else 'legit':<10} {', '.join(signals) or 'none'}")
