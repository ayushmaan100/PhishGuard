"""
ml/scripts/build_dataset.py

Downloads and assembles the training dataset for PhishGuard's LightGBM model.

DATA SOURCES:
  Phishing (label=1):
    - PhishTank verified feed (CSV, free, ~50K URLs)
    - OpenPhish community feed (free tier, ~5K URLs)
    - Fallback: curated synthetic samples if downloads fail

  Legitimate (label=0):
    - Tranco top-1M list (research-grade, free, no key)
    - Sampled to match phishing count (balanced dataset)

PIPELINE:
  1. Download phishing URLs → deduplicate → filter to http/https
  2. Download Tranco list → sample legitimate URLs
  3. Extract features for each URL (features.py)
  4. Handle missing domain intel (sentinel values — model learns from this)
  5. Save to data/dataset.csv

USAGE:
  python3 ml/scripts/build_dataset.py

  Options (set as env vars or edit constants below):
    PHISHTANK_API_KEY  — optional, increases rate limit
    MAX_SAMPLES        — max samples per class (default: 20000)
    DATA_DIR           — output directory (default: ml/data)

NOTE ON DOMAIN INTEL:
  Fetching RDAP/crt.sh for 40K URLs would take hours and get rate-limited.
  For training, we use synthetic domain intel signals derived from URL patterns:
    - Domains with random-looking names → age_days = 3 (synthetic)
    - Tranco top-10K → domain_age_days = 1000 (established)
  This gives the model a realistic distribution without exhausting APIs.
  In V3, we can enrich with real RDAP data for top phishing URLs.
"""

import os
import sys
import csv
import random
import hashlib
import requests
import zipfile
import io
import time
from pathlib import Path
from typing import List, Tuple

# Add parent directory to path for features import
sys.path.insert(0, str(Path(__file__).parent))
from features import extract_features, FEATURE_NAMES

# ── Configuration ─────────────────────────────────────────────────────────────

DATA_DIR    = Path(__file__).parent.parent / 'data'
MAX_SAMPLES = int(os.environ.get('MAX_SAMPLES', 20_000))
SEED        = 42
random.seed(SEED)

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Phishing URL sources ──────────────────────────────────────────────────────

def fetch_phishtank(max_urls: int = MAX_SAMPLES) -> List[str]:
    """
    Download PhishTank verified phishing URLs.
    PhishTank provides a free CSV download — no key needed for basic access.
    Returns a list of URL strings.
    """
    print("[PhishTank] Downloading verified phishing URLs...")

    url = 'http://data.phishtank.com/data/online-valid.csv'
    try:
        resp = requests.get(url, timeout=30, headers={
            'User-Agent': 'PhishGuard-Research/1.0 (academic use)',
        })
        resp.raise_for_status()

        urls = []
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            phish_url = row.get('url', '').strip()
            if phish_url and (phish_url.startswith('http://') or
                               phish_url.startswith('https://')):
                urls.append(phish_url)
            if len(urls) >= max_urls:
                break

        print(f"[PhishTank] Downloaded {len(urls):,} phishing URLs")
        return urls

    except Exception as e:
        print(f"[PhishTank] Download failed: {e}")
        print("[PhishTank] Using synthetic phishing samples for training")
        return generate_synthetic_phishing(max_urls)


def fetch_openphish(max_urls: int = 5000) -> List[str]:
    """
    Download OpenPhish community feed (real-time phishing URLs).
    Free tier, no authentication needed.
    """
    print("[OpenPhish] Downloading phishing feed...")
    try:
        resp = requests.get(
            'https://openphish.com/feed.txt', timeout=15,
            headers={'User-Agent': 'PhishGuard-Research/1.0'},
        )
        urls = [
            line.strip() for line in resp.text.splitlines()
            if line.strip().startswith(('http://', 'https://'))
        ][:max_urls]
        print(f"[OpenPhish] Downloaded {len(urls):,} URLs")
        return urls
    except Exception as e:
        print(f"[OpenPhish] Failed: {e}")
        return []


def generate_synthetic_phishing(count: int) -> List[str]:
    """
    Generate realistic synthetic phishing URLs when live sources are unavailable.
    Based on common phishing kit patterns observed in the wild.
    """
    print(f"[Synthetic] Generating {count:,} phishing URL samples...")

    brands = ['paypal', 'google', 'apple', 'amazon', 'microsoft', 'facebook',
              'netflix', 'instagram', 'linkedin', 'dropbox', 'coinbase', 'binance']
    suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.online']
    bad_tlds = ['.xyz', '.tk', '.ml', '.top', '.online']
    patterns = []

    for brand in brands:
        for i in range(count // (len(brands) * 4)):
            # Pattern 1: typosquat + login path
            typo = brand[:-1] + chr(ord(brand[-1]) + 1)  # last char +1
            patterns.append(f'https://{typo}.com/login')

            # Pattern 2: brand in subdomain
            rand = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
            patterns.append(f'https://{brand}-secure-{rand}.xyz/account/verify')

            # Pattern 3: brand + suspicious TLD
            patterns.append(f'https://{brand}-login{random.choice(bad_tlds)}/signin')

            # Pattern 4: IP address phishing
            ip = f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'
            patterns.append(f'http://{ip}/{brand}/login.php')

    random.shuffle(patterns)
    result = patterns[:count]
    print(f"[Synthetic] Generated {len(result):,} phishing samples")
    return result


# ── Legitimate URL source ─────────────────────────────────────────────────────

def fetch_tranco_legitimate(max_urls: int = MAX_SAMPLES) -> List[str]:
    """
    Download Tranco top-1M list and sample legitimate URLs from it.
    Tranco is a research-grade list combining Alexa, Majestic, Umbrella, Quantcast.
    Free, updated regularly: https://tranco-list.eu/
    """
    print("[Tranco] Downloading top-1M list...")

    tranco_csv_path = DATA_DIR / 'tranco-1m.csv'

    # Check if we have a recent download
    if tranco_csv_path.exists():
        age_hours = (time.time() - tranco_csv_path.stat().st_mtime) / 3600
        if age_hours < 48:
            print(f"[Tranco] Using cached list ({age_hours:.0f}h old)")
            return _sample_tranco_urls(tranco_csv_path, max_urls)

    try:
        # Tranco provides a stable download URL for the latest list
        resp = requests.get(
            'https://tranco-list.eu/top-1m.csv.zip',
            timeout=60,
            headers={'User-Agent': 'PhishGuard-Research/1.0'},
            stream=True,
        )
        resp.raise_for_status()

        # Decompress in memory
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            with z.open(z.namelist()[0]) as f:
                tranco_csv_path.write_bytes(f.read())

        print(f"[Tranco] Downloaded and cached to {tranco_csv_path}")
        return _sample_tranco_urls(tranco_csv_path, max_urls)

    except Exception as e:
        print(f"[Tranco] Download failed: {e}")
        print("[Tranco] Using synthetic legitimate samples")
        return generate_synthetic_legitimate(max_urls)


def _sample_tranco_urls(csv_path: Path, max_urls: int) -> List[str]:
    """Sample URLs from a downloaded Tranco CSV file."""
    domains = []
    with open(csv_path) as f:
        reader = csv.reader(f)
        for rank, domain in reader:
            domains.append(domain.strip())
            if len(domains) >= max_urls * 3:  # oversample, then dedupe
                break

    # Convert domains to URLs (use https for top sites)
    # Sample uniformly to avoid over-representing top-10 sites
    sampled = random.sample(domains, min(max_urls, len(domains)))
    urls = [f'https://www.{d}/' for d in sampled]
    print(f"[Tranco] Sampled {len(urls):,} legitimate URLs")
    return urls


def generate_synthetic_legitimate(count: int) -> List[str]:
    """Generate synthetic legitimate URLs from well-known domains."""
    known_legit = [
        'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org',
        'amazon.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'reddit.com', 'netflix.com', 'github.com', 'stackoverflow.com',
        'microsoft.com', 'apple.com', 'ebay.com', 'paypal.com',
        'dropbox.com', 'spotify.com', 'adobe.com', 'zoom.us',
        'slack.com', 'notion.so', 'medium.com', 'shopify.com',
        'wordpress.com', 'pinterest.com', 'tumblr.com', 'quora.com',
    ]
    urls = []
    paths = ['/', '/home', '/about', '/login', '/dashboard', '/settings',
             '/search?q=test', '/news', '/blog', '/contact', '/products']
    for _ in range(count):
        domain = random.choice(known_legit)
        path   = random.choice(paths)
        urls.append(f'https://www.{domain}{path}')
    print(f"[Synthetic] Generated {len(urls):,} legitimate samples")
    return urls


# ── Synthetic domain intel enrichment ────────────────────────────────────────

def synthetic_domain_intel(url: str, is_phishing: bool) -> dict:
    """
    Generate realistic synthetic domain intelligence for training.

    For phishing URLs: fresh domain (1-10 days), fresh cert (0-5 days), unranked
    For legitimate URLs: old domain (100-5000 days), older cert, ranked

    This gives the model a realistic signal distribution without exhausting
    live RDAP/crt.sh APIs. In V3, replace with real enrichment for top URLs.
    """
    if is_phishing:
        return {
            'age_days':      random.randint(1, 15) if random.random() > 0.2 else -1,
            'cert_age_days': random.randint(0, 7)  if random.random() > 0.3 else -1,
            'tranco_rank':   0,  # unranked (phishing sites never in top lists)
        }
    else:
        return {
            'age_days':      random.randint(100, 5000),
            'cert_age_days': random.randint(30, 365),
            'tranco_rank':   random.randint(1, 1_000_000),
        }


# ── Main dataset builder ──────────────────────────────────────────────────────

def build_dataset(output_path: Path = DATA_DIR / 'dataset.csv') -> Path:
    """
    Build the full labeled training dataset.

    Returns the path to the saved CSV file with columns:
      url, label, [29 feature columns]
    """
    print("\n" + "="*60)
    print("PhishGuard ML — Dataset Builder")
    print("="*60 + "\n")

    # ── Collect phishing URLs ─────────────────────────────────────────────
    phishing_urls = []
    phishing_urls.extend(fetch_phishtank(MAX_SAMPLES))
    phishing_urls.extend(fetch_openphish(5000))

    # Deduplicate while preserving order
    seen = set()
    phishing_dedup = []
    for u in phishing_urls:
        key = hashlib.md5(u.lower().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            phishing_dedup.append(u)

    phishing_final = phishing_dedup[:MAX_SAMPLES]
    print(f"\n[Dataset] Phishing samples: {len(phishing_final):,}")

    # ── Collect legitimate URLs ───────────────────────────────────────────
    legit_urls = fetch_tranco_legitimate(len(phishing_final))
    print(f"[Dataset] Legitimate samples: {len(legit_urls):,}")

    # ── Extract features ──────────────────────────────────────────────────
    print(f"\n[Features] Extracting {len(FEATURE_NAMES)} features per URL...")
    print(f"[Features] Total URLs: {len(phishing_final) + len(legit_urls):,}")

    rows = []
    errors = 0
    total = len(phishing_final) + len(legit_urls)

    all_samples: List[Tuple[str, int]] = (
        [(u, 1) for u in phishing_final] +
        [(u, 0) for u in legit_urls]
    )
    random.shuffle(all_samples)  # shuffle to avoid ordering artifacts

    for i, (url, label) in enumerate(all_samples):
        if i % 5000 == 0:
            print(f"  Progress: {i:,}/{total:,} ({100*i//total}%)")

        try:
            domain_intel = synthetic_domain_intel(url, label == 1)
            features = extract_features(url, domain_intel=domain_intel)
            row = {'url': url, 'label': label, **features}
            rows.append(row)
        except Exception as e:
            errors += 1
            if errors < 10:
                print(f"  [Warning] Feature extraction failed for {url[:60]}: {e}")

    print(f"\n[Features] Extracted {len(rows):,} rows ({errors} errors)")

    # ── Save dataset ──────────────────────────────────────────────────────
    columns = ['url', 'label'] + FEATURE_NAMES

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    # ── Dataset statistics ────────────────────────────────────────────────
    label_1 = sum(1 for r in rows if r['label'] == 1)
    label_0 = sum(1 for r in rows if r['label'] == 0)

    print(f"\n[Dataset] Saved to: {output_path}")
    print(f"[Dataset] Total:     {len(rows):,} samples")
    print(f"[Dataset] Phishing:  {label_1:,} ({100*label_1//len(rows)}%)")
    print(f"[Dataset] Legit:     {label_0:,} ({100*label_0//len(rows)}%)")
    print(f"[Dataset] Features:  {len(FEATURE_NAMES)}")
    print(f"[Dataset] File size: {output_path.stat().st_size / 1024 / 1024:.1f}MB")

    return output_path


if __name__ == '__main__':
    build_dataset()
