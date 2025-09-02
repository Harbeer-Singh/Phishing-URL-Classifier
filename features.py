"""
features.py - Feature extraction for phishing detector 
"""
import re
from urllib.parse import urlparse
import tldextract
import requests

IP_REGEX = re.compile(r"^(?:http[s]?://)?(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")
SUSPICIOUS_TLDS = {
    "zip","review","country","kim","ml","tk","pw","icu","gq","ga","cf","cn","top","xyz"
}
BRAND_KEYWORDS = ["paypal", "bank", "login", "secure", "update", "verify", "apple", "amazon"]
TRUSTED_DOMAINS = ["paypal.com", "amazon.com", "apple.com", "youtube.com", "google.com"]

def extract_domain(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    te = tldextract.extract(parsed.netloc)
    domain = ".".join(part for part in [te.domain, te.suffix] if part)
    subdomain = te.subdomain
    return domain.lower(), subdomain.lower(), parsed.geturl()

def has_at_symbol(url):
    return "@" in url

def count_dots(url):
    return url.count(".")

def has_ip_address(url):
    return bool(IP_REGEX.search(url))

def contains_punycode(url):
    return "xn--" in url.lower()

def suspicious_tld(url):
    try:
        domain, sub, _ = extract_domain(url)
        if not domain:
            return False
        tld = domain.split(".")[-1]
        return tld in SUSPICIOUS_TLDS
    except Exception:
        return False

def has_https(url):
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        if parsed.scheme == "https":
            return True
        resp = requests.head(url if url.startswith("http") else "http://" + url,
                             allow_redirects=True, timeout=5)
        return resp.url.startswith("https://")
    except Exception:
        return False

def invalid_ssl_cert(url):
    try:
        if not url.startswith("http"):
            url = "https://" + url
        requests.get(url, timeout=5, verify=True)
        return False
    except requests.exceptions.SSLError:
        return True
    except Exception:
        return False

def suspicious_length(url, total_threshold=150, query_threshold=100):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    total_len = len(url)
    query_len = len(parsed.query)
    if total_len > total_threshold:
        return True
    if query_len > query_threshold:
        return True
    return False

def has_double_slash_after_protocol(url):
    p = url.split("://",1)[-1]
    return "//" in p

def contains_brand_keyword(url):
    u = url.lower()
    return any(word in u for word in BRAND_KEYWORDS)

def is_trusted_domain(url):
    domain, _, _ = extract_domain(url)
    return domain in TRUSTED_DOMAINS

def has_hyphen_in_subdomain(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    first_label = parsed.netloc.split(".")[0]
    return "-" in first_label

def extract_features(url):
    feats = {}
    feats['url'] = url
    feats['has_at'] = has_at_symbol(url)
    feats['dots'] = count_dots(url)
    feats['has_ip'] = has_ip_address(url)
    feats['punycode'] = contains_punycode(url)
    feats['suspicious_tld'] = suspicious_tld(url)
    feats['uses_https'] = has_https(url)
    feats['invalid_cert'] = invalid_ssl_cert(url)
    feats['long_url'] = suspicious_length(url)
    feats['double_slash_path'] = has_double_slash_after_protocol(url)
    feats['brand_keyword'] = contains_brand_keyword(url)
    feats['trusted_domain'] = is_trusted_domain(url)
    feats['hyphen_subdomain'] = has_hyphen_in_subdomain(url)

    score = 0
    if feats['has_ip']: score += 3
    if feats['has_at']: score += 2
    if feats['punycode']: score += 2
    if feats['suspicious_tld']: score += 2
    if feats['dots'] > 5: score += 1
    if feats['double_slash_path']: score += 1
    if feats['long_url'] and not feats['trusted_domain']: score += 1
    if feats['invalid_cert']: score += 2
    if feats['brand_keyword'] and not feats['trusted_domain']: score += 3
    if feats['hyphen_subdomain']: score += 1
    if not feats['uses_https']: score += 2

    feats['score'] = score
    return feats
