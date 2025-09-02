"""
detector.py - CLI for phishing detector (improved version)
"""
import argparse, csv, sys
from features import extract_features

def verdict_from_score(score):
    if score >= 3:
        return "Phishing"
    if score >= 1:
        return "Suspicious"
    return "Safe"

def reasons_from_feats(feats):
    reasons = []
    if feats.get('has_ip'): reasons.append("contains IP address")
    if feats.get('has_at'): reasons.append("contains '@' symbol")
    if feats.get('punycode'): reasons.append("contains punycode/xn-- (possible homograph)")
    if feats.get('suspicious_tld'): reasons.append("uses suspicious TLD")
    if feats.get('dots',0) > 5: reasons.append("many subdomains/dots")
    if feats.get('double_slash_path'): reasons.append("double slash in path")
    if feats.get('long_url') and not feats.get('trusted_domain'): reasons.append("very long URL / query string")
    if not feats.get('uses_https'): reasons.append("no HTTPS / not using TLS")
    if feats.get('invalid_cert'): reasons.append("invalid/expired SSL certificate")
    if feats.get('brand_keyword') and not feats.get('trusted_domain'):
        reasons.append("brand keyword in non-official domain (possible impersonation)")
    if feats.get('hyphen_subdomain'): reasons.append("hyphenated subdomain (commonly used in phishing)")
    return reasons or ["no obvious rule-based flags"]

def scan_url(url):
    feats = extract_features(url)
    verdict = verdict_from_score(feats['score'])
    reasons = reasons_from_feats(feats)
    return {
        "url": url,
        "verdict": verdict,
        "score": feats['score'],
        "reasons": "; ".join(reasons)
    }

def scan_file(path, out_csv):
    results = []
    with open(path, "r") as f:
        for line in f:
            u = line.strip()
            if not u: continue
            results.append(scan_url(u))
    keys = ["url","verdict","score","reasons"]
    with open(out_csv, "w", newline="", encoding="utf-8") as wf:
        writer = csv.DictWriter(wf, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)
    return results

def scan_single(url):
    res = scan_url(url)
    print("URL:", res['url'])
    print("Verdict:", res['verdict'].upper(), f"(score={res['score']})")
    print("Reasons:")
    for r in res['reasons'].split("; "):
        print(" -", r)
    return res

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", type=str, help="Single URL to analyze")
    p.add_argument("--file", type=str, help="File containing newline-separated URLs")
    p.add_argument("--out", type=str, default="results.csv", help="Output CSV path (for --file)")
    args = p.parse_args()
    if not args.url and not args.file:
        p.print_help(); sys.exit(1)
    if args.url:
        scan_single(args.url)
    if args.file:
        res = scan_file(args.file, args.out)
        print(f"Scanned {len(res)} URLs. Results saved to {args.out}")

if __name__ == '__main__':
    main()
