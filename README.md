# Phishing-URL-Classifier
Rule-based phishing URL detector with improved heuristics and explainability.

## Features
- Detects suspicious patterns: IP addresses, `@`, punycode, suspicious TLDs
- Flags long query strings or excessive URL length (but ignores trusted domains like YouTube)
- Detects brand impersonation outside trusted domains (paypal, amazon, apple, bank, etc.)
- Flags hyphenated subdomains (common in phishing)
- Explains why each URL was judged (reason list)
- Outputs results to screen or CSV

## Usage
```bash
1. Create a virtualenv and install dependencies:
python -m venv venv
source venv/bin/activate // On Windows :- venv\Scripts\activate
pip install -r requirements.txt
```

## Verdict thresholds
- Score >= 3 → PHISHING
- Score >= 1 → SUSPICIOUS
- Score < 0 → SAFE

## Disclaimer
Educational purposes only. Do not use for unauthorized testing.