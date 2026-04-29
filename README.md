# HeadHunter – Security Header Scanner with PoC Screenshot Generator

### Note
- crawler.py or dynamic_crawler.py is another tool that I created for my workflow you can find them on https://github.com/U2kn0wn/dynamic_web_crawler


## Overview

`headhunter.py` is a post-processing security validation tool that uses URLs collected from:

* `crawler.py` → static crawler
* `dynamic_crawler.py` → JavaScript-aware crawler

It randomly selects up to **10 URLs** from a crawler CSV output, checks each target for missing or weak HTTP security headers, and automatically generates a **visual proof-of-concept screenshot** for each issue.

---

## Features

* Reads URLs from crawler CSV output
* Randomly samples 10 URLs
* Sends HTTP requests to each target
* Detects missing security headers
* Detects weak CSP policies
* Captures browser-based screenshots
* Saves evidence inside:

```id="t2x8mv"
POC/
```

---

## Checked Security Headers

The tool checks for:

* `Content-Security-Policy`
* `X-Frame-Options`
* `X-Content-Type-Options`
* `Strict-Transport-Security`
* `Referrer-Policy`
* `Permissions-Policy`

Additional validation:

* Flags CSP if it contains:

  * `unsafe-inline`
  * wildcard `*`

---

## Project Structure

```id="w3zr6h"
.
├── crawler.py
├── dynamic_crawler.py
├── headhunter.py
├── requirements.txt
├── README.md
└── POC/
```

---

## Installation

Install Python dependencies:

```bash id="n9y2as"
pip install -r requirements.txt
```

Install Playwright browser binaries:

```bash id="r4h7cd"
playwright install
```

---

## Usage

### Basic Scan

```bash id="f1u9kg"
python headhunter.py -f output.csv
```

---

### With Custom Headers

```bash id="p7x3dr"
python headhunter.py -f output.csv -H "Authorization: Bearer TOKEN"
```

You can provide multiple headers:

```bash id="m5q8zy"
python headhunter.py -f output.csv \
-H "Authorization: Bearer TOKEN" \
-H "Cookie: session=abc123"
```

---

## Input File Format

The CSV file must contain a column named:

```id="j6w4nv"
url
```

Example:

```csv id="y2e8kc"
url
https://example.com
https://example.com/login
https://example.com/dashboard
```

---

## Example Workflow

### Step 1 — Run Static Crawler

```bash id="x8g2sl"
python crawler.py -u https://target.com
```

### Step 2 — Run Dynamic Crawler

```bash id="q3v7pb"
python dynamic_crawler.py -u https://target.com
```

### Step 3 — Scan for Security Headers

```bash id="l4z1mr"
python headhunter.py -f target_urls.csv
```

---

## Output

Example console output:

```id="h8k5tc"
[+] Scanning 10 URLs...

[+] https://example.com -> ['X-Frame-Options', 'Referrer-Policy']
[+] https://example.com/login -> ['Content-Security-Policy']

[+] Scan Complete. Generating POCs...
[+] POC saved: POC/X-Frame-Options.png
```

---

## Generated Evidence

Each missing header produces a screenshot:

```id="d9m2xf"
POC/
├── X-Frame-Options.png
├── Referrer-Policy.png
└── Content-Security-Policy.png
```

Each image includes:

* Request details
* Response headers
* Response preview
* Target URL

---

## Example Command

```bash id="s2k7ju"
python headhunter.py -f results.csv -H "Cookie: SESSIONID=xxxx"
```

---

## Notes

* Only one screenshot is generated per finding type.
* Maximum 10 URLs are tested per run.
* URLs are selected randomly from the CSV.
* The script uses threading for faster scanning.

---

## Legal Warning

Use this tool only on:

* systems you own
* systems you are authorized to test

Unauthorized scanning may violate laws or policies.

---

## License

For educational and authorized security testing purposes only.
