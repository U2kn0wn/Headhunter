import argparse
import pandas as pd
import requests
import os
from concurrent.futures import ThreadPoolExecutor
import threading
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse

# ---------------------------
# Headers to check
# ---------------------------
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

# ---------------------------
# Global storage
# ---------------------------
findings_data = {}
lock = threading.Lock()


# ---------------------------
# Build Realistic Request
# ---------------------------
def build_request_text(response):
    req = response.request
    parsed = urlparse(req.url)

    path = parsed.path if parsed.path else "/"
    if parsed.query:
        path += "?" + parsed.query

    request_text = f"{req.method} {path} HTTP/1.1\n"

    for k, v in req.headers.items():
        request_text += f"{k}: {v}\n"

    return request_text


# ---------------------------
# Checker
# ---------------------------
def Checker(url, headers):
    try:
        response = requests.get(url, headers=headers, timeout=10)

        local_findings = []

        for sec_header in SECURITY_HEADERS:
            if sec_header not in response.headers:
                local_findings.append(sec_header)

        # CSP validation
        csp = response.headers.get("Content-Security-Policy")
        if csp:
            if "unsafe-inline" in csp or "*" in csp:
                local_findings.append("Content-Security-Policy_Misconfigured")
        else:
            local_findings.append("Content-Security-Policy")

        with lock:
            for finding in local_findings:
                if finding not in findings_data:
                    findings_data[finding] = {
                        "count": 0,
                        "example_url": url,
                        "response_headers": dict(response.headers),
                        "response_body": response.text,
                        "request_text": build_request_text(response),
                        "status_code": response.status_code
                    }
                findings_data[finding]["count"] += 1

        print(f"[+] {url} -> {local_findings}")

    except Exception as e:
        print(f"[!] Error for {url}: {e}")


# ---------------------------
# POC Generator
# ---------------------------
def POC_genr(finding_name, data):

    if not os.path.exists("POC"):
        os.makedirs("POC")

    url = data["example_url"]

    response_text = f"HTTP/1.1 {data['status_code']}\n"
    for k, v in data["response_headers"].items():
        response_text += f"{k}: {v}\n"

    body_preview = data["response_body"][:2000]
    request_text = data["request_text"]

    html_content = f"""
    <html>
    <head>
    <style>
    body {{
        font-family: monospace;
        background: #1e1e1e;
        color: #d4d4d4;
        margin: 0;
    }}

    .header {{
        padding: 10px;
        border-bottom: 1px solid #444;
    }}

    .container {{
        display: flex;
        height: 95vh;
    }}

    .panel {{
        width: 50%;
        padding: 10px;
        overflow: auto;
        border-right: 1px solid #444;
    }}

    .panel:last-child {{
        border-right: none;
    }}

    .title {{
        color: #9cdcfe;
        margin-bottom: 10px;
        font-weight: bold;
    }}

    pre {{
        white-space: pre-wrap;
        word-wrap: break-word;
    }}
    </style>
    </head>

    <body>

    <div class="header">
        <b>Target:</b> {url}
    </div>

    <div class="container">
        <div class="panel">
            <div class="title">Request</div>
            <pre>{request_text}</pre>
        </div>

        <div class="panel">
            <div class="title">Response</div>
            <pre>{response_text}</pre>
            <pre>{body_preview}</pre>
        </div>
    </div>

    </body>
    </html>
    """

    temp_file = "temp.html"
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    safe_name = finding_name.replace(" ", "_").replace("/", "_")
    screenshot_name = f"POC/{safe_name}.png"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f"file://{os.path.abspath(temp_file)}")
            page.screenshot(path=screenshot_name, full_page=True)
            browser.close()

        print(f"[+] POC saved: {screenshot_name}")

    except Exception as e:
        print(f"[!] POC generation failed: {e}")

    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


# ---------------------------
# Main
# ---------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-H", "--header", action='append')

    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()

    df = pd.read_csv(args.file)

    if "url" not in df.columns:
        print("[!] CSV must have 'URL'")
        return

    urls = df["url"].dropna().sample(n=min(10, len(df))).tolist()

    print(f"[+] Scanning {len(urls)} URLs...\n")

    # Threaded scan
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(lambda url: Checker(url, headers), urls)

    print("\n[+] Scan Complete. Generating POCs...\n")

    # Sequential POC generation
    for finding, data in findings_data.items():
        print(f"[+] {finding} found in {data['count']} URLs")
        POC_genr(finding, data)


if __name__ == "__main__":
    main()
