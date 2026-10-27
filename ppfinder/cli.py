#!/usr/bin/env python3
"""
ppfinder - prototype pollution hunting tool (client-side + server-side, black-box).

Usage examples:
  python cli.py client -u https://test.com --inject-points query,hash -v
  python cli.py server -u https://api.test.com/update-profile --method POST \\
      --content-types json,urlencoded --body-template body.json --rate-limit 5 -o report.json
  python cli.py both -U targets.txt --threads 10 --rate-limit 20 -o results/

-u/--url accepts:
  - a single URL
  - a comma-separated list of URLs
  - the flag repeated multiple times
all of which can be combined with -U/--url-file (one URL per line).
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Make sure the project root is on sys.path regardless of how this script was
# invoked (direct, via a symlink such as `ppfinder` on PATH, or `python3
# /some/path/cli.py` from a different cwd). Without this, running it as a
# symlinked command from outside the project directory can fail to find the
# client_side/server_side/report packages on some Python/OS combinations.
_PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

if sys.version_info < (3, 8):
    print(
        f"error: ppfinder requires Python 3.8+, found {sys.version.split()[0]}.\n"
        f"       Install a newer Python 3 and re-run (e.g. 'python3.10 cli.py ...').",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import requests  # noqa: F401
except ImportError:
    print(
        "error: the 'requests' package is required for server-side scanning but is not installed.\n"
        "       Fix: pip install --break-system-packages -r requirements.txt\n"
        "       (or run install.sh, which handles this automatically)",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from client_side.browser import ClientSideScanner
except ImportError as e:
    if "playwright" in str(e).lower():
        print(
            "error: the 'playwright' package is required for client-side scanning but is not installed.\n"
            "       Fix: pip install --break-system-packages -r requirements.txt\n"
            "       Then:  python3 -m playwright install chromium\n"
            "       (or run install.sh, which handles both automatically)",
            file=sys.stderr,
        )
    else:
        print(f"error: failed to import client_side package: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"error: unexpected failure loading client_side package: {e}", file=sys.stderr)
    sys.exit(1)

from client_side import gadget_scan  # noqa: F401 (wired in future PoC flow)
from server_side.blackbox import BlackBoxScanner, RateLimiter
from report.html_report import write_json_report, write_html_report


def _check_playwright_browsers_installed():
    """
    Returns None if OK, or a user-facing error string if Chromium's browser
    binary (downloaded separately from the pip package) looks missing.
    """
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
                browser.close()
            except Exception as e:
                msg = str(e)
                if "Executable doesn't exist" in msg or "playwright install" in msg.lower():
                    return (
                        "error: Playwright's Chromium browser binary is not installed.\n"
                        "       Fix: python3 -m playwright install chromium\n"
                        "       (or, for missing OS libraries too: python3 -m playwright install chromium --with-deps)"
                    )
                return f"error: could not launch Chromium for client-side scanning: {msg}"
    except Exception as e:
        return f"error: unexpected failure checking Playwright browser install: {e}"
    return None


def parse_args():
    parser = argparse.ArgumentParser(
        prog="ppfinder",
        description="Prototype pollution hunting tool - client-side and server-side (black-box).",
    )

    parser.add_argument(
        "mode",
        choices=["client", "server", "both"],
        help="Which scan mode to run.",
    )

    # --- target selection (shared) ---
    parser.add_argument(
        "-u", "--url",
        action="append",
        default=[],
        help="Target URL. Accepts a single URL, a comma-separated list, "
             "or can be passed multiple times.",
    )
    parser.add_argument(
        "-U", "--url-file",
        help="File containing target URLs, one per line.",
    )

    # --- shared flags ---
    parser.add_argument("-o", "--output", help="Output path (without extension); writes .json and .html")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel workers across targets.")
    parser.add_argument("--rate-limit", type=float, default=5.0, help="Max requests/page-loads per second (shared across threads).")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds per request/page load.")
    parser.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080 (route through Burp).")
    parser.add_argument("--headers", help="Extra headers as JSON string, or path to a JSON file.")
    parser.add_argument("--payloads", help="Path to custom payload file (JSON) to extend/override defaults.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose per-attempt output.")
    parser.add_argument("--safe-mode", dest="safe_mode", action="store_true", default=True, help="Disable risky payloads (default).")
    parser.add_argument("--aggressive", dest="safe_mode", action="store_false", help="Enable risky/destructive payloads.")

    # --- client-side specific ---
    parser.add_argument("--headless", dest="headless", action="store_true", default=True, help="Run browser headless (default).")
    parser.add_argument("--no-headless", dest="headless", action="store_false", help="Show the browser window.")
    parser.add_argument(
        "--inject-points",
        default="query,hash,postmessage,localstorage",
        help="Comma-separated list: query,hash,postmessage,localstorage",
    )
    parser.add_argument("--gadget-scan", action="store_true", help="Attempt gadget/impact detection after confirming pollution.")
    parser.add_argument("--wait-for", type=int, default=500, help="Milliseconds to wait after page load before checking Object.prototype.")
    parser.add_argument("--browser", default="chromium", choices=["chromium", "firefox", "webkit"], help="Browser engine to use.")

    # --- server-side specific ---
    parser.add_argument("--content-types", default="json", help="Comma-separated: json,urlencoded,query")
    parser.add_argument("--method", default="POST", help="HTTP method for server-side requests.")
    parser.add_argument("--body-template", help="Path to a JSON file with a sample valid request body to merge payloads into.")
    parser.add_argument("--diff-baseline", type=int, default=2, help="Number of baseline requests before comparing.")

    return parser.parse_args()


def load_targets(args) -> list:
    targets = []
    for u in args.url:
        targets.extend([t.strip() for t in u.split(",") if t.strip()])

    if args.url_file:
        if not os.path.isfile(args.url_file):
            print(f"error: -U/--url-file not found: {args.url_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.url_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    # de-dupe, preserve order
    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)

    if not unique_targets:
        print("error: no targets provided. Use -u/--url or -U/--url-file.", file=sys.stderr)
        sys.exit(1)

    bad_targets = [t for t in unique_targets if not (t.startswith("http://") or t.startswith("https://"))]
    if bad_targets:
        print(
            "error: every target must start with http:// or https://. Invalid entries:\n  "
            + "\n  ".join(bad_targets),
            file=sys.stderr,
        )
        sys.exit(1)

    return unique_targets


def load_headers(args) -> dict:
    if not args.headers:
        return {}
    if os.path.isfile(args.headers):
        with open(args.headers, "r", encoding="utf-8") as f:
            return json.load(f)
    return json.loads(args.headers)


def load_body_template(args) -> dict:
    if not args.body_template:
        return {}
    with open(args.body_template, "r", encoding="utf-8") as f:
        return json.load(f)


def run_client_scan(url, args, extra_headers) -> list:
    scanner = ClientSideScanner(
        headless=args.headless,
        browser_type=args.browser,
        timeout_ms=int(args.timeout * 1000),
        wait_after_load_ms=args.wait_for,
        proxy=args.proxy,
        extra_headers=extra_headers,
        verbose=args.verbose,
    )
    points = [p.strip() for p in args.inject_points.split(",") if p.strip()]
    if args.verbose:
        print(f"[client] scanning {url} inject_points={points}")
    return scanner.scan(url, points)


def run_server_scan(url, args, extra_headers, rate_limiter, body_template) -> list:
    scanner = BlackBoxScanner(
        rate_limiter=rate_limiter,
        timeout=args.timeout,
        baseline_requests=args.diff_baseline,
        safe_mode=args.safe_mode,
        verbose=args.verbose,
        proxies={"http": args.proxy, "https": args.proxy} if args.proxy else None,
        extra_headers=extra_headers,
    )
    content_types = [c.strip() for c in args.content_types.split(",") if c.strip()]
    if args.verbose:
        print(f"[server] scanning {url} content_types={content_types} method={args.method}")
    return scanner.scan_endpoint(
        url,
        method=args.method,
        content_types=content_types,
        body_template=body_template,
    )


def main():
    args = parse_args()

    if args.mode in ("client", "both"):
        browser_err = _check_playwright_browsers_installed()
        if browser_err:
            print(browser_err, file=sys.stderr)
            sys.exit(1)

    targets = load_targets(args)

    try:
        extra_headers = load_headers(args)
    except FileNotFoundError:
        print(f"error: --headers file not found: {args.headers}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: --headers is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        body_template = load_body_template(args)
    except FileNotFoundError:
        print(f"error: --body-template file not found: {args.body_template}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: --body-template is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if args.proxy and not (args.proxy.startswith("http://") or args.proxy.startswith("https://")):
        print(f"error: --proxy must start with http:// or https:// (got: {args.proxy!r})", file=sys.stderr)
        sys.exit(1)

    rate_limiter = RateLimiter(rate=args.rate_limit)

    all_client_findings = []
    all_server_findings = []

    def process_target(url):
        c_findings, s_findings = [], []
        if args.mode in ("client", "both"):
            try:
                c_findings = run_client_scan(url, args, extra_headers)
            except Exception as e:
                print(f"[client] error scanning {url}: {e}", file=sys.stderr)
        if args.mode in ("server", "both"):
            try:
                s_findings = run_server_scan(url, args, extra_headers, rate_limiter, body_template)
            except Exception as e:
                print(f"[server] error scanning {url}: {e}", file=sys.stderr)
        return c_findings, s_findings

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_target, url): url for url in targets}
        for future in as_completed(futures):
            url = futures[future]
            c_findings, s_findings = future.result()
            all_client_findings.extend(c_findings)
            all_server_findings.extend(s_findings)
            polluted_count = sum(1 for f in c_findings if f.polluted)
            notable_count = len(s_findings)
            print(f"[done] {url} -> client: {polluted_count} polluted / {len(c_findings)} tested, "
                  f"server: {notable_count} notable findings")

    meta = {
        "targets": targets,
        "mode": args.mode,
        "safe_mode": args.safe_mode,
    }

    if args.output:
        json_path = args.output if args.output.endswith(".json") else args.output + ".json"
        html_path = args.output.replace(".json", "") + ".html"
        write_json_report(json_path, all_client_findings, all_server_findings, meta)
        write_html_report(html_path, all_client_findings, all_server_findings, meta)
        print(f"[report] JSON: {json_path}")
        print(f"[report] HTML: {html_path}")
    else:
        print("\n--- Summary ---")
        print(f"Client-side polluted: {sum(1 for f in all_client_findings if f.polluted)}")
        print(f"Server-side notable:  {len(all_server_findings)}")
        print("(use -o/--output to write a full report)")


if __name__ == "__main__":
    main()
