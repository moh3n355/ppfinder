"""
Client-side prototype pollution scanner using Playwright.

For each injection point (query, hash, postmessage, localstorage) and each
payload variant, loads the target page with a unique marker injected, then
checks Object.prototype[<marker>] inside the page context. Captures
console/page errors along the way for debugging and evidence.
"""

import json
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

from . import payloads as pl


@dataclass
class Finding:
    url: str
    inject_point: str
    payload_name: str
    payload_raw: str
    marker: str
    polluted: bool
    console_logs: list = field(default_factory=list)
    page_errors: list = field(default_factory=list)
    evidence: Optional[str] = None


class ClientSideScanner:
    def __init__(
        self,
        headless: bool = True,
        browser_type: str = "chromium",
        timeout_ms: int = 8000,
        wait_after_load_ms: int = 500,
        proxy: Optional[str] = None,
        extra_headers: Optional[dict] = None,
        verbose: bool = False,
    ):
        self.headless = headless
        self.browser_type = browser_type
        self.timeout_ms = timeout_ms
        self.wait_after_load_ms = wait_after_load_ms
        self.proxy = proxy
        self.extra_headers = extra_headers or {}
        self.verbose = verbose

    def _launch_args(self):
        args = {"headless": self.headless}
        if self.proxy:
            args["proxy"] = {"server": self.proxy}
        return args

    def _check_prototype_polluted(self, page, marker: str) -> bool:
        """Check Object.prototype[marker] inside the page's JS context."""
        try:
            result = page.evaluate(
                """(marker) => {
                    try {
                        return Object.prototype[marker] !== undefined;
                    } catch (e) {
                        return false;
                    }
                }""",
                marker,
            )
            return bool(result)
        except Exception:
            return False

    def _attach_listeners(self, page, finding: Finding):
        def on_console(msg):
            try:
                finding.console_logs.append(f"[{msg.type}] {msg.text}")
            except Exception:
                pass

        def on_pageerror(exc):
            finding.page_errors.append(str(exc))

        page.on("console", on_console)
        page.on("pageerror", on_pageerror)

    def scan_query_or_hash(self, base_url: str, point: str, context) -> list:
        """point is 'query' or 'hash'."""
        results = []
        builder = pl.INJECT_POINTS[point]

        # Important: generate ONE marker and reuse it for every payload variant
        # returned by this builder call, and use that known value directly for
        # the Object.prototype check instead of re-parsing it out of the
        # payload string. Parsing it back out is fragile for multi-bracket
        # payloads (e.g. a[__proto__][marker]) and was previously grabbing the
        # wrong bracket segment (e.g. "__proto__" or "prototype"), which are
        # themselves accessor properties on Object.prototype that return
        # `null` rather than `undefined` - causing a false POLLUTED verdict
        # on every single payload, vulnerable or not.
        marker = pl.random_marker()

        for payload_name, frag in builder(marker):
            parsed = urllib.parse.urlsplit(base_url)
            if point == "query":
                existing_q = parsed.query
                new_q = f"{existing_q}&{frag}" if existing_q else frag
                test_url = urllib.parse.urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, new_q, "")
                )
            else:  # hash
                test_url = urllib.parse.urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.query, frag)
                )

            page = context.new_page()
            if self.extra_headers:
                page.set_extra_http_headers(self.extra_headers)

            finding = Finding(
                url=test_url,
                inject_point=point,
                payload_name=payload_name,
                payload_raw=frag,
                marker=marker,
                polluted=False,
            )
            self._attach_listeners(page, finding)

            try:
                page.goto(test_url, timeout=self.timeout_ms, wait_until="load")
                if self.wait_after_load_ms:
                    page.wait_for_timeout(self.wait_after_load_ms)
                finding.polluted = self._check_prototype_polluted(page, marker)
                if finding.polluted:
                    finding.evidence = f"Object.prototype['{marker}'] !== undefined"
            except PWTimeout:
                finding.page_errors.append("navigation timeout")
            except Exception as e:
                finding.page_errors.append(f"error: {e}")
            finally:
                page.close()

            if self.verbose:
                status = "POLLUTED" if finding.polluted else "clean"
                print(f"  [{point}/{payload_name}] {status} -> {test_url}")

            results.append(finding)

        return results

    def scan_postmessage(self, base_url: str, context) -> list:
        results = []
        marker = pl.random_marker()
        for payload_name, message in pl.build_postmessage_payloads(marker):
            page = context.new_page()
            if self.extra_headers:
                page.set_extra_http_headers(self.extra_headers)

            finding = Finding(
                url=base_url,
                inject_point="postmessage",
                payload_name=payload_name,
                payload_raw=json.dumps(message),
                marker=marker,
                polluted=False,
            )
            self._attach_listeners(page, finding)

            try:
                page.goto(base_url, timeout=self.timeout_ms, wait_until="load")
                page.evaluate(
                    """(msg) => { window.postMessage(msg, '*'); }""",
                    message,
                )
                if self.wait_after_load_ms:
                    page.wait_for_timeout(self.wait_after_load_ms)
                finding.polluted = self._check_prototype_polluted(page, marker)
                if finding.polluted:
                    finding.evidence = f"Object.prototype['{marker}'] !== undefined after postMessage"
            except PWTimeout:
                finding.page_errors.append("navigation timeout")
            except Exception as e:
                finding.page_errors.append(f"error: {e}")
            finally:
                page.close()

            if self.verbose:
                status = "POLLUTED" if finding.polluted else "clean"
                print(f"  [postmessage/{payload_name}] {status}")

            results.append(finding)

        return results

    def scan_localstorage(self, base_url: str, context) -> list:
        results = []
        marker_key = pl.random_marker()
        for payload_name, key, value_json in pl.build_localstorage_payloads(marker_key):
            page = context.new_page()
            if self.extra_headers:
                page.set_extra_http_headers(self.extra_headers)

            finding = Finding(
                url=base_url,
                inject_point="localstorage",
                payload_name=payload_name,
                payload_raw=f"{key}={value_json}",
                marker=marker_key,
                polluted=False,
            )
            self._attach_listeners(page, finding)

            try:
                # Need to visit once to set origin context before localStorage write
                page.goto(base_url, timeout=self.timeout_ms, wait_until="load")
                page.evaluate(
                    """([k, v]) => { localStorage.setItem(k, v); }""",
                    [key, value_json],
                )
                # reload so app code re-parses localStorage on init
                page.reload(timeout=self.timeout_ms, wait_until="load")
                if self.wait_after_load_ms:
                    page.wait_for_timeout(self.wait_after_load_ms)
                finding.polluted = self._check_prototype_polluted(page, marker_key)
                if finding.polluted:
                    finding.evidence = f"Object.prototype['{marker_key}'] !== undefined after localStorage reload"
            except PWTimeout:
                finding.page_errors.append("navigation timeout")
            except Exception as e:
                finding.page_errors.append(f"error: {e}")
            finally:
                page.close()

            if self.verbose:
                status = "POLLUTED" if finding.polluted else "clean"
                print(f"  [localstorage/{payload_name}] {status}")

            results.append(finding)

        return results

    def scan(self, url: str, inject_points: list) -> list:
        """
        Run all requested inject_points against url.
        inject_points: subset of ['query', 'hash', 'postmessage', 'localstorage']
        """
        all_results = []
        with sync_playwright() as p:
            browser_launcher = getattr(p, self.browser_type)
            browser = browser_launcher.launch(**self._launch_args())
            context = browser.new_context()

            if "query" in inject_points:
                all_results += self.scan_query_or_hash(url, "query", context)
            if "hash" in inject_points:
                all_results += self.scan_query_or_hash(url, "hash", context)
            if "postmessage" in inject_points:
                all_results += self.scan_postmessage(url, context)
            if "localstorage" in inject_points:
                all_results += self.scan_localstorage(url, context)

            browser.close()

        return all_results
