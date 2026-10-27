"""
Black-box server-side prototype pollution scanner.

Sends a baseline request, then a polluted request per payload per
content-type, and uses diff_engine to flag notable differences.
Supports a simple token-bucket rate limiter shared across all requests
regardless of thread count.
"""

import copy
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import requests

from . import payloads as pl
from .diff_engine import ResponseSnapshot, DiffResult, build_baseline, diff_responses


class RateLimiter:
    """Simple thread-safe token bucket: allows up to `rate` requests/sec."""

    def __init__(self, rate: float):
        self.rate = rate
        self.lock = threading.Lock()
        self.tokens = rate
        self.last_check = time.monotonic()

    def acquire(self):
        if self.rate <= 0:
            return
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_check
            self.last_check = now
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1


@dataclass
class ServerFinding:
    url: str
    method: str
    content_type: str
    payload_name: str
    payload_path: list
    diff: DiffResult
    request_repr: str


class BlackBoxScanner:
    def __init__(
        self,
        session: Optional[requests.Session] = None,
        rate_limiter: Optional[RateLimiter] = None,
        timeout: float = 10.0,
        baseline_requests: int = 2,
        safe_mode: bool = True,
        verbose: bool = False,
        proxies: Optional[dict] = None,
        extra_headers: Optional[dict] = None,
    ):
        self.session = session or requests.Session()
        self.rate_limiter = rate_limiter or RateLimiter(rate=5)
        self.timeout = timeout
        self.baseline_requests = max(1, baseline_requests)
        self.safe_mode = safe_mode
        self.verbose = verbose
        self.proxies = proxies
        self.extra_headers = extra_headers or {}

    def _send(self, url, method, content_type, body=None, params=None) -> ResponseSnapshot:
        self.rate_limiter.acquire()

        headers = dict(self.extra_headers)
        data = None
        json_body = None

        if content_type == "json":
            headers["Content-Type"] = "application/json"
            json_body = body
        elif content_type == "urlencoded":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = body
        elif content_type == "query":
            pass  # body goes in params instead

        start = time.monotonic()
        resp = self.session.request(
            method=method,
            url=url,
            params=params if content_type == "query" else None,
            json=json_body if content_type == "json" else None,
            data=data if content_type == "urlencoded" else None,
            headers=headers,
            timeout=self.timeout,
            proxies=self.proxies,
            verify=True,
        )
        elapsed_ms = (time.monotonic() - start) * 1000

        return ResponseSnapshot(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            elapsed_ms=elapsed_ms,
        )

    def _merge_body_template(self, template: dict, path: list, value) -> dict:
        """Deep-copy template and merge in the pollution path/value."""
        merged = copy.deepcopy(template) if template else {}
        nested = pl.nest_payload(path, value)
        # shallow merge at top level is enough since pollution path starts
        # fresh (e.g. __proto__) and won't collide with template's own keys
        merged.update(nested)
        return merged

    def scan_endpoint(
        self,
        url: str,
        method: str = "POST",
        content_types: list = None,
        body_template: dict = None,
    ) -> list:
        content_types = content_types or ["json"]
        findings = []

        payload_defs = pl.build_safe_payloads(pl.random_marker())
        if not self.safe_mode:
            payload_defs += pl.build_aggressive_payloads(pl.random_marker())

        for content_type in content_types:
            # 1. Establish baseline
            baseline_snapshots = []
            for _ in range(self.baseline_requests):
                if content_type == "query":
                    snap = self._send(url, method, content_type, params=body_template or {})
                else:
                    snap = self._send(url, method, content_type, body=body_template or {})
                baseline_snapshots.append(snap)

            baseline = build_baseline(baseline_snapshots)

            # 2. Send each payload and diff against baseline
            for pdef in payload_defs:
                marker = None
                for p in pdef["path"]:
                    if p.startswith("ppfs_"):
                        marker = p

                if content_type == "query":
                    frag_value = pl.flatten_to_bracket_query(pdef["path"], pdef["value"])
                    key, _, val = frag_value.partition("=")
                    params = dict(body_template or {})
                    params[key] = val
                    polluted_snap = self._send(url, method, content_type, params=params)
                    request_repr = f"{method} {url}?{key}={val}"
                elif content_type == "urlencoded":
                    form_pair = pl.flatten_to_form_body(pdef["path"], pdef["value"])
                    data = dict(body_template or {})
                    data.update(form_pair)
                    polluted_snap = self._send(url, method, content_type, body=data)
                    request_repr = f"{method} {url} (form) {form_pair}"
                else:  # json
                    merged = self._merge_body_template(body_template, pdef["path"], pdef["value"])
                    polluted_snap = self._send(url, method, content_type, body=merged)
                    request_repr = f"{method} {url} (json) {json.dumps(merged)}"

                diff = diff_responses(baseline, polluted_snap, marker=marker)

                finding = ServerFinding(
                    url=url,
                    method=method,
                    content_type=content_type,
                    payload_name=pdef["name"],
                    payload_path=pdef["path"],
                    diff=diff,
                    request_repr=request_repr,
                )

                if self.verbose:
                    status = "NOTABLE" if diff.notable else "clean"
                    print(f"  [{content_type}/{pdef['name']}] {status} - {diff.details}")

                if diff.notable:
                    findings.append(finding)

        return findings
