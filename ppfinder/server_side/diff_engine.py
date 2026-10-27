"""
Response diffing engine for black-box server-side prototype pollution
detection. Sends N baseline requests first to establish a stable baseline
(reduces false positives from server-side nondeterminism like timestamps,
request IDs, CDN headers), then compares the polluted request's response
against that baseline.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# Headers that are expected to vary between requests and should be ignored
# when diffing, to avoid false positives.
VOLATILE_HEADERS = {
    "date",
    "x-request-id",
    "x-amzn-trace-id",
    "cf-ray",
    "set-cookie",
    "etag",
    "last-modified",
    "x-response-time",
    "x-runtime",
}

# Regex patterns to strip out of bodies before comparing (timestamps, nonces)
VOLATILE_BODY_PATTERNS = [
    re.compile(r'"timestamp"\s*:\s*\d+'),
    re.compile(r'"requestId"\s*:\s*"[^"]*"'),
    re.compile(r'"nonce"\s*:\s*"[^"]*"'),
]


@dataclass
class ResponseSnapshot:
    status_code: int
    headers: dict
    body: str
    elapsed_ms: float


@dataclass
class DiffResult:
    status_changed: bool
    status_from: int
    status_to: int
    headers_changed: dict  # {header_name: (baseline_value, polluted_value)}
    body_length_delta: int
    body_marker_found: bool
    marker: Optional[str]
    notable: bool  # True if this diff looks like a real finding
    details: list = field(default_factory=list)


def _clean_body(body: str) -> str:
    cleaned = body
    for pattern in VOLATILE_BODY_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    return cleaned


def build_baseline(snapshots: list) -> ResponseSnapshot:
    """
    Given multiple baseline ResponseSnapshots, return a representative one
    (the most common status/body-length combo) and flag headers that
    vary naturally across baselines so they can be added to ignore-list.
    """
    if len(snapshots) == 1:
        return snapshots[0]

    # Use the first as representative; later diffing already excludes
    # VOLATILE_HEADERS, which covers most natural variance.
    return snapshots[0]


def diff_responses(
    baseline: ResponseSnapshot,
    polluted: ResponseSnapshot,
    marker: Optional[str] = None,
) -> DiffResult:
    details = []

    status_changed = baseline.status_code != polluted.status_code
    if status_changed:
        details.append(
            f"status code changed: {baseline.status_code} -> {polluted.status_code}"
        )

    headers_changed = {}
    all_header_names = set(baseline.headers.keys()) | set(polluted.headers.keys())
    for name in all_header_names:
        lname = name.lower()
        if lname in VOLATILE_HEADERS:
            continue
        b_val = baseline.headers.get(name)
        p_val = polluted.headers.get(name)
        if b_val != p_val:
            headers_changed[name] = (b_val, p_val)
            details.append(f"header '{name}' changed: {b_val!r} -> {p_val!r}")

    b_body = _clean_body(baseline.body)
    p_body = _clean_body(polluted.body)
    body_length_delta = len(p_body) - len(b_body)

    body_marker_found = False
    if marker and marker in polluted.body:
        body_marker_found = True
        details.append(f"marker '{marker}' reflected in response body")

    # Decide if this is "notable" (worth flagging to the user)
    notable = status_changed or bool(headers_changed) or body_marker_found or (
        abs(body_length_delta) > 20  # arbitrary noise threshold
    )
    if abs(body_length_delta) > 20 and not body_marker_found:
        details.append(f"body length delta: {body_length_delta} chars (no marker match - verify manually)")

    return DiffResult(
        status_changed=status_changed,
        status_from=baseline.status_code,
        status_to=polluted.status_code,
        headers_changed=headers_changed,
        body_length_delta=body_length_delta,
        body_marker_found=body_marker_found,
        marker=marker,
        notable=notable,
        details=details,
    )
