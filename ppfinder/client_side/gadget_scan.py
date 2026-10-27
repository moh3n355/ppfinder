"""
Client-side gadget scanner.

After a prototype-pollution source is confirmed, this module tries to
identify exploitable "gadgets" - code paths that read an attacker-controlled
property off Object.prototype and do something dangerous with it
(XSS via innerHTML, attribute injection, script src injection, etc).

This is a best-effort heuristic scanner: it fingerprints common libraries
known to historically contain gadgets, and optionally attempts a live PoC
pollution + trigger to confirm real impact (DOM-based XSS via alert marker).
"""

from dataclasses import dataclass, field
from typing import Optional


# Known gadget fingerprints: (library, versions/pattern, prototype property,
# short description). Sourced from publicly documented research
# (e.g. BlackFan/client-side-prototype-pollution and PortSwigger write-ups).
KNOWN_GADGETS = [
    {
        "library": "jQuery",
        "detect_js": "window.jQuery ? window.jQuery.fn.jquery : null",
        "property": "context / data attributes via $.extend",
        "description": "Older jQuery $.extend(true, ...) deep-merge can be polluted; "
                        "some plugins read polluted props into HTML (XSS).",
        "min_affected": "<3.4.0 for $.extend gadget; check $.extend usage for sinks",
    },
    {
        "library": "AngularJS",
        "detect_js": "window.angular ? window.angular.version.full : null",
        "property": "various $$ bindings",
        "description": "AngularJS <1.8 had documented prototype pollution sinks "
                        "in merge/extend utilities feeding into template rendering.",
        "min_affected": "<1.8.0",
    },
    {
        "library": "Lodash",
        "detect_js": "window._ ? window._.VERSION : null",
        "property": "merge/defaultsDeep/zipObjectDeep",
        "description": "lodash merge/zipObjectDeep/defaultsDeep <4.17.12 vulnerable to "
                        "prototype pollution via crafted keys.",
        "min_affected": "<4.17.12",
    },
    {
        "library": "Vue",
        "detect_js": "window.Vue ? window.Vue.version : null",
        "property": "options merge internals",
        "description": "Some Vue 2.x plugin merge strategies historically mergeable "
                        "with proto pollution leading to template injection.",
        "min_affected": "varies by plugin",
    },
]

# Common DOM sinks to probe after pollution is confirmed, to test real impact
SINK_PROPERTIES = [
    "innerHTML",
    "outerHTML",
    "src",
    "href",
    "onerror",
    "onload",
]


@dataclass
class GadgetResult:
    library: str
    version: Optional[str]
    likely_vulnerable: bool
    description: str
    poc_triggered: bool = False
    poc_evidence: Optional[str] = None


def fingerprint_libraries(page) -> list:
    """Detect which known libraries are loaded on the page."""
    detected = []
    for gadget in KNOWN_GADGETS:
        try:
            version = page.evaluate(gadget["detect_js"])
        except Exception:
            version = None
        if version:
            detected.append({**gadget, "version": version})
    return detected


def attempt_xss_poc(page, marker: str) -> Optional[str]:
    """
    After pollution, check if any common sink properties ended up reflecting
    the polluted value into the DOM (heuristic XSS confirmation).
    Returns evidence string if found, else None.
    """
    try:
        evidence = page.evaluate(
            """(marker) => {
                const html = document.documentElement.outerHTML;
                if (html.includes(marker)) {
                    return 'marker value found reflected in DOM HTML';
                }
                return null;
            }""",
            marker,
        )
        return evidence
    except Exception:
        return None


def scan_gadgets(page, marker: str) -> list:
    """
    Run fingerprinting + heuristic PoC check. Returns a list of GadgetResult.
    Call this on a page where pollution has already been confirmed and the
    same `page` object / context is still polluted (same JS realm).
    """
    results = []
    detected_libs = fingerprint_libraries(page)

    for lib in detected_libs:
        poc_evidence = attempt_xss_poc(page, marker)
        results.append(
            GadgetResult(
                library=lib["library"],
                version=lib["version"],
                likely_vulnerable=True,  # library present = candidate, not confirmed
                description=lib["description"],
                poc_triggered=poc_evidence is not None,
                poc_evidence=poc_evidence,
            )
        )

    if not detected_libs:
        # Still attempt a generic DOM-reflection check even with no known lib
        poc_evidence = attempt_xss_poc(page, marker)
        if poc_evidence:
            results.append(
                GadgetResult(
                    library="unknown",
                    version=None,
                    likely_vulnerable=True,
                    description="No fingerprinted library, but polluted marker reflected in DOM.",
                    poc_triggered=True,
                    poc_evidence=poc_evidence,
                )
            )

    return results
