"""
Generates JSON and HTML reports from client-side Findings and server-side
ServerFindings.
"""

import json
from datetime import datetime, timezone
from dataclasses import asdict, is_dataclass


def _to_serializable(obj):
    if is_dataclass(obj):
        return {k: _to_serializable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_serializable(v) for v in obj]
    return obj


def write_json_report(path: str, client_findings: list, server_findings: list, meta: dict):
    report = {
        "meta": {
            **meta,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "client_side": [_to_serializable(f) for f in client_findings],
        "server_side": [_to_serializable(f) for f in server_findings],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return report


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ppfinder report</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2rem; background: #0b0f14; color: #d8e1e8; }}
  h1, h2 {{ color: #f5f5f5; }}
  .finding {{ border: 1px solid #263340; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; background: #121821; }}
  .finding.polluted {{ border-color: #d84f4f; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
  .badge.hit {{ background: #d84f4f; color: white; }}
  .badge.miss {{ background: #2f3b47; color: #9fb0bd; }}
  code, pre {{ background: #060a0f; color: #8fd19e; padding: 0.15rem 0.4rem; border-radius: 4px; overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 0.5rem; }}
  td, th {{ border: 1px solid #263340; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }}
  .meta {{ color: #7d8b97; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>ppfinder report</h1>
<p class="meta">Generated: {generated_at} &middot; Targets: {targets}</p>

<h2>Client-side findings ({client_count} notable / {client_total} tested)</h2>
{client_html}

<h2>Server-side findings ({server_count} notable)</h2>
{server_html}

</body>
</html>
"""


def _client_finding_html(f: dict) -> str:
    cls = "finding polluted" if f.get("polluted") else "finding"
    badge = '<span class="badge hit">POLLUTED</span>' if f.get("polluted") else '<span class="badge miss">clean</span>'
    return f"""
<div class="{cls}">
  <p>{badge} <strong>{f.get('inject_point')}</strong> / <code>{f.get('payload_name')}</code></p>
  <p>URL: <code>{f.get('url')}</code></p>
  <p>Marker: <code>{f.get('marker')}</code></p>
  <p>Evidence: {f.get('evidence') or '-'}</p>
</div>
"""


def _server_finding_html(f: dict) -> str:
    diff = f.get("diff", {})
    details = "<br>".join(diff.get("details", []))
    return f"""
<div class="finding polluted">
  <p><span class="badge hit">NOTABLE</span> <strong>{f.get('content_type')}</strong> / <code>{f.get('payload_name')}</code></p>
  <p>Request: <code>{f.get('request_repr')}</code></p>
  <p>Status: {diff.get('status_from')} -&gt; {diff.get('status_to')}</p>
  <p>Details:<br>{details}</p>
</div>
"""


def write_html_report(path: str, client_findings: list, server_findings: list, meta: dict):
    client_dicts = [_to_serializable(f) for f in client_findings]
    server_dicts = [_to_serializable(f) for f in server_findings]

    client_notable = [f for f in client_dicts if f.get("polluted")]
    client_html = "".join(_client_finding_html(f) for f in client_notable) or "<p>No pollution confirmed.</p>"
    server_html = "".join(_server_finding_html(f) for f in server_dicts) or "<p>No notable diffs.</p>"

    html = _HTML_TEMPLATE.format(
        generated_at=datetime.now(timezone.utc).isoformat(),
        targets=", ".join(meta.get("targets", [])),
        client_count=len(client_notable),
        client_total=len(client_dicts),
        client_html=client_html,
        server_count=len(server_dicts),
        server_html=server_html,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
