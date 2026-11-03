#!/usr/bin/env python3
"""Inspect common HTTP security headers on a website response."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Sequence
from urllib.parse import urlsplit, urlunsplit


USER_AGENT = "HeaderScout/1.0 (+https://github.com/londbasak-dev/header-scout)"


@dataclass(frozen=True)
class Finding:
    name: str
    status: str
    value: str | None
    note: str


CHECKS = (
    ("Strict-Transport-Security", "Use HSTS only after HTTPS is configured for the full site."),
    ("Content-Security-Policy", "A carefully tested CSP can reduce the impact of injected content."),
    ("X-Content-Type-Options", "Set this to 'nosniff' to stop MIME-type sniffing."),
    ("X-Frame-Options", "Use DENY or SAMEORIGIN, or set CSP frame-ancestors."),
    ("Referrer-Policy", "Consider 'strict-origin-when-cross-origin' or a stricter policy."),
    ("Permissions-Policy", "Disable browser features the site does not need."),
    ("Cross-Origin-Opener-Policy", "Review whether 'same-origin' fits the site's integrations."),
    ("Cross-Origin-Resource-Policy", "Choose a policy that matches how other sites load resources."),
    ("Cross-Origin-Embedder-Policy", "Enable only when the site is ready for cross-origin isolation."),
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep the result scoped to the explicitly supplied host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def normalize_url(raw_url: str) -> str:
    """Validate and normalize a URL without exposing credentials in output."""
    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("Please provide a website URL.")
    if "://" not in candidate:
        candidate = "https://" + candidate

    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parts.hostname:
        raise ValueError("The URL must include a hostname, such as https://example.com.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Do not put usernames or passwords in the URL.")
    if parts.port is not None and not (1 <= parts.port <= 65535):
        raise ValueError("The URL port must be between 1 and 65535.")

    host = parts.hostname.encode("idna").decode("ascii")
    if ":" in host:
        host = f"[{host}]"
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def inspect_headers(headers, *, is_https: bool) -> list[Finding]:  # type: ignore[no-untyped-def]
    values = {key.lower(): value.strip() for key, value in headers.items()}
    findings: list[Finding] = []
    for name, note in CHECKS:
        value = values.get(name.lower())
        if name == "Strict-Transport-Security" and not is_https:
            findings.append(Finding(name, "review", value, "HSTS is meaningful only on HTTPS responses."))
        elif value:
            findings.append(Finding(name, "present", value, note))
        else:
            findings.append(Finding(name, "missing", None, note))
    return findings


def fetch(url: str, timeout: float):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
        method="GET",
    )
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            location = error.headers.get("Location", "")
            raise RuntimeError(f"The site redirected to {location or 'another URL'}. Check the destination separately.") from None
        response = error
    with response:
        # Read only a small amount so the tool can inspect response headers without downloading a full page.
        response.read(1024)
        return response.status, response.headers


def report(url: str, timeout: float) -> dict[str, object]:
    normalized = normalize_url(url)
    status_code, headers = fetch(normalized, timeout)
    findings = inspect_headers(headers, is_https=normalized.startswith("https://"))
    missing = sum(item.status == "missing" for item in findings)
    return {
        "url": normalized,
        "http_status": status_code,
        "summary": {"checked": len(findings), "present": len(findings) - missing, "missing": missing},
        "findings": [asdict(item) for item in findings],
        "note": "A missing header is a review prompt, not proof of a vulnerability. Check the site's needs before changing policy.",
    }


def render_text(result: dict[str, object]) -> str:
    summary = result["summary"]
    assert isinstance(summary, dict)
    lines = [
        "Header Scout",
        f"Target: {result['url']}",
        f"HTTP status: {result['http_status']}",
        f"Summary: {summary['present']} present/review, {summary['missing']} missing",
        "",
    ]
    findings = result["findings"]
    assert isinstance(findings, list)
    for item in findings:
        state = str(item["status"]).upper()
        lines.append(f"[{state}] {item['name']}")
        if item["value"]:
            lines.append(f"  Value: {item['value']}")
        lines.append(f"  Why it matters: {item['note']}")
    lines.extend(("", str(result["note"])))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check common HTTP security headers on a website you own or are authorized to assess.",
        epilog="Example: python security_headers.py https://example.com",
    )
    parser.add_argument("url", help="Website URL (https:// is assumed when omitted)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable JSON report")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (0.5 <= args.timeout <= 60):
        parser.error("--timeout must be between 0.5 and 60 seconds")
    try:
        result = report(args.url, args.timeout)
    except (ValueError, RuntimeError, urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"Header Scout: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

