#!/usr/bin/env python3
"""Conservative public-surface exposure audit with strict scope controls."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

VERSION = "1.0.1"
HARD_MAX_REQUESTS = 100
HARD_MAX_RATE = 2.0
HARD_MAX_TIMEOUT = 20.0
MAX_BODY_BYTES = 1_000_000
MAX_ERRORS = 3
FIXED_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger-ui/",
)
DOC_EXTENSIONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".zip", ".json")
PRIVATE_PATH_MARKERS = (
    "/account", "/admin", "/billing", "/checkout", "/customer", "/internal",
    "/login", "/logout", "/me", "/private", "/profile", "/signin", "/user",
)

SECRET_PATTERNS = (
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b")),
    ("JWT-like token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "assigned secret-like value",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|secret[_-]?key)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9_./+\-=]{16,})['\"]"
        ),
    ),
)
ENDPOINT_PATTERN = re.compile(
    r"(?:(?:https?://[A-Za-z0-9._:-]+)?/(?:api|graphql|rest|v[0-9]+)"
    r"(?:/[A-Za-z0-9._~!$&()*+,=:@%{}-]*)*)"
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")


class AuditError(Exception):
    pass


def safe_path(path: str) -> bool:
    """Reject ambiguous paths that servers or proxies might normalize differently."""
    return (
        path.startswith("/")
        and "%" not in path
        and "\\" not in path
        and not any(ord(char) < 32 or ord(char) == 127 for char in path)
        and not any(part in {".", ".."} for part in path.split("/"))
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class PublicPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.password_input = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): v for k, v in attrs if v is not None}
        if tag.lower() == "script" and values.get("src"):
            self.scripts.append(values["src"])
        if tag.lower() == "a" and values.get("href"):
            self.links.append(values["href"])
        if tag.lower() == "input" and values.get("type", "").lower() == "password":
            self.password_input = True


@dataclass(frozen=True)
class TargetRule:
    scheme: str
    host: str
    port: int
    allowed: tuple[str, ...]
    excluded: tuple[str, ...]

    def permits(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False
        path = parsed.path or "/"
        return (
            parsed.scheme == self.scheme
            and (parsed.hostname or "").lower() == self.host
            and port == self.port
            and safe_path(path)
            and any(path.startswith(prefix) for prefix in self.allowed)
            and not any(path.startswith(prefix) for prefix in self.excluded)
            and not parsed.username
            and not parsed.password
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized, non-invasive public website exposure audit."
    )
    parser.add_argument("url", help="Approved seed URL (http or https)")
    parser.add_argument("--scope", type=Path, help="Required approved scope JSON for non-loopback targets")
    parser.add_argument("--output-dir", type=Path, default=Path("audit-output"))
    parser.add_argument("--dry-run", action="store_true", help="Validate and print plan; send no traffic")
    parser.add_argument("--max-requests", type=int, default=30)
    parser.add_argument("--rate", type=float, default=1.0, help="Requests per second")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--public-path", action="append", default=[], help="Additional exact public path")
    return parser.parse_args()


def normalize_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AuditError("URL must use http or https and include a hostname")
    if parsed.username or parsed.password:
        raise AuditError("Credentials in URLs are prohibited")
    if parsed.query or parsed.fragment:
        raise AuditError("Seed URL must not contain a query string or fragment")
    host = (parsed.hostname or "").lower()
    port = parsed.port
    netloc = host if port is None else f"{host}:{port}"
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuditError(f"scope field {key!r} must be a non-empty string")
    return value.strip()


def parse_date(value: str, key: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise AuditError(f"scope field {key!r} must be YYYY-MM-DD") from exc


def validate_prefixes(value: Any, key: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise AuditError(f"scope field {key!r} must be a {'possibly empty ' if allow_empty else ''}list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not safe_path(item) or "?" in item or "#" in item:
            raise AuditError(f"scope field {key!r} contains an invalid path prefix")
        result.append(item)
    return tuple(result)


def load_scope(path: Path) -> tuple[dict[str, Any], list[TargetRule]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read valid scope JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("authorization_confirmed") is not True:
        raise AuditError("scope must set authorization_confirmed to true")
    for key in ("organization", "authorized_by", "security_contact", "valid_from", "expires"):
        require_string(data, key)
    today = dt.date.today()
    valid_from = parse_date(data["valid_from"], "valid_from")
    expires = parse_date(data["expires"], "expires")
    if valid_from > expires or not (valid_from <= today <= expires):
        raise AuditError(f"scope is not valid today ({today.isoformat()})")
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise AuditError("scope targets must be a non-empty list")
    rules: list[TargetRule] = []
    for raw in raw_targets:
        if not isinstance(raw, dict):
            raise AuditError("each scope target must be an object")
        scheme = raw.get("scheme")
        host = str(raw.get("host", "")).lower()
        port = raw.get("port")
        if scheme not in {"http", "https"} or not host or "*" in host or "/" in host:
            raise AuditError("scope target requires an exact host and http/https scheme")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise AuditError("scope target port must be an integer from 1 to 65535")
        rules.append(
            TargetRule(
                scheme=scheme,
                host=host,
                port=port,
                allowed=validate_prefixes(raw.get("allowed_path_prefixes"), "allowed_path_prefixes"),
                excluded=validate_prefixes(
                    raw.get("excluded_path_prefixes", []), "excluded_path_prefixes", allow_empty=True
                ),
            )
        )
    requests = data.get("max_requests")
    if isinstance(requests, bool) or not isinstance(requests, int) or not 1 <= requests <= HARD_MAX_REQUESTS:
        raise AuditError(f"scope max_requests must be an integer from 1 to {HARD_MAX_REQUESTS}")
    rate = data.get("max_requests_per_second")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or not 0 < rate <= HARD_MAX_RATE:
        raise AuditError(f"scope max_requests_per_second must be finite, greater than 0 and no more than {HARD_MAX_RATE}")
    return data, rules


def local_rule(seed: str) -> TargetRule:
    parsed = urllib.parse.urlsplit(seed)
    return TargetRule(
        parsed.scheme,
        (parsed.hostname or "").lower(),
        parsed.port or (443 if parsed.scheme == "https" else 80),
        ("/",),
        PRIVATE_PATH_MARKERS,
    )


def find_rule(url: str, rules: list[TargetRule]) -> TargetRule | None:
    return next((rule for rule in rules if rule.permits(url)), None)


def path_url(seed: str, path: str) -> str:
    parsed = urllib.parse.urlsplit(seed)
    if not path.startswith("/") or "?" in path or "#" in path:
        raise AuditError(f"invalid public path: {path!r}")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def build_plan(seed: str, extra_paths: list[str], rules: list[TargetRule]) -> list[str]:
    candidates = [seed]
    for path in FIXED_PATHS:
        url = path_url(seed, path)
        if find_rule(url, rules) and url not in candidates:
            candidates.append(url)
    for path in extra_paths:
        url = path_url(seed, path)
        if not find_rule(url, rules):
            raise AuditError(f"requested --public-path is outside approved scope: {path}")
        if url not in candidates:
            candidates.append(url)
    for url in candidates:
        if not find_rule(url, rules):
            raise AuditError(f"planned URL is outside approved scope: {url}")
    return candidates


def redact_secret(value: str) -> tuple[str, str]:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    preview = f"{value[:3]}…{value[-2:]} ({len(value)} chars)" if len(value) >= 8 else "[redacted]"
    return preview, digest


def secret_candidates(text: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            preview, fingerprint = redact_secret(value)
            key = (kind, fingerprint)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "category": "client-side secret",
                    "severity": "high",
                    "confidence": "medium",
                    "title": f"Suspected {kind} in public client content",
                    "source": source,
                    "evidence": {"type": kind, "redacted": preview, "sha256_12": fingerprint},
                    "caveat": "Pattern match only; value was not tested or reproduced in output.",
                }
            )
    return findings


def endpoint_references(text: str) -> list[str]:
    return sorted(set(match.group(0) for match in ENDPOINT_PATTERN.finditer(text)))[:100]


def document_references(base: str, raw_links: list[str]) -> list[str]:
    result: set[str] = set()
    for raw in raw_links:
        absolute = urllib.parse.urljoin(base, raw)
        parsed = urllib.parse.urlsplit(absolute)
        if parsed.scheme in {"http", "https"} and parsed.path.lower().endswith(DOC_EXTENSIONS):
            result.add(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
    return sorted(result)[:100]


def looks_like_api_docs(path: str, content_type: str, text: str) -> bool:
    lower_path = path.lower()
    if any(token in lower_path for token in ("openapi", "swagger", "api-docs", "swagger-ui")):
        return True
    head = text[:5000].lower()
    return ("openapi" in head or "swagger" in head) and ("application/json" in content_type or "<html" in head)


def sensitive_data_indicator(text: str) -> str | None:
    """Return a broad stop signal without returning the matched data."""
    patterns = (
        ("social-security-number field", re.compile(r'(?i)["\'](?:ssn|social_security_number)["\']\s*:')),
        ("payment-card field", re.compile(r'(?i)["\'](?:credit_card|card_number|pan)["\']\s*:')),
        ("date-of-birth field", re.compile(r'(?i)["\'](?:date_of_birth|dob)["\']\s*:')),
    )
    for label, pattern in patterns:
        if pattern.search(text):
            return label
    if len(re.findall(r'(?i)["\']email["\']\s*:', text)) >= 3:
        return "multiple email records"
    return None


def selected_headers(headers: dict[str, str]) -> dict[str, str]:
    names = (
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "cache-control",
        "content-security-policy",
        "permissions-policy",
        "referrer-policy",
        "strict-transport-security",
        "x-content-type-options",
    )
    return {name: headers[name] for name in names if name in headers}


def markdown_report(report: dict[str, Any]) -> str:
    meta = report["run"]
    lines = [
        "# Authorized web exposure audit",
        "",
        f"- Target: `{meta['target']}`",
        f"- Started: `{meta['started_at']}`",
        f"- Requests: {meta['requests_made']} (limit {meta['max_requests']})",
        f"- Rate: {meta['requests_per_second']} request(s)/second",
        f"- Stop reason: {meta['stop_reason'] or 'Completed planned requests'}",
        "- Explicitly not tested: authentication, bypasses, private records, credential validity, or state-changing actions",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings were generated. This does not prove absence of exposure.")
    for index, finding in enumerate(report["findings"], 1):
        lines.extend(
            [
                f"### F-{index:03d}: {finding['title']}",
                "",
                f"- Category: {finding['category']}",
                f"- Severity: {finding['severity']}",
                f"- Confidence: {finding['confidence']}",
                f"- Source: `{finding['source']}`",
                f"- Evidence: `{html.escape(json.dumps(finding.get('evidence', {}), sort_keys=True))}`",
                f"- Caveat: {finding.get('caveat', 'Review with the asset owner.')}",
                "",
            ]
        )
    lines.extend(["## Observations", ""])
    for observation in report["observations"]:
        lines.append(f"- `{observation['url']}` — {observation['summary']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    try:
        seed = normalize_url(args.url)
        parsed_seed = urllib.parse.urlsplit(seed)
        if not 1 <= args.max_requests <= HARD_MAX_REQUESTS:
            raise AuditError(f"--max-requests must be 1..{HARD_MAX_REQUESTS}")
        if not 0 < args.rate <= HARD_MAX_RATE:
            raise AuditError(f"--rate must be >0 and <= {HARD_MAX_RATE}")
        if not 0 < args.timeout <= HARD_MAX_TIMEOUT:
            raise AuditError(f"--timeout must be >0 and <= {HARD_MAX_TIMEOUT}")

        local = is_loopback(parsed_seed.hostname or "")
        scope_data: dict[str, Any] | None = None
        if local:
            rules = [local_rule(seed)]
        else:
            if args.scope is None:
                raise AuditError("non-loopback targets require --scope with explicit organizational authorization")
            scope_data, rules = load_scope(args.scope)
            if not find_rule(seed, rules):
                raise AuditError("seed URL is outside the exact approved scope")

        effective_requests = min(
            args.max_requests,
            int(scope_data["max_requests"]) if scope_data else HARD_MAX_REQUESTS,
            HARD_MAX_REQUESTS,
        )
        effective_rate = min(
            args.rate,
            float(scope_data["max_requests_per_second"]) if scope_data else HARD_MAX_RATE,
            HARD_MAX_RATE,
        )
        plan = build_plan(seed, args.public_path, rules)
        if args.dry_run:
            print("DRY RUN — no network traffic sent")
            print(f"Target: {seed}")
            print(f"Authorization: {'localhost fixture' if local else scope_data['authorized_by']}")
            print(f"Limits: {effective_requests} requests, {effective_rate:g} request(s)/second, {args.timeout:g}s timeout")
            print("Initial request plan (same-origin scripts may be added only when referenced):")
            for url in plan:
                print(f"  GET {url}")
            print("Stop on out-of-scope redirect, login form, sensitive-data indicators, 429/503, or 3 request errors.")
            return 0

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        queue = list(plan)
        queued = set(queue)
        observations: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        requests_made = 0
        errors = 0
        stop_reason: str | None = None
        cors_reported = False
        started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        last_request = 0.0

        while queue and requests_made < effective_requests and not stop_reason:
            url = queue.pop(0)
            if not find_rule(url, rules):
                stop_reason = f"planned or discovered URL left approved scope: {url}"
                break
            wait_for = (1.0 / effective_rate) - (time.monotonic() - last_request)
            if wait_for > 0:
                time.sleep(wait_for)
            request = urllib.request.Request(
                url,
                headers={"User-Agent": f"authorized-web-exposure-audit/{VERSION}"},
                method="GET",
            )
            requests_made += 1
            last_request = time.monotonic()
            try:
                response = opener.open(request, timeout=args.timeout)
                status = response.status
            except urllib.error.HTTPError as exc:
                response = exc
                status = exc.code
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                errors += 1
                observations.append({"url": url, "summary": f"request error: {type(exc).__name__}"})
                if errors >= MAX_ERRORS:
                    stop_reason = f"request error ceiling reached ({MAX_ERRORS})"
                continue

            headers = {key.lower(): value for key, value in response.headers.items()}
            content_type = headers.get("content-type", "").lower()
            content_length = headers.get("content-length")
            if status in {429, 503}:
                stop_reason = f"server returned {status}; stopped without retry"
                observations.append({"url": url, "summary": f"HTTP {status}"})
                continue
            if 300 <= status < 400:
                location = headers.get("location", "")
                destination = urllib.parse.urljoin(url, location) if location else ""
                scope_note = "in scope" if destination and find_rule(destination, rules) else "out of scope or absent"
                observations.append({"url": url, "summary": f"HTTP {status} redirect ({scope_note}); not followed"})
                if destination and not find_rule(destination, rules):
                    stop_reason = "redirect would leave approved scope"
                continue
            if status >= 400:
                observations.append({"url": url, "summary": f"HTTP {status}"})
                continue
            if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
                observations.append({"url": url, "summary": "HTTP 200; body skipped because declared size exceeds 1 MB"})
                continue
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                stop_reason = "response body exceeded 1 MB ceiling"
                observations.append({"url": url, "summary": "body exceeded 1 MB; content discarded"})
                continue
            text = body.decode("utf-8", errors="replace")
            parsed_url = urllib.parse.urlsplit(url)
            summary = f"HTTP {status}; {content_type or 'unknown content type'}; {len(body)} bytes"
            observations.append({"url": url, "summary": summary, "headers": selected_headers(headers)})

            api_docs = looks_like_api_docs(parsed_url.path, content_type, text)
            sensitive_indicator = None if api_docs else sensitive_data_indicator(text)
            if sensitive_indicator:
                stop_reason = f"possible sensitive data encountered ({sensitive_indicator}); body discarded"
                continue

            if api_docs:
                findings.append(
                    {
                        "category": "API documentation",
                        "severity": "informational",
                        "confidence": "high",
                        "title": "API documentation is publicly reachable",
                        "source": url,
                        "evidence": {"http_status": status, "content_type": content_type},
                        "caveat": "Public availability may be intentional; confirm expected state with the owner.",
                    }
                )

            findings.extend(secret_candidates(text, url))
            endpoints = endpoint_references(text)
            if endpoints:
                findings.append(
                    {
                        "category": "endpoint reference",
                        "severity": "informational",
                        "confidence": "high",
                        "title": "Public client content references API-style paths",
                        "source": url,
                        "evidence": {"references": endpoints},
                        "caveat": "References were not requested; endpoint visibility alone is not a vulnerability.",
                    }
                )

            acao = headers.get("access-control-allow-origin")
            acac = headers.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true" and not cors_reported:
                cors_reported = True
                findings.append(
                    {
                        "category": "headers",
                        "severity": "medium",
                        "confidence": "high",
                        "title": "Invalid and risky wildcard CORS credentials combination",
                        "source": url,
                        "evidence": {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"},
                        "caveat": "Browsers normally reject this exact combination, but it indicates a configuration error.",
                    }
                )

            if "text/html" in content_type or "<html" in text[:1000].lower():
                parser = PublicPageParser()
                parser.feed(text)
                if parser.password_input:
                    stop_reason = "login/password form encountered"
                    continue
                docs = document_references(url, parser.links)
                if docs:
                    findings.append(
                        {
                            "category": "public document",
                            "severity": "informational",
                            "confidence": "high",
                            "title": "Public page references downloadable documents",
                            "source": url,
                            "evidence": {"references": docs},
                            "caveat": "Documents were not downloaded; confirm intended publication and indexing with the owner.",
                        }
                    )
                for raw_script in parser.scripts:
                    script_url = urllib.parse.urljoin(url, raw_script)
                    script_parsed = urllib.parse.urlsplit(script_url)
                    script_url = urllib.parse.urlunsplit(
                        (script_parsed.scheme, script_parsed.netloc, script_parsed.path, "", "")
                    )
                    if (
                        script_url not in queued
                        and find_rule(script_url, rules)
                        and not any(marker in script_parsed.path.lower() for marker in PRIVATE_PATH_MARKERS)
                        and not script_parsed.path.lower().endswith(".map")
                    ):
                        queue.append(script_url)
                        queued.add(script_url)

            if parsed_url.path in {"/robots.txt", "/sitemap.xml"}:
                refs = sorted(set(URL_PATTERN.findall(text)))[:100]
                if refs:
                    observations.append(
                        {"url": url, "summary": f"metadata listed {len(refs)} URL(s); references not fetched"}
                    )
                    docs = document_references(url, refs)
                    if docs:
                        findings.append(
                            {
                                "category": "public document",
                                "severity": "informational",
                                "confidence": "high",
                                "title": "Indexing metadata references downloadable documents",
                                "source": url,
                                "evidence": {"references": docs},
                                "caveat": "Documents were not downloaded; confirm intended indexing with the owner.",
                            }
                        )

        report = {
            "schema_version": "1.0",
            "run": {
                "target": seed,
                "started_at": started,
                "completed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
                "authorization": "localhost fixture" if local else {
                    "organization": scope_data["organization"],
                    "authorized_by": scope_data["authorized_by"],
                    "security_contact": scope_data["security_contact"],
                },
                "requests_made": requests_made,
                "max_requests": effective_requests,
                "requests_per_second": effective_rate,
                "errors": errors,
                "stop_reason": stop_reason,
                "body_retention": "none",
            },
            "findings": findings,
            "observations": observations,
        }
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "findings.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (args.output_dir / "findings.md").write_text(markdown_report(report), encoding="utf-8")
        print(f"Wrote {args.output_dir / 'findings.json'} and {args.output_dir / 'findings.md'}")
        print(f"Requests: {requests_made}; findings: {len(findings)}; stop: {stop_reason or 'planned requests complete'}")
        return 3 if stop_reason else 0
    except AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

