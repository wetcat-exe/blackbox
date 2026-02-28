#!/usr/bin/env python3
"""Automated bug bounty assistant powered by ChatGPT.

This utility performs lightweight web reconnaissance and vulnerability heuristics,
then asks ChatGPT to prioritize findings and generate a triage-ready report.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_WORKERS = 8
DEFAULT_USER_AGENT = "Blackbox/2.1"
COMMON_SENSITIVE_PATHS = [
    "/.git/",
    "/.env",
    "/backup.zip",
    "/db.sql",
    "/phpinfo.php",
    "/server-status",
]
INTERESTING_ROBOTS_PATTERNS = ["admin", "backup", "internal", "private", "staging", "debug"]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: str
    target: str
    recommendation: str


@dataclass
class ScanResult:
    target: str
    timestamp_utc: str
    findings: List[Finding]
    metadata: Dict[str, str]


class LightweightScanner:
    """Runs pragmatic bug bounty checks without intrusive exploitation."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT_SECONDS, user_agent: str = DEFAULT_USER_AGENT) -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def scan(self, target: str) -> ScanResult:
        normalized = normalize_target(target)
        findings: List[Finding] = []

        response_data, headers = self._fetch(normalized)
        findings.extend(self._check_missing_security_headers(normalized, headers))
        findings.extend(self._check_cors(normalized, headers))
        findings.extend(self._check_cookie_flags(normalized, headers))
        findings.extend(self._check_server_banner(normalized, headers))
        findings.extend(self._check_robots(normalized))
        findings.extend(self._check_sensitive_paths(normalized))
        findings.extend(self._check_tls(normalized))

        return ScanResult(
            target=normalized,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            findings=findings,
            metadata={
                "status": str(response_data.get("status", "unknown")),
                "server": headers.get("Server", "unknown"),
                "findings_count": str(len(findings)),
            },
        )

    def _fetch(self, url: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        req = Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                return {"status": str(resp.status)}, {k: v for k, v in resp.headers.items()}
        except HTTPError as exc:
            return {"status": str(exc.code)}, {k: v for k, v in exc.headers.items()}
        except URLError:
            return {"status": "unreachable"}, {}

    def _check_missing_security_headers(self, target: str, headers: Dict[str, str]) -> List[Finding]:
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if not missing:
            return []
        return [
            Finding(
                title="Missing security headers",
                severity="medium",
                description="The target response lacks recommended browser security headers.",
                evidence=f"Missing: {', '.join(missing)}",
                target=target,
                recommendation="Set hardened defaults for CSP, HSTS, clickjacking, MIME sniffing, and referrer policy.",
            )
        ]

    def _check_cors(self, target: str, headers: Dict[str, str]) -> List[Finding]:
        origin = headers.get("Access-Control-Allow-Origin", "")
        creds = headers.get("Access-Control-Allow-Credentials", "")
        if origin == "*" and creds.lower() == "true":
            return [
                Finding(
                    title="Potentially dangerous CORS policy",
                    severity="high",
                    description="Wildcard CORS origin appears alongside credential support.",
                    evidence=f"Access-Control-Allow-Origin={origin}, Access-Control-Allow-Credentials={creds}",
                    target=target,
                    recommendation="Restrict origins and avoid credentialed wildcard policies.",
                )
            ]
        if origin == "*":
            return [
                Finding(
                    title="Permissive CORS wildcard",
                    severity="medium",
                    description="Target allows any origin to access resources.",
                    evidence="Access-Control-Allow-Origin=*",
                    target=target,
                    recommendation="Use an explicit allow-list of trusted front-end origins.",
                )
            ]
        return []

    def _check_cookie_flags(self, target: str, headers: Dict[str, str]) -> List[Finding]:
        cookie_header = headers.get("Set-Cookie", "")
        if not cookie_header:
            return []
        findings: List[Finding] = []
        lowered = cookie_header.lower()
        if "httponly" not in lowered:
            findings.append(
                Finding(
                    title="Session cookie may be missing HttpOnly",
                    severity="medium",
                    description="Cookies without HttpOnly can be read by client-side scripts.",
                    evidence=f"Set-Cookie={cookie_header[:200]}",
                    target=target,
                    recommendation="Set HttpOnly on session and auth cookies.",
                )
            )
        if "secure" not in lowered:
            findings.append(
                Finding(
                    title="Session cookie may be missing Secure flag",
                    severity="medium",
                    description="Cookies without Secure may traverse plaintext channels in mixed deployments.",
                    evidence=f"Set-Cookie={cookie_header[:200]}",
                    target=target,
                    recommendation="Set Secure on sensitive cookies and enforce HTTPS.",
                )
            )
        if "samesite" not in lowered:
            findings.append(
                Finding(
                    title="Session cookie may be missing SameSite",
                    severity="low",
                    description="Absent SameSite can increase cross-site request exposure.",
                    evidence=f"Set-Cookie={cookie_header[:200]}",
                    target=target,
                    recommendation="Set SameSite=Lax/Strict where appropriate.",
                )
            )
        return findings

    def _check_server_banner(self, target: str, headers: Dict[str, str]) -> List[Finding]:
        server = headers.get("Server", "")
        if not server:
            return []
        if re.search(r"\d", server):
            return [
                Finding(
                    title="Potential version disclosure in server banner",
                    severity="low",
                    description="Server header appears to include version information.",
                    evidence=f"Server={server}",
                    target=target,
                    recommendation="Minimize version disclosure in response headers.",
                )
            ]
        return []

    def _check_robots(self, target: str) -> List[Finding]:
        robots_url = f"{target.rstrip('/')}/robots.txt"
        _, headers = self._fetch(robots_url)
        req = Request(robots_url, headers={"User-Agent": self.user_agent})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                if resp.status >= 400:
                    return []
                body = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return []

        suspicious = []
        for line in body.splitlines():
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip().lower()
                if any(pattern in path for pattern in INTERESTING_ROBOTS_PATTERNS):
                    suspicious.append(path)

        findings = []
        if suspicious:
            findings.append(
                Finding(
                    title="Interesting paths exposed in robots.txt",
                    severity="low",
                    description="robots.txt may disclose sensitive or high-value endpoints.",
                    evidence="; ".join(suspicious),
                    target=target,
                    recommendation="Avoid listing sensitive application routes in robots.txt.",
                )
            )
        if headers.get("X-Robots-Tag", "").strip() == "":
            findings.append(
                Finding(
                    title="No X-Robots-Tag header",
                    severity="info",
                    description="X-Robots-Tag is not present on robots.txt response.",
                    evidence=f"{robots_url} missing X-Robots-Tag",
                    target=target,
                    recommendation="Consider explicit crawler directives where policy requires.",
                )
            )
        return findings

    def _check_sensitive_paths(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        for path in COMMON_SENSITIVE_PATHS:
            url = f"{target.rstrip('/')}{path}"
            req = Request(url, headers={"User-Agent": self.user_agent})
            try:
                with urlopen(req, timeout=self.timeout) as resp:
                    if resp.status < 400:
                        findings.append(
                            Finding(
                                title="Potential sensitive file or endpoint exposed",
                                severity="high" if any(x in path for x in [".env", "backup", ".sql", ".git"]) else "medium",
                                description="A potentially sensitive path appears reachable.",
                                evidence=f"{url} -> HTTP {resp.status}",
                                target=target,
                                recommendation="Restrict access and ensure sensitive artifacts are never web-accessible.",
                            )
                        )
            except HTTPError as exc:
                if exc.code in (301, 302):
                    findings.append(
                        Finding(
                            title="Potential sensitive path redirects",
                            severity="low",
                            description="Sensitive path redirects and may still be exposed behind rewrites.",
                            evidence=f"{url} -> HTTP {exc.code}",
                            target=target,
                            recommendation="Manually verify route protections for redirected sensitive endpoints.",
                        )
                    )
            except Exception:
                continue
        return findings

    def _check_tls(self, target: str) -> List[Finding]:
        parsed = urlparse(target)
        if parsed.scheme != "https":
            return [
                Finding(
                    title="Target is not using HTTPS",
                    severity="medium",
                    description="Traffic may be vulnerable to interception without TLS.",
                    evidence=f"scheme={parsed.scheme}",
                    target=target,
                    recommendation="Serve the application exclusively over HTTPS and redirect HTTP to HTTPS.",
                )
            ]

        host = parsed.hostname
        if not host:
            return []

        findings: List[Finding] = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
        except Exception:
            return []

        not_after = cert.get("notAfter") if isinstance(cert, dict) else None
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                remaining_days = (expiry - datetime.now(timezone.utc)).days
                if remaining_days < 15:
                    findings.append(
                        Finding(
                            title="TLS certificate expires soon",
                            severity="medium",
                            description="Certificate lifecycle risk can cause outages and trust warnings.",
                            evidence=f"Certificate expires in {remaining_days} day(s)",
                            target=target,
                            recommendation="Rotate/renew TLS certificates before expiry.",
                        )
                    )
            except ValueError:
                pass
        return findings


class ChatGPTTriage:
    """Uses OpenAI Chat Completions API to prioritize findings and build a report."""

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        self.model = model
        self.api_key = os.getenv("OPENAI_API_KEY", "")

    def summarize(self, scan_results: Sequence[ScanResult]) -> str:
        if not self.api_key:
            return self._local_summary(scan_results)

        try:
            import requests
        except ImportError:
            return self._local_summary(scan_results)

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a bug bounty triage assistant. Output sections: "
                        "1) executive summary, 2) prioritized findings, "
                        "3) remediation actions, 4) validation workflow, 5) submission notes."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps([scan_result_to_dict(s) for s in scan_results], indent=2),
                },
            ],
            "temperature": 0.2,
        }

        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=30,
            )
        except Exception:
            return self._local_summary(scan_results)

        if response.status_code >= 400:
            return self._local_summary(scan_results)

        data = response.json()
        choices = data.get("choices", [])
        if not choices:
            return self._local_summary(scan_results)
        return choices[0].get("message", {}).get("content", self._local_summary(scan_results))

    def _local_summary(self, scan_results: Sequence[ScanResult]) -> str:
        all_findings = [finding for result in scan_results for finding in result.findings]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(all_findings, key=lambda f: severity_order.get(f.severity, 9))

        severity_counts: Dict[str, int] = {}
        for finding in sorted_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        lines = [
            "# Blackbox Triage Report (Local Fallback)",
            "",
            "OPENAI_API_KEY not set or API unavailable, so this report uses built-in ranking.",
            "",
            "## Severity Summary",
            *(f"- {sev.upper()}: {count}" for sev, count in sorted(severity_counts.items(), key=lambda kv: severity_order.get(kv[0], 9))),
            "",
            "## Top Findings",
        ]

        if not sorted_findings:
            lines.append("No findings detected by lightweight checks.")
            return "\n".join(lines)

        for finding in sorted_findings[:20]:
            lines.extend(
                [
                    f"- **[{finding.severity.upper()}] {finding.title}** ({finding.target})",
                    f"  - Evidence: {finding.evidence}",
                    f"  - Recommendation: {finding.recommendation}",
                ]
            )

        lines.extend(
            [
                "",
                "## Validation Workflow",
                "1. Reproduce each finding manually in scope-approved targets.",
                "2. Confirm exploitability and real impact.",
                "3. Draft vendor-safe proof-of-concept and remediation guidance.",
                "4. Submit responsibly through the program policy channels.",
            ]
        )
        return "\n".join(lines)


def normalize_target(target: str) -> str:
    value = target.strip()
    if not re.match(r"^https?://", value):
        value = f"https://{value}"
    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError(f"Invalid target: {target}")
    return f"{parsed.scheme}://{parsed.netloc}"


def scan_result_to_dict(result: ScanResult) -> Dict[str, object]:
    return {
        "target": result.target,
        "timestamp_utc": result.timestamp_utc,
        "metadata": result.metadata,
        "findings": [asdict(finding) for finding in result.findings],
    }


def write_outputs(results: Sequence[ScanResult], summary: str, out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "scan_results.json"
    md_path = out_dir / "triage_report.md"
    json_path.write_text(json.dumps([scan_result_to_dict(r) for r in results], indent=2), encoding="utf-8")
    md_path.write_text(summary, encoding="utf-8")
    return json_path, md_path


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Blackbox automated security triage tool powered by ChatGPT")
    parser.add_argument("--target", action="append", default=[], help="Target host or URL (can be repeated)")
    parser.add_argument("--targets-file", help="File with one target per line")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model for triage")
    parser.add_argument("--out-dir", default="reports", help="Directory for generated artifacts")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="HTTP/TLS timeout in seconds")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Concurrent target scans")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent for scan requests")
    return parser.parse_args(argv)


def load_targets(args: argparse.Namespace) -> List[str]:
    targets = list(args.target)
    if args.targets_file:
        file_targets = [
            line.strip()
            for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        targets.extend(file_targets)

    unique_targets = sorted(set(targets))
    if not unique_targets:
        raise ValueError("No targets supplied. Use --target or --targets-file.")
    return unique_targets


def run_scans(targets: Sequence[str], scanner: LightweightScanner, max_workers: int) -> List[ScanResult]:
    results: List[ScanResult] = []
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        futures = {executor.submit(scanner.scan, t): t for t in targets}
        for future in as_completed(futures):
            target = futures[future]
            try:
                results.append(future.result())
                print(f"[+] Completed {target}")
            except Exception as exc:
                print(f"[!] Failed scanning {target}: {exc}")
    return sorted(results, key=lambda r: r.target)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        targets = load_targets(args)
    except Exception as exc:
        print(f"[!] {exc}")
        return 1

    scanner = LightweightScanner(timeout=args.timeout, user_agent=args.user_agent)
    print(f"[*] Scanning {len(targets)} target(s) with max_workers={max(1, args.max_workers)}")
    results = run_scans(targets, scanner=scanner, max_workers=args.max_workers)

    triage = ChatGPTTriage(model=args.model)
    summary = triage.summarize(results)

    json_path, md_path = write_outputs(results, summary, Path(args.out_dir))
    print(f"[+] Saved JSON results to {json_path}")
    print(f"[+] Saved triage report to {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
