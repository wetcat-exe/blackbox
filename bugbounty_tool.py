#!/usr/bin/env python3
"""Automated bug bounty assistant powered by ChatGPT.

This utility performs lightweight web reconnaissance and vulnerability heuristics,
then asks ChatGPT to prioritize findings and generate a triage-ready report.
"""

from __future__ import annotations

import argparse
import hashlib
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
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_WORKERS = 8
DEFAULT_USER_AGENT = "Blackbox/2.1"
DEFAULT_PLUGIN_VERSION = "1.0.0"
COMMON_SENSITIVE_PATHS = ["/.git/", "/.env", "/backup.zip", "/db.sql", "/phpinfo.php", "/server-status"]
INTERESTING_ROBOTS_PATTERNS = ["admin", "backup", "internal", "private", "staging", "debug"]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


@dataclass
class CheckPlugin:
    plugin_id: str
    version: str
    description: str
    category: str


@dataclass
class SuppressionRule:
    title_contains: Optional[str] = None
    target_regex: Optional[str] = None
    plugin_id: Optional[str] = None
    min_confidence: float = 0.0


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: str
    target: str
    recommendation: str
    plugin_id: str
    plugin_version: str
    confidence: float
    evidence_quality: str
    fingerprint: str = ""


@dataclass
class ScanResult:
    target: str
    timestamp_utc: str
    findings: List[Finding]
    metadata: Dict[str, str]
    suppressed_findings: int = 0


@dataclass
class DiffResult:
    baseline_total: int
    current_total: int
    new_findings: List[Finding]


@dataclass
class ResponseSnapshot:
    url: str
    status: str
    headers: Dict[str, str]
    body: str


class LightweightScanner:
    """Runs pragmatic bug bounty checks without intrusive exploitation."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        suppression_rules: Optional[List[SuppressionRule]] = None,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.suppression_rules = suppression_rules or []
        self.plugins = self._build_plugins()

    def _build_plugins(self) -> List[Tuple[CheckPlugin, Callable[[str, ResponseSnapshot], List[Finding]]]]:
        return [
            (CheckPlugin("core.security_headers", DEFAULT_PLUGIN_VERSION, "Missing security headers", "web"), self._check_missing_security_headers),
            (CheckPlugin("web.cors_reflection", DEFAULT_PLUGIN_VERSION, "CORS trust reflection and wildcard", "web"), self._check_cors),
            (CheckPlugin("core.cookie_flags", DEFAULT_PLUGIN_VERSION, "Cookie hygiene", "web"), self._check_cookie_flags),
            (CheckPlugin("core.server_banner", DEFAULT_PLUGIN_VERSION, "Version disclosure", "web"), self._check_server_banner),
            (CheckPlugin("core.robots", DEFAULT_PLUGIN_VERSION, "Robots exposure", "web"), self._check_robots),
            (CheckPlugin("core.sensitive_paths", DEFAULT_PLUGIN_VERSION, "Sensitive path checks", "web"), self._check_sensitive_paths),
            (CheckPlugin("core.tls", DEFAULT_PLUGIN_VERSION, "TLS posture", "web"), self._check_tls),
            (CheckPlugin("web.ssrf_sinks", DEFAULT_PLUGIN_VERSION, "SSRF sink parameter detection", "web"), self._check_ssrf_sinks),
            (CheckPlugin("web.open_redirect", DEFAULT_PLUGIN_VERSION, "Open redirect parameters", "web"), self._check_open_redirect),
            (CheckPlugin("web.cache_poisoning", DEFAULT_PLUGIN_VERSION, "Cache poisoning indicators", "web"), self._check_cache_poisoning),
            (CheckPlugin("web.csp_bypass", DEFAULT_PLUGIN_VERSION, "CSP bypass patterns", "web"), self._check_csp_bypass),
            (CheckPlugin("web.jwt_misconfig", DEFAULT_PLUGIN_VERSION, "JWT misconfiguration indicators", "web"), self._check_jwt_misconfig),
            (CheckPlugin("api.graphql", DEFAULT_PLUGIN_VERSION, "GraphQL exposure", "api"), self._check_graphql),
            (CheckPlugin("api.grpc_web", DEFAULT_PLUGIN_VERSION, "gRPC-web exposure", "api"), self._check_grpc_web),
            (CheckPlugin("api.openapi_drift", DEFAULT_PLUGIN_VERSION, "OpenAPI drift indicators", "api"), self._check_openapi_drift),
            (CheckPlugin("api.mass_assignment", DEFAULT_PLUGIN_VERSION, "Mass-assignment risk", "api"), self._check_mass_assignment),
            (CheckPlugin("api.authz_boundary", DEFAULT_PLUGIN_VERSION, "Authorization boundary probes", "api"), self._check_authz_boundary),
            (CheckPlugin("cloud.public_storage", DEFAULT_PLUGIN_VERSION, "Public storage bucket indicators", "cloud"), self._check_public_storage),
            (CheckPlugin("cloud.iam_metadata", DEFAULT_PLUGIN_VERSION, "Leaked IAM metadata paths", "cloud"), self._check_iam_metadata),
            (CheckPlugin("cloud.saas_misconfig", DEFAULT_PLUGIN_VERSION, "Common SaaS misconfiguration indicators", "cloud"), self._check_saas_misconfig),
        ]

    def scan(self, target: str) -> ScanResult:
        normalized = normalize_target(target)
        snapshot = self._fetch(normalized)
        findings: List[Finding] = []

        for plugin, handler in self.plugins:
            plugin_findings = handler(normalized, snapshot)
            for finding in plugin_findings:
                finding.plugin_id = plugin.plugin_id
                finding.plugin_version = plugin.version
                finding.fingerprint = finding.fingerprint or self._fingerprint(finding)
            findings.extend(plugin_findings)

        filtered = [f for f in findings if not self._is_suppressed(f)]
        suppressed = len(findings) - len(filtered)
        return ScanResult(
            target=normalized,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            findings=filtered,
            suppressed_findings=suppressed,
            metadata={
                "status": snapshot.status,
                "server": snapshot.headers.get("Server", "unknown"),
                "findings_count": str(len(filtered)),
                "plugins_loaded": str(len(self.plugins)),
            },
        )

    def _make_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str,
        target: str,
        recommendation: str,
        confidence: float,
        evidence_quality: str,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            target=target,
            recommendation=recommendation,
            plugin_id="unassigned",
            plugin_version=DEFAULT_PLUGIN_VERSION,
            confidence=max(0.0, min(1.0, confidence)),
            evidence_quality=evidence_quality,
        )

    def _fingerprint(self, finding: Finding) -> str:
        payload = "|".join([finding.target, finding.plugin_id, finding.title, finding.evidence])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _is_suppressed(self, finding: Finding) -> bool:
        for rule in self.suppression_rules:
            if rule.plugin_id and rule.plugin_id != finding.plugin_id:
                continue
            if rule.title_contains and rule.title_contains.lower() not in finding.title.lower():
                continue
            if rule.target_regex and not re.search(rule.target_regex, finding.target):
                continue
            if finding.confidence < rule.min_confidence:
                continue
            return True
        return False

    def _fetch(self, url: str) -> ResponseSnapshot:
        req = Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(250_000).decode("utf-8", errors="ignore")
                return ResponseSnapshot(url=url, status=str(resp.status), headers={k: v for k, v in resp.headers.items()}, body=body)
        except HTTPError as exc:
            body = exc.read(250_000).decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
            return ResponseSnapshot(url=url, status=str(exc.code), headers={k: v for k, v in exc.headers.items()}, body=body)
        except URLError:
            return ResponseSnapshot(url=url, status="unreachable", headers={}, body="")

    def _check_missing_security_headers(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        missing = [h for h in SECURITY_HEADERS if h not in snapshot.headers]
        if not missing:
            return []
        return [
            self._make_finding(
                "Missing security headers",
                "medium",
                "The target response lacks recommended browser security headers.",
                f"Missing: {', '.join(missing)}",
                target,
                "Set hardened defaults for CSP, HSTS, clickjacking, MIME sniffing, and referrer policy.",
                confidence=0.8,
                evidence_quality="high",
            )
        ]

    def _check_cors(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        origin = snapshot.headers.get("Access-Control-Allow-Origin", "")
        creds = snapshot.headers.get("Access-Control-Allow-Credentials", "")
        findings: List[Finding] = []
        if origin == "*" and creds.lower() == "true":
            findings.append(self._make_finding("Potentially dangerous CORS policy", "high", "Wildcard CORS origin appears alongside credential support.", f"ACAO={origin}, ACAC={creds}", target, "Restrict origins and avoid credentialed wildcard policies.", 0.9, "high"))
        elif origin == "*":
            findings.append(self._make_finding("Permissive CORS wildcard", "medium", "Target allows any origin to access resources.", "ACAO=*", target, "Use an explicit allow-list of trusted front-end origins.", 0.75, "high"))
        elif origin and "localhost" in origin.lower():
            findings.append(self._make_finding("CORS trust reflection candidate", "medium", "CORS allows localhost-style origins that are often over-trusted.", f"ACAO={origin}", target, "Use strict origin validation and explicit environment allow-lists.", 0.7, "medium"))
        return findings

    def _check_cookie_flags(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        cookie_header = snapshot.headers.get("Set-Cookie", "")
        if not cookie_header:
            return []
        findings: List[Finding] = []
        lowered = cookie_header.lower()
        if "httponly" not in lowered:
            findings.append(self._make_finding("Session cookie may be missing HttpOnly", "medium", "Cookies without HttpOnly can be read by client-side scripts.", f"Set-Cookie={cookie_header[:200]}", target, "Set HttpOnly on session and auth cookies.", 0.7, "medium"))
        if "secure" not in lowered:
            findings.append(self._make_finding("Session cookie may be missing Secure flag", "medium", "Cookies without Secure may traverse plaintext channels in mixed deployments.", f"Set-Cookie={cookie_header[:200]}", target, "Set Secure on sensitive cookies and enforce HTTPS.", 0.75, "medium"))
        if "samesite" not in lowered:
            findings.append(self._make_finding("Session cookie may be missing SameSite", "low", "Absent SameSite can increase cross-site request exposure.", f"Set-Cookie={cookie_header[:200]}", target, "Set SameSite=Lax/Strict where appropriate.", 0.65, "medium"))
        return findings

    def _check_server_banner(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        server = snapshot.headers.get("Server", "")
        if server and re.search(r"\d", server):
            return [self._make_finding("Potential version disclosure in server banner", "low", "Server header appears to include version information.", f"Server={server}", target, "Minimize version disclosure in response headers.", 0.7, "high")]
        return []

    def _check_robots(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        robots_url = f"{target.rstrip('/')}/robots.txt"
        robots = self._fetch(robots_url)
        if robots.status == "unreachable" or int(robots.status) >= 400 if robots.status.isdigit() else True:
            return []
        suspicious = []
        for line in robots.body.splitlines():
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip().lower()
                if any(pattern in path for pattern in INTERESTING_ROBOTS_PATTERNS):
                    suspicious.append(path)
        findings: List[Finding] = []
        if suspicious:
            findings.append(self._make_finding("Interesting paths exposed in robots.txt", "low", "robots.txt may disclose sensitive endpoints.", "; ".join(suspicious), target, "Avoid listing sensitive application routes in robots.txt.", 0.7, "high"))
        return findings

    def _check_sensitive_paths(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        findings: List[Finding] = []
        for path in COMMON_SENSITIVE_PATHS:
            url = f"{target.rstrip('/')}{path}"
            path_snapshot = self._fetch(url)
            if path_snapshot.status.isdigit() and int(path_snapshot.status) < 400:
                severity = "high" if any(x in path for x in [".env", "backup", ".sql", ".git"]) else "medium"
                findings.append(self._make_finding("Potential sensitive file or endpoint exposed", severity, "A potentially sensitive path appears reachable.", f"{url} -> HTTP {path_snapshot.status}", target, "Restrict access and ensure sensitive artifacts are never web-accessible.", 0.85, "high"))
        return findings

    def _check_tls(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        parsed = urlparse(target)
        if parsed.scheme != "https":
            return [self._make_finding("Target is not using HTTPS", "medium", "Traffic may be vulnerable to interception without TLS.", f"scheme={parsed.scheme}", target, "Serve the application exclusively over HTTPS and redirect HTTP to HTTPS.", 0.95, "high")]
        host = parsed.hostname
        if not host:
            return []
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
                    return [self._make_finding("TLS certificate expires soon", "medium", "Certificate lifecycle risk can cause outages and trust warnings.", f"Certificate expires in {remaining_days} day(s)", target, "Rotate/renew TLS certificates before expiry.", 0.85, "high")]
            except ValueError:
                return []
        return []

    def _check_ssrf_sinks(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        sinks = re.findall(r"(?:url|uri|redirect|dest|callback|next)=", snapshot.body, re.IGNORECASE)
        if not sinks:
            return []
        return [self._make_finding("Potential SSRF sink parameter pattern", "medium", "Response body includes URL-like sink parameter names frequently abused in SSRF chains.", f"Matched sink tokens: {len(sinks)}", target, "Validate outbound destinations against strict allow-lists and block metadata IP ranges.", 0.6, "low")]

    def _check_open_redirect(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        location = snapshot.headers.get("Location", "")
        if location.startswith("http") and target not in location:
            return [self._make_finding("Potential open redirect behavior", "medium", "Redirect points to external absolute URL.", f"Location={location}", target, "Validate redirect destinations and constrain to internal paths or trusted hosts.", 0.75, "high")]
        if re.search(r"(?:next|return|redirect|url)=https?://", snapshot.body, re.IGNORECASE):
            return [self._make_finding("Open redirect parameter candidate", "low", "Body references user-controlled redirect-like parameters.", "Detected redirect parameter in response content", target, "Apply strict canonicalization and allow-listing for redirect targets.", 0.55, "low")]
        return []

    def _check_cache_poisoning(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        cache = snapshot.headers.get("Cache-Control", "")
        vary = snapshot.headers.get("Vary", "")
        if "public" in cache.lower() and "host" not in vary.lower() and "x-forwarded-host" not in vary.lower():
            return [self._make_finding("Cache poisoning indicator", "medium", "Public caching is enabled without host-related Vary controls.", f"Cache-Control={cache}; Vary={vary or 'none'}", target, "Review cache key composition and include trusted host/proto controls at the edge.", 0.65, "medium")]
        return []

    def _check_csp_bypass(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        csp = snapshot.headers.get("Content-Security-Policy", "")
        if not csp:
            return []
        weak_tokens = ["'unsafe-inline'", "'unsafe-eval'", "data:"]
        found = [t for t in weak_tokens if t in csp]
        if found:
            return [self._make_finding("CSP bypass-friendly directives", "medium", "CSP includes directives associated with common bypasses.", f"CSP weak tokens: {', '.join(found)}", target, "Harden CSP by removing unsafe directives and using nonces/hashes.", 0.8, "high")]
        return []

    def _check_jwt_misconfig(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        candidates = re.findall(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{2,}", snapshot.body)
        if candidates:
            return [self._make_finding("JWT token exposure in response", "medium", "Response appears to expose JWT-like token material.", f"Detected {len(candidates)} JWT-like strings", target, "Avoid exposing reusable bearer tokens in cacheable/page content and enforce secure token handling.", 0.7, "medium")]
        if "jwt" in snapshot.headers.get("Server", "").lower() and "none" in snapshot.body.lower():
            return [self._make_finding("JWT algorithm confusion indicator", "low", "Found weak JWT hints (e.g., 'none' references).", "Server/body contain JWT + none hints", target, "Ensure JWT verification disallows alg=none and enforces strict algorithms.", 0.5, "low")]
        return []

    def _check_graphql(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        if "graphql" in snapshot.body.lower() or "/graphql" in snapshot.body.lower():
            return [self._make_finding("GraphQL endpoint indicator", "info", "Target may expose GraphQL surface area.", "Found graphql markers in body", target, "Disable introspection in production and enforce resolver authz checks.", 0.6, "low")]
        return []

    def _check_grpc_web(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        if "application/grpc-web" in snapshot.headers.get("Content-Type", "") or "x-grpc-web" in snapshot.body.lower():
            return [self._make_finding("gRPC-web endpoint indicator", "info", "Detected gRPC-web content markers.", "grpc-web marker present", target, "Validate authn/authz and input controls in gRPC-web gateways.", 0.65, "medium")]
        return []

    def _check_openapi_drift(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        body = snapshot.body.lower()
        if "openapi" in body and "deprecated" in body:
            return [self._make_finding("OpenAPI drift indicator", "low", "Specification hints include deprecated routes that may remain reachable.", "openapi + deprecated markers found", target, "Continuously compare deployed routes to API spec and retire undocumented handlers.", 0.6, "low")]
        return []

    def _check_mass_assignment(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        if re.search(r"(?:is_admin|role|permissions)\s*[:=]", snapshot.body, re.IGNORECASE):
            return [self._make_finding("Mass-assignment indicator", "medium", "Privileged fields appear in serializable payloads.", "Detected role/is_admin style fields", target, "Use explicit allow-lists for writable fields and enforce server-side authorization checks.", 0.65, "medium")]
        return []

    def _check_authz_boundary(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        if re.search(r"/(?:admin|internal|staff|superuser)", snapshot.body, re.IGNORECASE):
            return [self._make_finding("Authorization boundary probe target", "low", "Potential privileged endpoints discovered in unauthenticated content.", "Found admin/internal route markers", target, "Require strong object/function-level authorization on all privileged routes.", 0.55, "low")]
        return []

    def _check_public_storage(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        patterns = [r"s3\.amazonaws\.com", r"storage\.googleapis\.com", r"blob\.core\.windows\.net"]
        hits = [p for p in patterns if re.search(p, snapshot.body, re.IGNORECASE)]
        if hits:
            return [self._make_finding("Public cloud storage reference", "medium", "Response references cloud object storage domains that should be validated for public access.", f"Matched storage domains: {', '.join(hits)}", target, "Audit bucket/container ACLs, block anonymous list/read unless explicitly intended.", 0.6, "low")]
        return []

    def _check_iam_metadata(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        metadata_markers = ["169.254.169.254", "metadata.google.internal", "/latest/meta-data/"]
        found = [m for m in metadata_markers if m in snapshot.body]
        if found:
            return [self._make_finding("Leaked IAM metadata path indicator", "high", "Response includes cloud metadata service markers.", f"Metadata markers: {', '.join(found)}", target, "Block SSRF to metadata endpoints and sanitize logs/templates leaking metadata URLs.", 0.8, "medium")]
        return []

    def _check_saas_misconfig(self, target: str, snapshot: ResponseSnapshot) -> List[Finding]:
        markers = ["atlassian.net", "okta.com", "salesforce.com", "sharepoint.com"]
        found = [m for m in markers if m in snapshot.body.lower()]
        if found:
            return [self._make_finding("SaaS trust/misconfiguration indicator", "low", "Response references SaaS tenancy URLs that may expose trust or SSO misconfiguration paths.", f"SaaS markers: {', '.join(found)}", target, "Review SaaS tenant sharing, SSO trust, and public-link policies.", 0.5, "low")]
        return []


class ChatGPTTriage:
    """Uses OpenAI Chat Completions API to prioritize findings and build a report."""

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        self.model = model
        self.api_key = os.getenv("OPENAI_API_KEY", "")

    def summarize(self, scan_results: Sequence[ScanResult], diff_result: Optional[DiffResult] = None) -> str:
        if not self.api_key:
            return self._local_summary(scan_results, diff_result)
        try:
            import requests
        except ImportError:
            return self._local_summary(scan_results, diff_result)
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
                    "content": json.dumps({"results": [scan_result_to_dict(s) for s in scan_results], "diff": asdict(diff_result) if diff_result else None}, indent=2),
                },
            ],
            "temperature": 0.2,
        }
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json=payload,
                timeout=30,
            )
        except Exception:
            return self._local_summary(scan_results, diff_result)
        if response.status_code >= 400:
            return self._local_summary(scan_results, diff_result)
        data = response.json()
        choices = data.get("choices", [])
        if not choices:
            return self._local_summary(scan_results, diff_result)
        return choices[0].get("message", {}).get("content", self._local_summary(scan_results, diff_result))

    def _local_summary(self, scan_results: Sequence[ScanResult], diff_result: Optional[DiffResult] = None) -> str:
        all_findings = [finding for result in scan_results for finding in result.findings]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(all_findings, key=lambda f: severity_order.get(f.severity, 9))
        severity_counts: Dict[str, int] = {}
        for finding in sorted_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        lines = ["# Blackbox Triage Report (Local Fallback)", "", "OPENAI_API_KEY not set or API unavailable, so this report uses built-in ranking.", "", "## Severity Summary"]
        lines.extend(f"- {sev.upper()}: {count}" for sev, count in sorted(severity_counts.items(), key=lambda kv: severity_order.get(kv[0], 9)))
        lines.extend(["", "## Top Findings"])
        if not sorted_findings:
            lines.append("No findings detected by lightweight checks.")
            return "\n".join(lines)
        for finding in sorted_findings[:20]:
            lines.extend([
                f"- **[{finding.severity.upper()}] {finding.title}** ({finding.target})",
                f"  - Plugin: {finding.plugin_id}@{finding.plugin_version}",
                f"  - Confidence: {finding.confidence:.2f} | Evidence quality: {finding.evidence_quality}",
                f"  - Evidence: {finding.evidence}",
                f"  - Recommendation: {finding.recommendation}",
            ])
        if diff_result:
            lines.extend([
                "",
                "## Baseline Diff",
                f"- Baseline findings: {diff_result.baseline_total}",
                f"- Current findings: {diff_result.current_total}",
                f"- Newly introduced findings: {len(diff_result.new_findings)}",
            ])
        lines.extend(["", "## Validation Workflow", "1. Reproduce each finding manually in scope-approved targets.", "2. Confirm exploitability and real impact.", "3. Draft vendor-safe proof-of-concept and remediation guidance.", "4. Submit responsibly through the program policy channels."])
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
        "suppressed_findings": result.suppressed_findings,
        "findings": [asdict(finding) for finding in result.findings],
    }


def write_outputs(results: Sequence[ScanResult], summary: str, out_dir: Path, diff_result: Optional[DiffResult] = None) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "scan_results.json"
    md_path = out_dir / "triage_report.md"
    payload: Dict[str, object] = {"results": [scan_result_to_dict(r) for r in results]}
    if diff_result:
        payload["diff"] = {
            "baseline_total": diff_result.baseline_total,
            "current_total": diff_result.current_total,
            "new_findings": [asdict(f) for f in diff_result.new_findings],
        }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(summary, encoding="utf-8")
    return json_path, md_path


def parse_suppressions(path: Optional[str]) -> List[SuppressionRule]:
    if not path:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Suppression file must be a JSON list")
    return [SuppressionRule(**item) for item in data]


def load_baseline_fingerprints(path: Optional[str]) -> Set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = data.get("results", []) if isinstance(data, dict) else data
    fps: Set[str] = set()
    for result in results:
        for finding in result.get("findings", []):
            fp = finding.get("fingerprint")
            if fp:
                fps.add(fp)
    return fps


def compute_diff(results: Sequence[ScanResult], baseline_fingerprints: Set[str]) -> Optional[DiffResult]:
    if not baseline_fingerprints:
        return None
    current = [f for r in results for f in r.findings]
    new_findings = [f for f in current if f.fingerprint not in baseline_fingerprints]
    return DiffResult(baseline_total=len(baseline_fingerprints), current_total=len(current), new_findings=new_findings)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Blackbox automated security triage tool powered by ChatGPT")
    parser.add_argument("--target", action="append", default=[], help="Target host or URL (can be repeated)")
    parser.add_argument("--targets-file", help="File with one target per line")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model for triage")
    parser.add_argument("--out-dir", default="reports", help="Directory for generated artifacts")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="HTTP/TLS timeout in seconds")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Concurrent target scans")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent for scan requests")
    parser.add_argument("--suppressions-file", help="JSON file with suppression rules")
    parser.add_argument("--baseline-file", help="Previous scan_results.json for diff scanning")
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
        suppression_rules = parse_suppressions(args.suppressions_file)
        baseline_fingerprints = load_baseline_fingerprints(args.baseline_file)
    except Exception as exc:
        print(f"[!] {exc}")
        return 1

    scanner = LightweightScanner(timeout=args.timeout, user_agent=args.user_agent, suppression_rules=suppression_rules)
    print(f"[*] Scanning {len(targets)} target(s) with max_workers={max(1, args.max_workers)}")
    results = run_scans(targets, scanner=scanner, max_workers=args.max_workers)
    diff_result = compute_diff(results, baseline_fingerprints)

    triage = ChatGPTTriage(model=args.model)
    summary = triage.summarize(results, diff_result)
    json_path, md_path = write_outputs(results, summary, Path(args.out_dir), diff_result)
    print(f"[+] Saved JSON results to {json_path}")
    print(f"[+] Saved triage report to {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
