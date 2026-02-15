"""Security vulnerabilities scanner - detect web security issues and vulnerabilities.

This analyzer performs comprehensive security vulnerability scanning including:
- Outdated software detection (based on technology fingerprints)
- Known vulnerable JavaScript libraries
- Missing security headers
- SSL/TLS configuration issues
- Cookie security flags
- Sensitive information exposure
- Common web vulnerabilities (clickjacking, MIME sniffing)

Completely self-contained with config, logic, and output formatting.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import Field

from ..constants import DEFAULT_USER_AGENT
from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class SecurityVulnsConfig(AnalyzerConfig):
    """Security vulnerabilities analyzer configuration."""

    check_outdated_software: bool = Field(
        default=True, description="Check for outdated software based on technology fingerprints"
    )
    check_vulnerable_js: bool = Field(
        default=True, description="Check for known vulnerable JavaScript libraries"
    )
    check_security_headers: bool = Field(
        default=True, description="Check for missing security headers"
    )
    check_ssl_issues: bool = Field(
        default=True, description="Check for SSL/TLS configuration issues"
    )
    check_cookie_security: bool = Field(
        default=True, description="Check for cookie security flags"
    )
    check_info_exposure: bool = Field(
        default=True, description="Check for sensitive information exposure"
    )
    check_common_vulns: bool = Field(
        default=True, description="Check for common web vulnerabilities"
    )
    user_agent: str = Field(default=DEFAULT_USER_AGENT, description="User agent for HTTP requests")


# ============================================================================
# Vulnerability Database
# ============================================================================

# Known vulnerable JavaScript libraries and versions
VULNERABLE_JS_LIBRARIES: dict[str, list[tuple[str, str, str, str]]] = {
    "jquery": [
        (r"^[1-2]\.", "CVE-2020-11022", "medium", "XSS vulnerability in jQuery < 3.5.0"),
        (r"^3\.[0-4]\.", "CVE-2020-11022", "medium", "XSS vulnerability in jQuery < 3.5.0"),
    ],
    "angular": [
        (r"^1\.[0-6]\.", "CVE-2019-10768", "high", "Prototype pollution in AngularJS < 1.7.9"),
        (r"^1\.7\.[0-8]$", "CVE-2019-10768", "high", "Prototype pollution in AngularJS < 1.7.9"),
    ],
    "lodash": [
        (r"^[0-3]\.", "CVE-2019-10744", "high", "Prototype pollution in lodash < 4.17.12"),
    ],
    "moment.js": [
        (r"^[0-2]\.", "CVE-2022-31129", "medium", "ReDoS vulnerability in moment.js < 2.29.4"),
    ],
    "bootstrap": [
        (r"^[1-3]\.", "CVE-2019-8331", "medium", "XSS vulnerability in Bootstrap < 3.4.1"),
    ],
}

# Outdated software detection rules
OUTDATED_SOFTWARE: dict[str, tuple[str, str, str]] = {
    "PHP 5": ("2018-12-31", "critical", "PHP 5 reached EOL. Upgrade to PHP 8.x immediately"),
    "PHP 7.0": ("2018-12-03", "critical", "PHP 7.0 reached EOL. Upgrade to PHP 8.x"),
    "PHP 7.1": ("2019-12-01", "critical", "PHP 7.1 reached EOL. Upgrade to PHP 8.x"),
    "PHP 7.2": ("2020-11-30", "critical", "PHP 7.2 reached EOL. Upgrade to PHP 8.x"),
    "PHP 7.3": ("2021-12-06", "high", "PHP 7.3 reached EOL. Upgrade to PHP 8.x"),
    "PHP 7.4": ("2022-11-28", "high", "PHP 7.4 reached EOL. Upgrade to PHP 8.x"),
    "WordPress 4": ("2019-12-31", "high", "WordPress 4.x is outdated. Upgrade to latest version"),
    "Drupal 7": ("2022-11-01", "high", "Drupal 7 reached EOL. Upgrade to Drupal 10.x"),
    "Drupal 8": ("2021-11-02", "high", "Drupal 8 reached EOL. Upgrade to Drupal 10.x"),
    "Joomla 3": ("2023-08-17", "high", "Joomla 3 reached EOL. Upgrade to Joomla 5.x"),
    "Python 2.7": ("2020-01-01", "critical", "Python 2.7 reached EOL. Upgrade to Python 3.x"),
    "Python 3.6": ("2021-12-23", "high", "Python 3.6 reached EOL. Upgrade to Python 3.11+"),
    "Python 3.7": ("2023-06-27", "high", "Python 3.7 reached EOL. Upgrade to Python 3.11+"),
    "Node.js 10": ("2021-04-30", "high", "Node.js 10 reached EOL. Upgrade to Node.js 20 LTS"),
    "Node.js 12": ("2022-04-30", "high", "Node.js 12 reached EOL. Upgrade to Node.js 20 LTS"),
    "Apache 2.2": ("2017-07-11", "critical", "Apache 2.2 reached EOL. Upgrade to Apache 2.4"),
}

# Required security headers with descriptions
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "severity": "high",
        "recommendation": "Add CSP header to prevent XSS attacks",
    },
    "X-Frame-Options": {
        "description": "Clickjacking protection",
        "severity": "medium",
        "recommendation": "Add: X-Frame-Options: SAMEORIGIN or DENY",
    },
    "X-Content-Type-Options": {
        "description": "MIME type sniffing protection",
        "severity": "medium",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "description": "Referrer information control",
        "severity": "low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Browser feature control",
        "severity": "medium",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

# Sensitive information patterns to detect
SENSITIVE_PATTERNS = [
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "Private key exposed"),
    (r"password\s*[:=]\s*['\"][^'\"]+['\"]", "Potential password in code"),
    (r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]", "API key exposed"),
    (r"secret[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]", "Secret key exposed"),
]

# Cookie security issues
COOKIE_SECURITY_ISSUES = {
    "missing_secure": {
        "description": "Cookie transmitted over HTTP",
        "severity": "high",
        "recommendation": "Add Secure flag to cookie",
    },
    "missing_httponly": {
        "description": "Cookie accessible via JavaScript (XSS risk)",
        "severity": "medium",
        "recommendation": "Add HttpOnly flag to cookie",
    },
    "missing_samesite": {
        "description": "Cookie vulnerable to CSRF attacks",
        "severity": "medium",
        "recommendation": "Add SameSite=Strict or SameSite=Lax to cookie",
    },
}


# ============================================================================
# Result Models
# ============================================================================


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability."""

    vuln_id: str
    category: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # high, medium, low
    evidence: str | None = None
    cwe: str | None = None
    cve: str | None = None
    recommendation: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class SecurityVulnsResult:
    """Results from security vulnerabilities analysis."""

    domain: str
    url: str = ""
    
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    risk_score: int = 0
    
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================================
# Analyzer Implementation
# ============================================================================


@registry.register
class SecurityVulnsAnalyzer:
    """Security vulnerabilities scanner."""

    analyzer_id = "security-vulns"
    name = "Security Vulnerabilities"
    description = "Scan for web security vulnerabilities and issues"
    category = "security"
    icon = "shield"
    config_class = SecurityVulnsConfig
    depends_on = ["http", "technology", "ssl", "headers"]

    def analyze(
        self,
        domain: str,
        config: SecurityVulnsConfig,
        context: dict[str, Any] | None = None,
    ) -> SecurityVulnsResult:
        """Perform security vulnerabilities analysis."""
        logger.info(f"Starting security vulnerabilities analysis for {domain}")
        result = SecurityVulnsResult(domain=domain)

        domain = domain.rstrip("/").lower()
        
        http_result = context.get("http") if context else None
        technology_result = context.get("technology") if context else None
        ssl_result = context.get("ssl") if context else None
        headers_result = context.get("headers") if context else None

        http_headers = {}
        html_content = None
        cookies = []
        
        if http_result:
            if hasattr(http_result, "headers"):
                http_headers = http_result.headers
            if hasattr(http_result, "html_content"):
                html_content = http_result.html_content
            if hasattr(http_result, "preferred_final_url"):
                result.url = http_result.preferred_final_url or ""
        
        if headers_result and hasattr(headers_result, "headers"):
            http_headers = headers_result.headers

        technologies = []
        if technology_result and hasattr(technology_result, "technologies"):
            technologies = technology_result.technologies

        ssl_info = {}
        ssl_protocols = []
        if ssl_result:
            if hasattr(ssl_result, "certificates"):
                ssl_info = ssl_result.certificates
            if hasattr(ssl_result, "protocols"):
                ssl_protocols = ssl_result.protocols

        vuln_id = 0
        
        if config.check_outdated_software and technologies:
            vuln_id = self._check_outdated_software(technologies, result, vuln_id)
        
        if config.check_vulnerable_js and technologies:
            vuln_id = self._check_vulnerable_js(technologies, result, vuln_id)
        
        if config.check_security_headers and http_headers:
            vuln_id = self._check_security_headers(http_headers, result, vuln_id)
        
        if config.check_ssl_issues and ssl_protocols:
            vuln_id = self._check_ssl_issues(ssl_protocols, ssl_info, result, vuln_id)
        
        if config.check_cookie_security and cookies:
            vuln_id = self._check_cookie_security(cookies, result, vuln_id)
        
        if config.check_info_exposure and html_content:
            vuln_id = self._check_info_exposure(html_content, result, vuln_id)
        
        if config.check_common_vulns and http_headers:
            vuln_id = self._check_common_vulns(http_headers, result, vuln_id)

        self._calculate_summary(result)
        
        logger.info(f"Found {result.total_vulnerabilities} vulnerabilities for {domain}")
        
        return result

    def _check_outdated_software(
        self, technologies: list[Any], result: SecurityVulnsResult, vuln_id: int
    ) -> int:
        """Check for outdated software."""
        tech_map = {}
        for tech in technologies:
            if hasattr(tech, "name") and hasattr(tech, "evidence"):
                tech_map[tech.name.lower()] = tech.evidence

        for tech_key, (eol_date, severity, recommendation) in OUTDATED_SOFTWARE.items():
            tech_lower = tech_key.lower()
            detected = False
            evidence_str = ""
            
            for tech_name, evidence in tech_map.items():
                if tech_lower in tech_name or tech_name in tech_lower:
                    detected = True
                    if evidence:
                        evidence_str = ", ".join(evidence[:3])
                    break
            
            if detected:
                try:
                    eol_dt = datetime.strptime(eol_date, "%Y-%m-%d")
                    if eol_dt < datetime.now():
                        vuln_id += 1
                        vuln = Vulnerability(
                            vuln_id=f"SV-{vuln_id:04d}",
                            category="outdated-software",
                            title=f"Outdated Software: {tech_key}",
                            description=f"{tech_key} reached end-of-life on {eol_date}",
                            severity=severity,
                            confidence="high",
                            evidence=evidence_str or "Detected in page",
                            cwe="CWE-1104",
                            recommendation=recommendation,
                        )
                        result.vulnerabilities.append(vuln)
                except ValueError:
                    pass
        
        return vuln_id

    def _check_vulnerable_js(
        self, technologies: list[Any], result: SecurityVulnsResult, vuln_id: int
    ) -> int:
        """Check for vulnerable JavaScript libraries."""
        for tech in technologies:
            if not hasattr(tech, "name") or not hasattr(tech, "category"):
                continue
            
            if tech.category not in ["library", "framework"]:
                continue
            
            tech_name = tech.name.lower()
            evidence_list = tech.evidence if hasattr(tech, "evidence") else []
            evidence_str = " ".join(evidence_list) if evidence_list else ""
            
            for lib_name, vulns in VULNERABLE_JS_LIBRARIES.items():
                if lib_name in tech_name or tech_name in lib_name:
                    for version_pattern, cve_id, severity, description in vulns:
                        if evidence_str and re.search(version_pattern, evidence_str, re.IGNORECASE):
                            vuln_id += 1
                            vuln = Vulnerability(
                                vuln_id=f"SV-{vuln_id:04d}",
                                category="vulnerable-js",
                                title=f"Vulnerable JavaScript Library: {tech.name}",
                                description=description,
                                severity=severity,
                                confidence="medium" if evidence_str else "low",
                                evidence=evidence_str or "Library detected without version",
                                cve=cve_id,
                                cwe="CWE-1035",
                                recommendation=f"Update {tech.name} to the latest version",
                            )
                            result.vulnerabilities.append(vuln)
                            break
        
        return vuln_id

    def _check_security_headers(
        self, headers: dict[str, str], result: SecurityVulnsResult, vuln_id: int
    ) -> int:
        """Check for missing security headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, info in REQUIRED_SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            
            if header_lower not in headers_lower:
                vuln_id += 1
                vuln = Vulnerability(
                    vuln_id=f"SV-{vuln_id:04d}",
                    category="headers",
                    title=f"Missing Security Header: {header_name}",
                    description=f"Missing {info['description']} header",
                    severity=info["severity"],
                    confidence="high",
                    cwe="CWE-693",
                    recommendation=info["recommendation"],
                )
                result.vulnerabilities.append(vuln)
            else:
                value = headers_lower[header_lower]
                
                if header_lower == "content-security-policy":
                    if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                        vuln_id += 1
                        vuln = Vulnerability(
                            vuln_id=f"SV-{vuln_id:04d}",
                            category="headers",
                            title="Weak Content Security Policy",
                            description="CSP contains unsafe directives",
                            severity="medium",
                            confidence="high",
                            evidence=value,
                            recommendation="Remove 'unsafe-inline' and 'unsafe-eval' from CSP",
                        )
                        result.vulnerabilities.append(vuln)
        
        return vuln_id

    def _check_ssl_issues(
        self, protocols: list[str], ssl_info: dict[str, Any],
        result: SecurityVulnsResult, vuln_id: int
    ) -> int:
        """Check for SSL/TLS issues."""
        deprecated_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        
        for protocol in protocols:
            if protocol in deprecated_protocols:
                severity = "high" if protocol in ["SSLv2", "SSLv3"] else "medium"
                vuln_id += 1
                vuln = Vulnerability(
                    vuln_id=f"SV-{vuln_id:04d}",
                    category="ssl",
                    title=f"Deprecated TLS Protocol: {protocol}",
                    description=f"{protocol} is deprecated and insecure",
                    severity=severity,
                    confidence="high",
                    cwe="CWE-327",
                    recommendation=f"Disable {protocol} and enable TLSv1.2 and TLSv1.3 only",
                )
                result.vulnerabilities.append(vuln)
        
        if "TLSv1.3" not in protocols and protocols:
            vuln_id += 1
            vuln = Vulnerability(
                vuln_id=f"SV-{vuln_id:04d}",
                category="ssl",
                title="TLS 1.3 Not Supported",
                description="TLS 1.3 is not supported",
                severity="low",
                confidence="high",
                recommendation="Enable TLS 1.3 for improved security",
            )
            result.vulnerabilities.append(vuln)
        
        return vuln_id

    def _check_cookie_security(
        self, cookies: list[Any], result: SecurityVulnsResult, vuln_id: int
    ) -> int:
        """Check for cookie security issues."""
        for cookie in cookies:
            if isinstance(cookie, dict):
                cookie_name = cookie.get("name", "")
                secure = cookie.get("secure", False)
                httponly = cookie.get("httponly", False)
                samesite = cookie.get("samesite", None)
            elif hasattr(cookie, "name"):
                cookie_name = cookie.name
                secure = getattr(cookie, "secure", False)
                httponly = getattr(cookie, "httponly", False)
                samesite = getattr(cookie, "samesite", None)
            else:
                continue

            if not secure:
                vuln_id += 1
                issue = COOKIE_SECURITY_ISSUES["missing_secure"]
                vuln = Vulnerability(
                    vuln_id=f"SV-{vuln_id:04d}",
                    category="cookies",
                    title=f"Insecure Cookie: {cookie_name}",
                    description=f"Cookie '{cookie_name}' missing Secure flag",
                    severity=issue["severity"],
                    confidence="high",
                    recommendation=issue["recommendation"],
                )
                result.vulnerabilities.append(vuln)
            
            if not httponly:
                vuln_id += 1
                issue = COOKIE_SECURITY_ISSUES["missing_httponly"]
                vuln = Vulnerability(
                    vuln_id=f"SV-{vuln_id:04d}",
                    category="cookies",
                    title=f"Cookie Vulnerable to XSS: {cookie_name}",
                    description=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    severity=issue["severity"],
                    confidence="high",
                    recommendation=issue["recommendation"],
                )
                result.vulnerabilities.append(vuln)
            
            if not samesite:
                vuln_id += 1
                issue = COOKIE_SECURITY_ISSUES["missing_samesite"]
                vuln = Vulnerability(
                    vuln_id=f"SV-{vuln_id:04d}",
                    category="cookies",
                    title=f"Cookie Vulnerable to CSRF: {cookie_name}",
                    description=f"Cookie '{cookie_name}' missing SameSite flag",
                    severity=issue["severity"],
                    confidence="high",
                    recommendation=issue["recommendation"],
                )
                result.vulnerabilities.append(vuln)
        
        return vuln_id

    def _check_info_exposure(
        self, html_content: str, result: SecurityVulnsResult, vuln_id: int
    ) -> int:
        """Check for sensitive information exposure."""
        for pattern, description in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            
            if matches:
                for match in matches[:3]:
                    vuln_id += 1
                    vuln = Vulnerability(
                        vuln_id=f"SV-{vuln_id:04d}",
                        category="info-exposure",
                        title="Sensitive Information Exposure",
                        description=description,
                        severity="medium",
                        confidence="low",
                        evidence=str(match)[:100] if match else None,
                        cwe="CWE-200",
                        recommendation="Remove sensitive data from client-side code",
                    )
                    result.vulnerabilities.append(vuln)
        
        return vuln_id

    def _check_common_vulns(
        self, headers: dict[str, str], result: SecurityVulnsResult, vuln_id: int
    ) -> int:
        """Check for common web vulnerabilities."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        x_frame_options = headers_lower.get("x-frame-options", "").lower()
        csp = headers_lower.get("content-security-policy", "").lower()
        
        if not x_frame_options and "frame-ancestors" not in csp:
            vuln_id += 1
            vuln = Vulnerability(
                vuln_id=f"SV-{vuln_id:04d}",
                category="common-vulns",
                title="Clickjacking Vulnerability",
                description="Page can be embedded in frames, allowing clickjacking",
                severity="medium",
                confidence="high",
                cwe="CWE-1021",
                recommendation="Add X-Frame-Options header or CSP frame-ancestors",
            )
            result.vulnerabilities.append(vuln)
        
        x_content_type = headers_lower.get("x-content-type-options", "").lower()
        if x_content_type != "nosniff":
            vuln_id += 1
            vuln = Vulnerability(
                vuln_id=f"SV-{vuln_id:04d}",
                category="common-vulns",
                title="MIME Sniffing Vulnerability",
                description="Browser may interpret files as different MIME types",
                severity="medium",
                confidence="high",
                cwe="CWE-1173",
                recommendation="Add X-Content-Type-Options: nosniff header",
            )
            result.vulnerabilities.append(vuln)
        
        server_header = headers_lower.get("server", "")
        if server_header and re.search(r"\d", server_header):
            vuln_id += 1
            vuln = Vulnerability(
                vuln_id=f"SV-{vuln_id:04d}",
                category="common-vulns",
                title="Server Version Disclosure",
                description=f"Server header reveals version: {server_header}",
                severity="low",
                confidence="high",
                cwe="CWE-200",
                recommendation="Hide version information in Server header",
            )
            result.vulnerabilities.append(vuln)
        
        x_powered_by = headers_lower.get("x-powered-by", "")
        if x_powered_by:
            vuln_id += 1
            vuln = Vulnerability(
                vuln_id=f"SV-{vuln_id:04d}",
                category="common-vulns",
                title="Technology Disclosure",
                description=f"X-Powered-By header reveals: {x_powered_by}",
                severity="low",
                confidence="high",
                cwe="CWE-200",
                recommendation="Remove X-Powered-By header",
            )
            result.vulnerabilities.append(vuln)
        
        return vuln_id

    def _calculate_summary(self, result: SecurityVulnsResult) -> None:
        """Calculate summary statistics."""
        result.total_vulnerabilities = len(result.vulnerabilities)
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in result.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        result.critical_count = severity_counts["critical"]
        result.high_count = severity_counts["high"]
        result.medium_count = severity_counts["medium"]
        result.low_count = severity_counts["low"]
        result.info_count = severity_counts["info"]
        
        # Calculate risk score (0-100)
        score = 0
        score += result.critical_count * 25
        score += result.high_count * 15
        score += result.medium_count * 5
        score += result.low_count * 1
        result.risk_score = min(score, 100)

    def describe_output(self, result: SecurityVulnsResult) -> OutputDescriptor:
        """Describe how to render results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        descriptor.quiet_summary = lambda r: f"Vulnerabilities: {r.total_vulnerabilities} (Risk: {r.risk_score}/100)"

        # Risk score
        score = result.risk_score
        if score >= 75:
            score_style = "error"
            score_icon = "cross"
        elif score >= 50:
            score_style = "warning"
            score_icon = "warning"
        elif score >= 25:
            score_style = "info"
            score_icon = "info"
        else:
            score_style = "success"
            score_icon = "check"

        descriptor.add_row(
            label="Risk Score",
            value=f"{score}/100",
            style_class=score_style,
            icon=score_icon,
            severity="warning" if score >= 50 else "info",
            verbosity=VerbosityLevel.NORMAL,
        )

        # Severity breakdown
        if result.critical_count > 0:
            descriptor.add_row(
                label="Critical",
                value=result.critical_count,
                style_class="error",
                icon="cross",
                severity="critical",
                verbosity=VerbosityLevel.NORMAL,
            )
        
        if result.high_count > 0:
            descriptor.add_row(
                label="High",
                value=result.high_count,
                style_class="error",
                icon="warning",
                severity="error",
                verbosity=VerbosityLevel.NORMAL,
            )
        
        if result.medium_count > 0:
            descriptor.add_row(
                label="Medium",
                value=result.medium_count,
                style_class="warning",
                icon="warning",
                severity="warning",
                verbosity=VerbosityLevel.NORMAL,
            )
        
        if result.low_count > 0:
            descriptor.add_row(
                label="Low",
                value=result.low_count,
                style_class="info",
                icon="info",
                severity="info",
                verbosity=VerbosityLevel.NORMAL,
            )

        # List vulnerabilities (verbose)
        for vuln in result.vulnerabilities:
            severity_style = {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "info",
                "info": "muted",
            }.get(vuln.severity, "neutral")

            severity_icon = {
                "critical": "cross",
                "high": "warning",
                "medium": "warning",
                "low": "info",
                "info": "info",
            }.get(vuln.severity, "info")

            descriptor.add_row(
                label=vuln.title,
                value=vuln.description,
                style_class=severity_style,
                icon=severity_icon,
                severity=vuln.severity,
                section_name=f"{vuln.category.title()} Vulnerabilities",
                verbosity=VerbosityLevel.VERBOSE,
            )
            
            if vuln.recommendation:
                descriptor.add_row(
                    value=f"  → {vuln.recommendation}",
                    style_class="muted",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
                verbosity=VerbosityLevel.NORMAL,
            )

        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning",
                verbosity=VerbosityLevel.NORMAL,
            )

        return descriptor

    def to_dict(self, result: SecurityVulnsResult) -> dict[str, Any]:
        """Serialize result to JSON-compatible dictionary."""
        return {
            "domain": result.domain,
            "url": result.url,
            "total_vulnerabilities": result.total_vulnerabilities,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "info_count": result.info_count,
            "risk_score": result.risk_score,
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "category": v.category,
                    "title": v.title,
                    "description": v.description,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "evidence": v.evidence,
                    "cwe": v.cwe,
                    "cve": v.cve,
                    "recommendation": v.recommendation,
                    "references": v.references,
                }
                for v in result.vulnerabilities
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }
