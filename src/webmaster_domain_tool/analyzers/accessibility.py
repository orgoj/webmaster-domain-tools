"""Accessibility analyzer for WCAG 2.1 AA compliance.

Performs static HTML analysis to check accessibility features including:
- Alt tags for images
- ARIA labels for interactive elements
- Heading structure (h1-h6 hierarchy)
- Form labels
- Link text descriptiveness
- Language declaration
"""

import logging
import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


class AccessibilityConfig(AnalyzerConfig):
    """Accessibility analyzer configuration."""

    timeout: float = Field(default=15.0, description="HTTP request timeout in seconds")
    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/1.0 Accessibility Checker)",
        description="User agent for HTTP requests",
    )
    wcag_level: str = Field(default="aa", description="WCAG level to check (a, aa, aaa)")
    check_alt_tags: bool = Field(default=True, description="Check images for alt attributes")
    check_aria: bool = Field(default=True, description="Check ARIA attributes")
    check_headings: bool = Field(default=True, description="Check heading structure")
    check_forms: bool = Field(default=True, description="Check form labels")
    check_links: bool = Field(default=True, description="Check link text")
    check_keyboard: bool = Field(default=True, description="Check keyboard accessibility")
    max_links_to_check: int = Field(default=100, description="Maximum links to analyze")
    max_images_to_check: int = Field(default=100, description="Maximum images to analyze")


@dataclass
class AccessibilityIssue:
    """Represents a single accessibility issue."""

    wcag_criterion: str
    level: str
    element: str
    issue: str
    recommendation: str
    severity: str = "error"


@dataclass
class HeadingInfo:
    """Information about a heading element."""

    level: int
    text: str
    position: int


@dataclass
class AccessibilityResult:
    """Results from accessibility analysis."""

    domain: str
    url: str
    success: bool = False
    wcag_level: str = "aa"
    total_issues: int = 0
    error_count: int = 0
    warning_count: int = 0
    issues: list[AccessibilityIssue] = field(default_factory=list)
    accessibility_score: int = 0

    # Images
    images_total: int = 0
    images_with_alt: int = 0
    images_without_alt: int = 0
    images_decorative: int = 0
    image_issues: list[AccessibilityIssue] = field(default_factory=list)

    # Headings
    heading_count: int = 0
    heading_structure: list[HeadingInfo] = field(default_factory=list)
    has_h1: bool = False
    h1_count: int = 0
    heading_issues: list[AccessibilityIssue] = field(default_factory=list)

    # Links
    links_total: int = 0
    links_descriptive: int = 0
    links_generic: int = 0
    links_empty: int = 0
    link_issues: list[AccessibilityIssue] = field(default_factory=list)

    # Forms
    forms_total: int = 0
    form_fields_total: int = 0
    form_fields_with_labels: int = 0
    form_issues: list[AccessibilityIssue] = field(default_factory=list)

    # ARIA & Keyboard
    aria_usage_count: int = 0
    tabindex_usage: int = 0
    keyboard_issues: list[AccessibilityIssue] = field(default_factory=list)

    # Language
    has_lang: bool = False
    lang: str | None = None

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@registry.register
class AccessibilityAnalyzer:
    """Accessibility Analyzer for WCAG 2.1 AA Compliance.

    Performs static HTML analysis to identify accessibility issues.

    Features:
    - Image alt text checking (WCAG 1.1.1)
    - Heading structure analysis (WCAG 1.3.1, 2.4.6)
    - Link text descriptiveness (WCAG 2.4.4)
    - Form label association (WCAG 1.3.1, 4.1.2)
    - Keyboard accessibility hints (WCAG 2.1.1)
    - Language declaration check (WCAG 3.1.1)

    Dependencies:
    - http: Needs HTTP analyzer to determine if site is accessible
    """

    analyzer_id = "accessibility"
    name = "Accessibility Audit"
    description = "WCAG 2.1 AA accessibility compliance checker"
    category = "compliance"
    icon = "accessibility"
    config_class = AccessibilityConfig
    depends_on = ["http"]

    GENERIC_LINK_PATTERNS = [
        r"^click\s*here$", r"^here$", r"^read\s*more$", r"^more$",
        r"^learn\s*more$", r"^continue$", r"^see\s*more$", r"^view\s*more$",
        r"^details$", r"^download$", r"^link$", r"^go$", r"^>>$", r"^>$",
    ]

    def analyze(
        self,
        domain: str,
        config: AccessibilityConfig,
        context: dict[str, object] | None = None,
    ) -> AccessibilityResult:
        """Perform accessibility analysis."""
        url = self._get_url(domain, context)
        result = AccessibilityResult(domain=domain, url=url, wcag_level=config.wcag_level)

        try:
            html_content = self._fetch_html(url, config)
            if not html_content:
                result.errors.append("Failed to fetch HTML content")
                return result

            result.success = True
            soup = BeautifulSoup(html_content, "html5lib")

            self._check_language(soup, result)
            if config.check_alt_tags:
                self._check_images(soup, result, config)
            if config.check_headings:
                self._check_headings(soup, result)
            if config.check_links:
                self._check_links(soup, result, config)
            if config.check_forms:
                self._check_forms(soup, result)
            if config.check_keyboard:
                self._check_keyboard(soup, result)

            self._calculate_score(result)

        except httpx.HTTPError as e:
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            result.errors.append(f"Analysis failed: {e}")

        return result

    def _get_url(self, domain: str, context: dict[str, object] | None) -> str:
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                return http_result.preferred_final_url
        return f"https://{domain}"

    def _fetch_html(self, url: str, config: AccessibilityConfig) -> str | None:
        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True, verify=True) as client:
                response = client.get(url, headers={"User-Agent": config.user_agent})
                response.raise_for_status()
                if "text/html" not in response.headers.get("content-type", "").lower():
                    return None
                return response.text
        except Exception as e:
            logger.error(f"Failed to fetch HTML: {e}")
            return None

    def _check_language(self, soup: BeautifulSoup, result: AccessibilityResult) -> None:
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            result.has_lang = True
            result.lang = html_tag["lang"]
        else:
            result.issues.append(AccessibilityIssue(
                wcag_criterion="3.1.1", level="a", element="<html>",
                issue="Missing lang attribute on HTML element",
                recommendation='Add lang attribute: <html lang="en">',
                severity="error",
            ))
            result.error_count += 1

    def _check_images(self, soup: BeautifulSoup, result: AccessibilityResult, config: AccessibilityConfig) -> None:
        images = soup.find_all("img", limit=config.max_images_to_check)
        result.images_total = len(images)

        for img in images:
            src = img.get("src", "unknown")
            alt = img.get("alt")
            role = img.get("role")
            is_decorative = alt == "" or role in ("presentation", "none")

            if is_decorative:
                result.images_decorative += 1
                result.images_with_alt += 1
            elif alt is not None and alt.strip():
                result.images_with_alt += 1
            elif img.get("aria-label") or img.get("title"):
                result.images_with_alt += 1
            else:
                result.images_without_alt += 1
                result.image_issues.append(AccessibilityIssue(
                    wcag_criterion="1.1.1", level="a",
                    element=f'<img src="{src[:50]}...">',
                    issue="Image missing alt attribute",
                    recommendation='Add descriptive alt text or alt="" for decorative images',
                    severity="error",
                ))
                result.error_count += 1

        result.issues.extend(result.image_issues)
        if result.images_without_alt > 0:
            result.warnings.append(f"{result.images_without_alt}/{result.images_total} images missing alt text")

    def _check_headings(self, soup: BeautifulSoup, result: AccessibilityResult) -> None:
        headings = []
        position = 0
        for level in range(1, 7):
            for h in soup.find_all(f"h{level}"):
                text = h.get_text(strip=True)
                if text:
                    position += 1
                    headings.append(HeadingInfo(level=level, text=text, position=position))

        result.heading_count = len(headings)
        result.heading_structure = headings
        result.h1_count = len([h for h in headings if h.level == 1])
        result.has_h1 = result.h1_count > 0

        if not result.has_h1:
            result.heading_issues.append(AccessibilityIssue(
                wcag_criterion="1.3.1", level="a", element="<body>",
                issue="No H1 heading found on page",
                recommendation="Add exactly one H1 heading as the main page title",
                severity="error",
            ))
            result.error_count += 1

        if result.h1_count > 1:
            result.heading_issues.append(AccessibilityIssue(
                wcag_criterion="1.3.1", level="a", element=f"<h1> (x{result.h1_count})",
                issue=f"Multiple H1 headings found ({result.h1_count})",
                recommendation="Use only one H1 per page",
                severity="warning",
            ))
            result.warning_count += 1

        prev_level = 0
        for h in headings:
            if prev_level > 0 and h.level > prev_level + 1:
                result.heading_issues.append(AccessibilityIssue(
                    wcag_criterion="1.3.1", level="aa", element=f"<h{h.level}>",
                    issue=f"Heading level skipped: h{prev_level} to h{h.level}",
                    recommendation="Follow proper heading hierarchy",
                    severity="warning",
                ))
                result.warning_count += 1
            prev_level = h.level

        result.issues.extend(result.heading_issues)

    def _check_links(self, soup: BeautifulSoup, result: AccessibilityResult, config: AccessibilityConfig) -> None:
        links = soup.find_all("a", href=True, limit=config.max_links_to_check)
        result.links_total = len(links)
        generic_pattern = re.compile("|".join(self.GENERIC_LINK_PATTERNS), re.IGNORECASE)

        for link in links:
            href = link.get("href", "")
            text = link.get_text(strip=True)
            aria_label = link.get("aria-label")
            has_image = link.find("img") is not None

            if not text and not aria_label and not has_image:
                result.links_empty += 1
                result.link_issues.append(AccessibilityIssue(
                    wcag_criterion="2.4.4", level="a",
                    element=f'<a href="{href[:40]}...">',
                    issue="Empty link with no accessible text",
                    recommendation="Add descriptive link text or aria-label",
                    severity="error",
                ))
                result.error_count += 1
            elif text and generic_pattern.match(text.strip()) and not aria_label:
                result.links_generic += 1
                result.link_issues.append(AccessibilityIssue(
                    wcag_criterion="2.4.4", level="a",
                    element=f'<a href="{href[:40]}...">',
                    issue=f"Generic link text: '{text}'",
                    recommendation="Use descriptive link text",
                    severity="warning",
                ))
                result.warning_count += 1
            else:
                result.links_descriptive += 1

        result.issues.extend(result.link_issues)

    def _check_forms(self, soup: BeautifulSoup, result: AccessibilityResult) -> None:
        forms = soup.find_all("form")
        result.forms_total = len(forms)

        form_elements = soup.find_all(["input", "select", "textarea"])
        hidden = soup.find_all("input", attrs={"type": "hidden"})
        buttons = soup.find_all("input", attrs={"type": ["submit", "button", "reset"]})
        visible_fields = [f for f in form_elements if f not in hidden and f not in buttons]

        result.form_fields_total = len(visible_fields)

        labels = soup.find_all("label")
        label_for_ids = {label.get("for") for label in labels if label.get("for")}

        for field in visible_fields:
            field_id = field.get("id")
            field_name = field.get("name", "")
            has_label = field_id in label_for_ids if field_id else False
            has_aria = bool(field.get("aria-label") or field.get("aria-labelledby"))

            if has_label or has_aria:
                result.form_fields_with_labels += 1
            elif field.get("placeholder"):
                result.form_issues.append(AccessibilityIssue(
                    wcag_criterion="1.3.1", level="a",
                    element=f'<{field.name} name="{field_name}">',
                    issue="Form field relies only on placeholder",
                    recommendation="Add a visible label element",
                    severity="warning",
                ))
                result.warning_count += 1
            else:
                result.form_issues.append(AccessibilityIssue(
                    wcag_criterion="1.3.1", level="a",
                    element=f'<{field.name} name="{field_name}">',
                    issue="Form field missing accessible label",
                    recommendation="Add a label element with for attribute",
                    severity="error",
                ))
                result.error_count += 1

        result.issues.extend(result.form_issues)

    def _check_keyboard(self, soup: BeautifulSoup, result: AccessibilityResult) -> None:
        tabindex_elements = soup.find_all(attrs={"tabindex": True})
        result.tabindex_usage = len(tabindex_elements)

        for element in tabindex_elements:
            tabindex = element.get("tabindex")
            try:
                if int(tabindex) > 0:
                    result.keyboard_issues.append(AccessibilityIssue(
                        wcag_criterion="2.4.3", level="a",
                        element=f'<{element.name} tabindex="{tabindex}">',
                        issue="Positive tabindex changes natural tab order",
                        recommendation='Use tabindex="0" instead',
                        severity="warning",
                    ))
                    result.warning_count += 1
            except ValueError:
                pass

        result.issues.extend(result.keyboard_issues)

    def _calculate_score(self, result: AccessibilityResult) -> None:
        score = 100
        score -= result.error_count * 10
        score -= result.warning_count * 3

        if result.has_h1 and result.h1_count == 1:
            score += 5
        if result.images_total > 0 and result.images_with_alt / result.images_total >= 0.9:
            score += 5
        if result.has_lang:
            score += 5

        result.accessibility_score = max(0, min(100, score))
        result.total_issues = result.error_count + result.warning_count

        if result.accessibility_score < 50:
            result.warnings.append(f"Poor accessibility score: {result.accessibility_score}/100")
        elif result.accessibility_score < 75:
            result.warnings.append(f"Accessibility needs improvement: {result.accessibility_score}/100")

    def describe_output(self, result: AccessibilityResult) -> OutputDescriptor:
        descriptor = OutputDescriptor(title=self.name, category=self.category)
        descriptor.quiet_summary = lambda r: f"Accessibility: {result.accessibility_score}/100"

        score_style = "error" if result.accessibility_score < 50 else "warning" if result.accessibility_score < 75 else "success"
        score_icon = "cross" if result.accessibility_score < 50 else "warning" if result.accessibility_score < 75 else "check"

        descriptor.add_row(
            label="Accessibility Score", value=f"{result.accessibility_score}/100",
            style_class=score_style, icon=score_icon,
        )

        if not result.success:
            descriptor.add_row(value="Failed to analyze", style_class="error", severity="error")
            return descriptor

        descriptor.add_row(section_name="Summary", section_type="heading")
        descriptor.add_row(
            label="Issues", value=f"{result.total_issues} ({result.error_count} errors, {result.warning_count} warnings)",
            style_class=score_style,
        )

        # Images
        if result.images_total > 0:
            descriptor.add_row(section_name="Images (WCAG 1.1.1)", section_type="heading")
            img_style = "success" if result.images_without_alt == 0 else "error"
            descriptor.add_row(
                label="Alt Tags", value=f"{result.images_with_alt}/{result.images_total}",
                style_class=img_style,
            )

        # Headings
        if result.heading_count > 0:
            descriptor.add_row(section_name="Headings (WCAG 1.3.1)", section_type="heading")
            h1_style = "success" if result.h1_count == 1 else "warning" if result.has_h1 else "error"
            descriptor.add_row(label="H1 Count", value=str(result.h1_count), style_class=h1_style)

        # Links
        if result.links_total > 0:
            descriptor.add_row(section_name="Links (WCAG 2.4.4)", section_type="heading")
            link_style = "success" if result.links_empty == 0 else "error"
            descriptor.add_row(
                label="Descriptive", value=f"{result.links_descriptive}/{result.links_total}",
                style_class=link_style,
            )

        # Forms
        if result.form_fields_total > 0:
            descriptor.add_row(section_name="Forms (WCAG 1.3.1)", section_type="heading")
            form_style = "success" if result.form_fields_with_labels == result.form_fields_total else "warning"
            descriptor.add_row(
                label="Labels", value=f"{result.form_fields_with_labels}/{result.form_fields_total}",
                style_class=form_style,
            )

        # Language
        descriptor.add_row(section_name="Language (WCAG 3.1.1)", section_type="heading", verbosity=VerbosityLevel.VERBOSE)
        lang_style = "success" if result.has_lang else "error"
        descriptor.add_row(
            label="Lang", value=result.lang if result.has_lang else "Missing",
            style_class=lang_style, verbosity=VerbosityLevel.VERBOSE,
        )

        # Issues
        if result.issues:
            descriptor.add_row(section_name="Issues", section_type="heading")
            for issue in result.issues[:15]:
                sev_style = "error" if issue.severity == "error" else "warning"
                icon = "cross" if issue.severity == "error" else "warning"
                descriptor.add_row(
                    value=f"[{issue.wcag_criterion}] {issue.issue}",
                    section_type="text", style_class=sev_style, icon=icon,
                )

        for w in result.warnings:
            descriptor.add_row(value=w, section_type="text", style_class="warning", icon="warning")
        for e in result.errors:
            descriptor.add_row(value=e, section_type="text", style_class="error", icon="cross")

        return descriptor

    def to_dict(self, result: AccessibilityResult) -> dict:
        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "wcag_level": result.wcag_level,
            "accessibility_score": result.accessibility_score,
            "summary": {
                "total_issues": result.total_issues,
                "error_count": result.error_count,
                "warning_count": result.warning_count,
            },
            "images": {
                "total": result.images_total,
                "with_alt": result.images_with_alt,
                "without_alt": result.images_without_alt,
                "decorative": result.images_decorative,
            },
            "headings": {
                "count": result.heading_count,
                "has_h1": result.has_h1,
                "h1_count": result.h1_count,
                "structure": [{"level": h.level, "text": h.text} for h in result.heading_structure],
            },
            "links": {
                "total": result.links_total,
                "descriptive": result.links_descriptive,
                "generic": result.links_generic,
                "empty": result.links_empty,
            },
            "forms": {
                "total": result.forms_total,
                "fields_total": result.form_fields_total,
                "fields_with_labels": result.form_fields_with_labels,
            },
            "language": {
                "has_lang": result.has_lang,
                "lang": result.lang,
            },
            "issues": [
                {
                    "wcag": i.wcag_criterion,
                    "level": i.level,
                    "element": i.element,
                    "issue": i.issue,
                    "recommendation": i.recommendation,
                    "severity": i.severity,
                }
                for i in result.issues
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }
