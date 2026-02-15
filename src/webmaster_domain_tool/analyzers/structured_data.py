"""Structured Data validator for Schema.org markup.

Analyzes and validates structured data in HTML pages:
- JSON-LD (JavaScript Object Notation for Linked Data)
- Microdata (itemscope, itemtype, itemprop)
- RDFa (Resource Description Framework in Attributes)

Validates against Google's structured data guidelines and checks:
- Required fields presence
- Field types correctness
- Enum values validity
- Multiple values for repeated fields
- Duplicate @id detection
- Malformed JSON in JSON-LD
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx
from bs4 import BeautifulSoup
from pydantic import Field

from ..core.registry import registry
from .protocol import AnalyzerConfig, OutputDescriptor, VerbosityLevel

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================


class StructuredDataConfig(AnalyzerConfig):
    """Structured Data analyzer configuration."""

    timeout: float = Field(default=15.0, description="HTTP request timeout in seconds")
    user_agent: str = Field(
        default="Mozilla/5.0 (compatible; WebmasterDomainTool/1.0 StructuredData Validator)",
        description="User agent for HTTP requests",
    )
    check_jsonld: bool = Field(default=True, description="Check JSON-LD structured data")
    check_microdata: bool = Field(default=True, description="Check Microdata markup")
    check_rdfa: bool = Field(default=True, description="Check RDFa markup")
    max_blocks: int = Field(default=50, description="Maximum structured data blocks to analyze")


# =============================================================================
# Schema Definitions for Common Types
# =============================================================================

# Required and recommended fields for common schema.org types
SCHEMA_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "WebSite": {
        "required": ["name"],
        "recommended": ["url", "potentialAction"],
        "fields": {
            "name": {"type": "Text", "description": "Site name"},
            "url": {"type": "URL", "description": "Site URL"},
            "potentialAction": {"type": "SearchAction", "description": "Search action"},
        },
    },
    "Organization": {
        "required": ["name"],
        "recommended": ["url", "logo", "contactPoint"],
        "fields": {
            "name": {"type": "Text", "description": "Organization name"},
            "url": {"type": "URL", "description": "Organization URL"},
            "logo": {"type": "URL", "description": "Logo URL"},
            "contactPoint": {"type": "ContactPoint", "description": "Contact information"},
        },
    },
    "Article": {
        "required": ["headline", "author", "datePublished"],
        "recommended": ["image", "publisher", "dateModified"],
        "fields": {
            "headline": {"type": "Text", "description": "Article headline"},
            "author": {"type": "Person|Organization", "description": "Author"},
            "datePublished": {"type": "Date", "description": "Publication date (ISO 8601)"},
            "dateModified": {"type": "Date", "description": "Modification date (ISO 8601)"},
            "image": {"type": "URL|ImageObject", "description": "Article image"},
            "publisher": {"type": "Organization", "description": "Publisher"},
        },
    },
    "BlogPosting": {
        "required": ["headline", "author", "datePublished"],
        "recommended": ["image", "publisher", "dateModified"],
        "fields": {
            "headline": {"type": "Text", "description": "Blog post headline"},
            "author": {"type": "Person|Organization", "description": "Author"},
            "datePublished": {"type": "Date", "description": "Publication date (ISO 8601)"},
            "image": {"type": "URL|ImageObject", "description": "Featured image"},
        },
    },
    "Product": {
        "required": ["name"],
        "recommended": ["image", "description", "offers", "brand"],
        "fields": {
            "name": {"type": "Text", "description": "Product name"},
            "image": {"type": "URL", "description": "Product image URL"},
            "description": {"type": "Text", "description": "Product description"},
            "brand": {"type": "Brand|Text", "description": "Product brand"},
            "sku": {"type": "Text", "description": "Stock Keeping Unit"},
            "offers": {"type": "Offer", "description": "Offer details"},
        },
    },
    "Offer": {
        "required": ["price", "priceCurrency"],
        "recommended": ["availability", "url"],
        "fields": {
            "price": {"type": "Number", "description": "Price value"},
            "priceCurrency": {"type": "Text", "description": "Currency code (ISO 4217)"},
            "availability": {"type": "ItemAvailability", "description": "Stock status"},
            "url": {"type": "URL", "description": "Offer URL"},
            "priceValidUntil": {"type": "Date", "description": "Price validity date"},
        },
    },
    "Review": {
        "required": ["itemReviewed", "reviewRating"],
        "recommended": ["author", "datePublished"],
        "fields": {
            "itemReviewed": {"type": "Thing", "description": "Reviewed item"},
            "reviewRating": {"type": "Rating", "description": "Rating given"},
            "author": {"type": "Person|Organization", "description": "Reviewer"},
            "datePublished": {"type": "Date", "description": "Review date"},
        },
    },
    "Rating": {
        "required": ["ratingValue"],
        "recommended": ["bestRating", "worstRating"],
        "fields": {
            "ratingValue": {"type": "Number|Text", "description": "Rating value"},
            "bestRating": {"type": "Number", "description": "Maximum rating"},
            "worstRating": {"type": "Number", "description": "Minimum rating"},
        },
    },
    "BreadcrumbList": {
        "required": ["itemListElement"],
        "recommended": [],
        "fields": {
            "itemListElement": {"type": "ListItem", "description": "Breadcrumb items"},
        },
    },
    "LocalBusiness": {
        "required": ["name", "address"],
        "recommended": ["telephone", "openingHours", "geo"],
        "fields": {
            "name": {"type": "Text", "description": "Business name"},
            "address": {"type": "PostalAddress", "description": "Business address"},
            "telephone": {"type": "Text", "description": "Phone number"},
            "openingHours": {"type": "Text", "description": "Opening hours"},
            "geo": {"type": "GeoCoordinates", "description": "Geographic coordinates"},
        },
    },
    "FAQPage": {
        "required": ["mainEntity"],
        "recommended": [],
        "fields": {
            "mainEntity": {"type": "Question", "description": "FAQ questions"},
        },
    },
    "QAPage": {
        "required": ["mainEntity"],
        "recommended": [],
        "fields": {
            "mainEntity": {"type": "Question", "description": "Question with answers"},
        },
    },
    "Question": {
        "required": ["name", "acceptedAnswer"],
        "recommended": ["author", "dateCreated"],
        "fields": {
            "name": {"type": "Text", "description": "Question text"},
            "acceptedAnswer": {"type": "Answer", "description": "Accepted answer"},
            "author": {"type": "Person", "description": "Question author"},
        },
    },
    "HowTo": {
        "required": ["name", "step"],
        "recommended": ["totalTime", "estimatedCost", "supply", "tool"],
        "fields": {
            "name": {"type": "Text", "description": "How-to name"},
            "step": {"type": "HowToStep", "description": "Steps"},
            "totalTime": {"type": "Duration", "description": "Total time"},
        },
    },
    "Recipe": {
        "required": ["name", "recipeIngredient", "recipeInstructions"],
        "recommended": ["cookTime", "prepTime", "totalTime", "image", "author"],
        "fields": {
            "name": {"type": "Text", "description": "Recipe name"},
            "recipeIngredient": {"type": "Text", "description": "Ingredients"},
            "recipeInstructions": {"type": "Text|HowToStep", "description": "Instructions"},
            "cookTime": {"type": "Duration", "description": "Cooking time"},
        },
    },
    "Event": {
        "required": ["name", "startDate", "location"],
        "recommended": ["endDate", "image", "description"],
        "fields": {
            "name": {"type": "Text", "description": "Event name"},
            "startDate": {"type": "Date|DateTime", "description": "Start date/time"},
            "location": {"type": "Place", "description": "Event location"},
            "endDate": {"type": "Date|DateTime", "description": "End date/time"},
        },
    },
    "Person": {
        "required": ["name"],
        "recommended": ["url", "image", "jobTitle"],
        "fields": {
            "name": {"type": "Text", "description": "Person name"},
            "url": {"type": "URL", "description": "Person URL"},
            "image": {"type": "URL|ImageObject", "description": "Person image"},
            "jobTitle": {"type": "Text", "description": "Job title"},
        },
    },
    "PostalAddress": {
        "required": ["streetAddress", "addressLocality", "addressCountry"],
        "recommended": ["postalCode", "addressRegion"],
        "fields": {
            "streetAddress": {"type": "Text", "description": "Street address"},
            "addressLocality": {"type": "Text", "description": "City"},
            "addressCountry": {"type": "Text|Country", "description": "Country"},
            "postalCode": {"type": "Text", "description": "Postal code"},
        },
    },
}

# Enum values for specific properties
ENUM_VALUES: dict[str, list[str]] = {
    "availability": [
        "http://schema.org/InStock",
        "http://schema.org/OutOfStock",
        "http://schema.org/PreOrder",
        "http://schema.org/SoldOut",
        "http://schema.org/LimitedAvailability",
        "http://schema.org/OnlineOnly",
        "http://schema.org/InStoreOnly",
        "http://schema.org/Discontinued",
        "InStock",
        "OutOfStock",
        "PreOrder",
        "SoldOut",
        "LimitedAvailability",
        "OnlineOnly",
        "InStoreOnly",
        "Discontinued",
    ],
    "availabilityEnum": [
        "InStock",
        "OutOfStock",
        "PreOrder",
        "SoldOut",
        "LimitedAvailability",
        "OnlineOnly",
        "InStoreOnly",
        "Discontinued",
    ],
}

# ISO 8601 date/datetime pattern
ISO_8601_PATTERN = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?:Z|[+-](?:[01]\d|2[0-3]):?[0-5]\d)?)?$"
)


# =============================================================================
# Result Models
# =============================================================================


@dataclass
class ValidationIssue:
    """Represents a validation issue found in structured data."""

    schema_type: str
    field: str
    issue: str
    severity: str  # error, warning, info
    suggestion: str | None = None
    block_index: int = 0


@dataclass
class StructuredDataBlock:
    """Represents a single structured data block."""

    format: str  # json-ld, microdata, rdfa
    schema_type: str
    content: dict[str, Any]
    is_valid: bool = True
    issues: list[ValidationIssue] = field(default_factory=list)
    index: int = 0


@dataclass
class StructuredDataResult:
    """Results from structured data analysis."""

    domain: str
    url: str = ""
    success: bool = False
    has_structured_data: bool = False

    # Block counts
    total_blocks: int = 0
    valid_blocks: int = 0
    invalid_blocks: int = 0
    jsonld_blocks: int = 0
    microdata_blocks: int = 0
    rdfa_blocks: int = 0

    # All blocks found
    blocks: list[StructuredDataBlock] = field(default_factory=list)

    # Issues summary
    total_issues: int = 0
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0

    # Schema types found
    schema_types_found: list[str] = field(default_factory=list)
    duplicate_ids: list[str] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# =============================================================================
# Analyzer Implementation
# =============================================================================


@registry.register
class StructuredDataAnalyzer:
    """
    Structured Data Analyzer for Schema.org Markup Validation.

    Extracts and validates structured data from HTML pages:
    - JSON-LD: <script type="application/ld+json"> blocks
    - Microdata: itemscope, itemtype, itemprop attributes
    - RDFa: typeof, property attributes

    Validates against Google's structured data guidelines:
    - Required fields present
    - Field types correct
    - Enum values valid
    - Duplicate @id detection
    - Malformed JSON detection

    Supports common schema.org types:
    - WebSite, Organization, Article, BlogPosting
    - Product, Offer, Review, Rating
    - BreadcrumbList, LocalBusiness
    - FAQPage, QAPage, HowTo, Recipe, Event

    Dependencies:
    - http: Needs HTTP analyzer to determine if site is accessible
    """

    # ========================================================================
    # Required Metadata
    # ========================================================================

    analyzer_id = "structured-data"
    name = "Structured Data"
    description = "Schema.org structured data validator (JSON-LD, Microdata, RDFa)"
    category = "seo"
    icon = "code"
    config_class = StructuredDataConfig
    depends_on = ["http"]

    # ========================================================================
    # Protocol Methods
    # ========================================================================

    def analyze(
        self,
        domain: str,
        config: StructuredDataConfig,
        context: dict[str, object] | None = None,
    ) -> StructuredDataResult:
        """
        Analyze structured data on a web page.

        Args:
            domain: Domain to analyze
            config: Structured data analyzer configuration
            context: Context from previous analyzers

        Returns:
            StructuredDataResult with analysis data
        """
        url = self._get_url(domain, context)
        result = StructuredDataResult(domain=domain, url=url)

        try:
            html_content = self._fetch_html(url, config)
            if not html_content:
                result.errors.append("Failed to fetch HTML content")
                return result

            result.success = True
            soup = BeautifulSoup(html_content, "html5lib")

            # Extract structured data
            all_ids: list[str] = []

            if config.check_jsonld:
                self._extract_jsonld(soup, result, all_ids, config)

            if config.check_microdata:
                self._extract_microdata(soup, result, all_ids, config)

            if config.check_rdfa:
                self._extract_rdfa(soup, result, all_ids, config)

            # Check for duplicate IDs
            self._check_duplicate_ids(all_ids, result)

            # Calculate summary
            self._calculate_summary(result)

        except httpx.HTTPError as e:
            result.errors.append(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Structured data analysis failed for {domain}: {e}", exc_info=True)
            result.errors.append(f"Analysis failed: {e}")

        return result

    def _get_url(self, domain: str, context: dict[str, object] | None) -> str:
        """Get URL to analyze from context or fallback."""
        if context and "http" in context:
            http_result = context["http"]
            if hasattr(http_result, "preferred_final_url") and http_result.preferred_final_url:
                return http_result.preferred_final_url
        return f"https://{domain}"

    def _fetch_html(self, url: str, config: StructuredDataConfig) -> str | None:
        """Fetch HTML content from URL."""
        try:
            with httpx.Client(timeout=config.timeout, follow_redirects=True, verify=True) as client:
                response = client.get(url, headers={"User-Agent": config.user_agent})
                response.raise_for_status()
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" not in content_type:
                    return None
                return response.text
        except Exception as e:
            logger.error(f"Failed to fetch HTML: {e}")
            return None

    def _extract_jsonld(
        self,
        soup: BeautifulSoup,
        result: StructuredDataResult,
        all_ids: list[str],
        config: StructuredDataConfig,
    ) -> None:
        """Extract and validate JSON-LD blocks."""
        scripts = soup.find_all("script", type="application/ld+json")

        for index, script in enumerate(scripts):
            if index >= config.max_blocks:
                result.warnings.append(f"Reached max JSON-LD blocks limit ({config.max_blocks})")
                break

            block = StructuredDataBlock(
                format="json-ld",
                schema_type="Unknown",
                content={},
                index=len(result.blocks),
            )

            try:
                data = json.loads(script.string or "{}")
                
                # Handle @graph (multiple entities in one script)
                if "@graph" in data:
                    for item in data["@graph"]:
                        self._process_jsonld_item(item, block, all_ids, result)
                else:
                    self._process_jsonld_item(data, block, all_ids, result)

            except json.JSONDecodeError as e:
                block.is_valid = False
                block.issues.append(ValidationIssue(
                    schema_type="JSON-LD",
                    field="",
                    issue=f"Malformed JSON: {e.msg}",
                    severity="error",
                    suggestion="Fix JSON syntax errors",
                ))
                result.error_count += 1

            result.blocks.append(block)
            result.jsonld_blocks += 1

    def _process_jsonld_item(
        self,
        data: dict[str, Any],
        block: StructuredDataBlock,
        all_ids: list[str],
        result: StructuredDataResult,
    ) -> None:
        """Process a single JSON-LD item."""
        schema_type = data.get("@type", "Unknown")
        if isinstance(schema_type, list):
            schema_type = schema_type[0] if schema_type else "Unknown"
        
        block.schema_type = schema_type
        block.content = data

        # Collect @id
        if "@id" in data:
            all_ids.append(str(data["@id"]))

        # Validate context
        context = data.get("@context", "")
        if context and not str(context).startswith("https://schema.org"):
            block.issues.append(ValidationIssue(
                schema_type=schema_type,
                field="@context",
                issue=f"Non-standard context: {context}",
                severity="warning",
                suggestion="Use https://schema.org for best compatibility",
            ))

        # Validate against schema requirements
        self._validate_schema(data, schema_type, block, result)

    def _extract_microdata(
        self,
        soup: BeautifulSoup,
        result: StructuredDataResult,
        all_ids: list[str],
        config: StructuredDataConfig,
    ) -> None:
        """Extract and validate Microdata."""
        itemscope_elements = soup.find_all(itemscope=True)

        for index, element in enumerate(itemscope_elements):
            if index >= config.max_blocks:
                result.warnings.append(f"Reached max Microdata blocks limit ({config.max_blocks})")
                break

            itemtype = element.get("itemtype", "")
            schema_type = "Unknown"
            
            if itemtype:
                # Extract type from URL (e.g., https://schema.org/Product -> Product)
                schema_type = itemtype.split("/")[-1] if "/" in str(itemtype) else str(itemtype)

            block = StructuredDataBlock(
                format="microdata",
                schema_type=schema_type,
                content={"itemtype": itemtype},
                index=len(result.blocks),
            )

            # Extract properties
            properties = {}
            for prop_element in element.find_all(itemprop=True):
                prop_name = prop_element.get("itemprop", "")
                prop_value = prop_element.get("content") or prop_element.get_text(strip=True)
                if prop_name:
                    properties[prop_name] = prop_value

            block.content.update(properties)

            # Validate
            self._validate_schema(block.content, schema_type, block, result)

            result.blocks.append(block)
            result.microdata_blocks += 1

    def _extract_rdfa(
        self,
        soup: BeautifulSoup,
        result: StructuredDataResult,
        all_ids: list[str],
        config: StructuredDataConfig,
    ) -> None:
        """Extract and validate RDFa."""
        typeof_elements = soup.find_all(typeof=True)

        for index, element in enumerate(typeof_elements):
            if index >= config.max_blocks:
                result.warnings.append(f"Reached max RDFa blocks limit ({config.max_blocks})")
                break

            typeof = element.get("typeof", "")
            schema_type = str(typeof).split(":")[-1] if typeof else "Unknown"

            block = StructuredDataBlock(
                format="rdfa",
                schema_type=schema_type,
                content={"typeof": typeof},
                index=len(result.blocks),
            )

            # Extract properties
            properties = {}
            for prop_element in element.find_all(property=True):
                prop_name = prop_element.get("property", "")
                prop_value = prop_element.get("content") or prop_element.get("resource") or prop_element.get_text(strip=True)
                if prop_name:
                    properties[prop_name] = prop_value

            block.content.update(properties)

            # Validate
            self._validate_schema(block.content, schema_type, block, result)

            result.blocks.append(block)
            result.rdfa_blocks += 1

    def _validate_schema(
        self,
        data: dict[str, Any],
        schema_type: str,
        block: StructuredDataBlock,
        result: StructuredDataResult,
    ) -> None:
        """Validate data against schema requirements."""
        requirements = SCHEMA_REQUIREMENTS.get(schema_type)
        
        if not requirements:
            # Unknown schema type - info only
            block.issues.append(ValidationIssue(
                schema_type=schema_type,
                field="",
                issue=f"Unknown or unsupported schema type: {schema_type}",
                severity="info",
                suggestion="Consider using a well-known schema type",
            ))
            result.info_count += 1
            return

        # Check required fields
        for field_name in requirements.get("required", []):
            if field_name not in data or not data[field_name]:
                block.is_valid = False
                block.issues.append(ValidationIssue(
                    schema_type=schema_type,
                    field=field_name,
                    issue=f"Missing required field: '{field_name}'",
                    severity="error",
                    suggestion=f"Add the '{field_name}' field",
                    block_index=block.index,
                ))
                result.error_count += 1

        # Check recommended fields
        for field_name in requirements.get("recommended", []):
            if field_name not in data or not data[field_name]:
                block.issues.append(ValidationIssue(
                    schema_type=schema_type,
                    field=field_name,
                    issue=f"Missing recommended field: '{field_name}'",
                    severity="warning",
                    suggestion=f"Consider adding the '{field_name}' field for better SEO",
                    block_index=block.index,
                ))
                result.warning_count += 1

        # Validate field types and values
        field_defs = requirements.get("fields", {})
        for field_name, value in data.items():
            if field_name.startswith("@"):
                continue  # Skip JSON-LD keywords

            field_def = field_defs.get(field_name)
            if field_def:
                self._validate_field_value(schema_type, field_name, value, field_def, block, result)

    def _validate_field_value(
        self,
        schema_type: str,
        field_name: str,
        value: Any,
        field_def: dict[str, Any],
        block: StructuredDataBlock,
        result: StructuredDataResult,
    ) -> None:
        """Validate a field value against its definition."""
        expected_type = field_def.get("type", "")

        # Check enum values
        if field_name.lower() in ENUM_VALUES or field_name in ENUM_VALUES:
            enum_key = field_name.lower() if field_name.lower() in ENUM_VALUES else field_name
            allowed_values = ENUM_VALUES[enum_key]
            str_value = str(value).strip()
            
            if str_value not in allowed_values:
                block.issues.append(ValidationIssue(
                    schema_type=schema_type,
                    field=field_name,
                    issue=f"Invalid enum value: '{str_value}'",
                    severity="warning",
                    suggestion=f"Use one of: {', '.join(allowed_values[:5])}...",
                ))
                result.warning_count += 1

        # Type-specific validations
        if "Date" in expected_type:
            if isinstance(value, str) and not ISO_8601_PATTERN.match(value):
                block.issues.append(ValidationIssue(
                    schema_type=schema_type,
                    field=field_name,
                    issue=f"Invalid date format: '{value}'",
                    severity="warning",
                    suggestion="Use ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)",
                ))
                result.warning_count += 1

        elif "Number" in expected_type:
            if isinstance(value, str):
                try:
                    float(value)
                except ValueError:
                    block.issues.append(ValidationIssue(
                        schema_type=schema_type,
                        field=field_name,
                        issue=f"Expected Number, got String: '{value}'",
                        severity="warning",
                        suggestion="Use numeric value without quotes",
                    ))
                    result.warning_count += 1
            elif not isinstance(value, (int, float)):
                block.issues.append(ValidationIssue(
                    schema_type=schema_type,
                    field=field_name,
                    issue=f"Expected Number, got {type(value).__name__}",
                    severity="warning",
                ))
                result.warning_count += 1

        elif "URL" in expected_type:
            if isinstance(value, str):
                if not value.startswith(("http://", "https://", "/")):
                    block.issues.append(ValidationIssue(
                        schema_type=schema_type,
                        field=field_name,
                        issue=f"Invalid URL format: '{value}'",
                        severity="warning",
                        suggestion="Use absolute URL (https://...) or relative path (/...)",
                    ))
                    result.warning_count += 1

    def _check_duplicate_ids(self, all_ids: list[str], result: StructuredDataResult) -> None:
        """Check for duplicate @id values."""
        seen: set[str] = set()
        for id_value in all_ids:
            if id_value in seen:
                result.duplicate_ids.append(id_value)
                result.warning_count += 1
            else:
                seen.add(id_value)

        if result.duplicate_ids:
            result.warnings.append(f"Duplicate @id values found: {', '.join(result.duplicate_ids[:3])}")

    def _calculate_summary(self, result: StructuredDataResult) -> None:
        """Calculate summary statistics."""
        result.total_blocks = len(result.blocks)
        result.valid_blocks = sum(1 for b in result.blocks if b.is_valid)
        result.invalid_blocks = result.total_blocks - result.valid_blocks
        result.total_issues = result.error_count + result.warning_count + result.info_count
        result.has_structured_data = result.total_blocks > 0
        
        # Unique schema types
        result.schema_types_found = list({b.schema_type for b in result.blocks if b.schema_type != "Unknown"})

        # Overall success
        if result.has_structured_data and result.invalid_blocks == 0:
            result.success = True

    def describe_output(self, result: StructuredDataResult) -> OutputDescriptor:
        """Describe how to render structured data results."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        if not result.has_structured_data:
            descriptor.quiet_summary = lambda r: "Structured Data: None found"
        elif result.invalid_blocks > 0:
            descriptor.quiet_summary = lambda r: f"Structured Data: {result.invalid_blocks} invalid"
        else:
            descriptor.quiet_summary = lambda r: f"Structured Data: {result.valid_blocks} valid"

        if not result.success and not result.has_structured_data:
            descriptor.add_row(
                value="No structured data found on this page",
                style_class="warning",
                icon="warning",
            )
            return descriptor

        # Summary header
        descriptor.add_row(
            section_name="Summary",
            section_type="heading",
        )

        status_style = "success" if result.invalid_blocks == 0 else "error"
        status_icon = "check" if result.invalid_blocks == 0 else "cross"
        descriptor.add_row(
            label="Total Blocks",
            value=str(result.total_blocks),
            style_class=status_style,
            icon=status_icon,
        )

        descriptor.add_row(
            label="Valid",
            value=str(result.valid_blocks),
            style_class="success" if result.valid_blocks > 0 else "muted",
        )

        if result.invalid_blocks > 0:
            descriptor.add_row(
                label="Invalid",
                value=str(result.invalid_blocks),
                style_class="error",
            )

        if result.warning_count > 0:
            descriptor.add_row(
                label="Warnings",
                value=str(result.warning_count),
                style_class="warning",
            )

        # Format breakdown
        descriptor.add_row(
            section_name="Formats Found",
            section_type="heading",
        )

        if result.jsonld_blocks > 0:
            descriptor.add_row(
                label="JSON-LD",
                value=f"{result.jsonld_blocks} block(s)",
                style_class="info",
            )

        if result.microdata_blocks > 0:
            descriptor.add_row(
                label="Microdata",
                value=f"{result.microdata_blocks} block(s)",
                style_class="info",
            )

        if result.rdfa_blocks > 0:
            descriptor.add_row(
                label="RDFa",
                value=f"{result.rdfa_blocks} block(s)",
                style_class="info",
            )

        # Schema types found
        if result.schema_types_found:
            descriptor.add_row(
                section_name="Schema Types",
                section_type="heading",
            )
            for schema_type in result.schema_types_found[:10]:
                count = sum(1 for b in result.blocks if b.schema_type == schema_type)
                descriptor.add_row(
                    label=schema_type,
                    value=f"{count} instance(s)",
                    style_class="neutral",
                )

        # Issues
        all_issues: list[ValidationIssue] = []
        for block in result.blocks:
            all_issues.extend(block.issues)

        if all_issues:
            descriptor.add_row(
                section_name="Issues Found",
                section_type="heading",
            )

            # Sort by severity
            severity_order = {"error": 0, "warning": 1, "info": 2}
            all_issues.sort(key=lambda x: severity_order.get(x.severity, 3))

            for issue in all_issues[:20]:  # Limit to 20 issues
                severity_style = {
                    "error": "error",
                    "warning": "warning",
                    "info": "info",
                }.get(issue.severity, "neutral")

                severity_icon = {
                    "error": "cross",
                    "warning": "warning",
                    "info": "info",
                }.get(issue.severity, "info")

                issue_text = f"[{issue.schema_type}] "
                if issue.field:
                    issue_text += f"{issue.field}: "
                issue_text += issue.issue

                descriptor.add_row(
                    value=issue_text,
                    section_type="text",
                    style_class=severity_style,
                    icon=severity_icon,
                    severity=issue.severity,
                )

            if len(all_issues) > 20:
                descriptor.add_row(
                    value=f"... and {len(all_issues) - 20} more issues",
                    style_class="muted",
                )

        # Detailed blocks (Verbose mode)
        if result.blocks:
            descriptor.add_row(
                section_name="Block Details",
                section_type="heading",
                verbosity=VerbosityLevel.VERBOSE,
            )

            for block in result.blocks[:10]:
                status = "✓" if block.is_valid else "✗"
                descriptor.add_row(
                    label=f"{status} {block.format.upper()}",
                    value=block.schema_type,
                    style_class="success" if block.is_valid else "error",
                    verbosity=VerbosityLevel.VERBOSE,
                )

        # Debug info
        descriptor.add_row(
            section_name="Debug Info",
            section_type="heading",
            verbosity=VerbosityLevel.DEBUG,
        )
        descriptor.add_row(
            label="URL Analyzed",
            value=result.url,
            verbosity=VerbosityLevel.DEBUG,
        )
        descriptor.add_row(
            label="Total Issues",
            value=f"{result.total_issues} (errors: {result.error_count}, warnings: {result.warning_count})",
            verbosity=VerbosityLevel.DEBUG,
        )

        # Errors and warnings
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross",
            )

        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning",
            )

        return descriptor

    def to_dict(self, result: StructuredDataResult) -> dict:
        """Serialize result to JSON-compatible dictionary."""
        return {
            "domain": result.domain,
            "url": result.url,
            "success": result.success,
            "has_structured_data": result.has_structured_data,
            "summary": {
                "total_blocks": result.total_blocks,
                "valid_blocks": result.valid_blocks,
                "invalid_blocks": result.invalid_blocks,
                "jsonld_blocks": result.jsonld_blocks,
                "microdata_blocks": result.microdata_blocks,
                "rdfa_blocks": result.rdfa_blocks,
                "error_count": result.error_count,
                "warning_count": result.warning_count,
                "info_count": result.info_count,
            },
            "schema_types_found": result.schema_types_found,
            "duplicate_ids": result.duplicate_ids,
            "blocks": [
                {
                    "format": block.format,
                    "schema_type": block.schema_type,
                    "is_valid": block.is_valid,
                    "issues": [
                        {
                            "schema_type": issue.schema_type,
                            "field": issue.field,
                            "issue": issue.issue,
                            "severity": issue.severity,
                            "suggestion": issue.suggestion,
                        }
                        for issue in block.issues
                    ],
                    "content": block.content if len(str(block.content)) < 1000 else "(truncated)",
                }
                for block in result.blocks
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }
