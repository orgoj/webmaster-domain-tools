# Structured Data Analyzer

Analyzes and validates Schema.org structured data markup on web pages for SEO and Google rich results compliance.

## Overview

The Structured Data Analyzer extracts and validates structured data from HTML pages in three formats:

1. **JSON-LD** (JavaScript Object Notation for Linked Data) - Google's recommended format
2. **Microdata** - HTML5 extension using `itemscope`, `itemtype`, `itemprop` attributes
3. **RDFa** (Resource Description Framework in Attributes) - Using `typeof`, `property` attributes

## Supported Schema Types

The analyzer validates against Google's structured data guidelines for these common types:

### Organization & Website
- `WebSite` - Website information with search action
- `Organization` - Business or organization details
- `Person` - Individual person information

### Content
- `Article` - News article or blog post
- `BlogPosting` - Blog post with author and dates
- `Recipe` - Recipe with ingredients and instructions
- `HowTo` - Step-by-step instructions
- `FAQPage` - Frequently Asked Questions page
- `QAPage` - Question and Answer page

### E-commerce
- `Product` - Product information
- `Offer` - Pricing and availability
- `Review` - Product or service review
- `Rating` - Numerical rating

### Local Business
- `LocalBusiness` - Physical business location
- `PostalAddress` - Mailing address
- `GeoCoordinates` - Geographic coordinates

### Navigation
- `BreadcrumbList` - Site navigation breadcrumbs

### Events
- `Event` - Event with date, time, and location

## Validation Checks

### Required Fields

Checks that all required fields are present for each schema type. For example:

- `Product` requires `name`
- `Article` requires `headline`, `author`, `datePublished`
- `Offer` requires `price`, `priceCurrency`
- `LocalBusiness` requires `name`, `address`

### Recommended Fields

Warns about missing recommended fields that improve rich result eligibility:

- `Product` recommends `image`, `description`, `offers`, `brand`
- `Article` recommends `image`, `publisher`, `dateModified`

### Field Type Validation

Validates that fields have correct types:

- **URL** - Must be valid absolute URL or relative path
- **Number** - Must be numeric (not string)
- **Date** - Must be ISO 8601 format (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`)
- **Enum** - Must be one of allowed values

### Enum Values

Validates enum properties against allowed values:

```json
"availability": [
  "http://schema.org/InStock",
  "http://schema.org/OutOfStock",
  "http://schema.org/PreOrder",
  "http://schema.org/SoldOut",
  "LimitedAvailability",
  "OnlineOnly",
  "InStoreOnly",
  "Discontinued"
]
```

### Duplicate @id Detection

Warns about duplicate `@id` values across JSON-LD blocks, which can cause conflicts in knowledge graphs.

### Malformed JSON Detection

Detects and reports JSON syntax errors in JSON-LD blocks.

## Configuration

```toml
[structured-data]
enabled = true
timeout = 15.0
user_agent = "Mozilla/5.0 (compatible; WebmasterDomainTool/1.0 StructuredData Validator)"
check_jsonld = true
check_microdata = true
check_rdfa = true
max_blocks = 50
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable the analyzer |
| `timeout` | float | `15.0` | HTTP request timeout in seconds |
| `user_agent` | string | `"Mozilla/5.0..."` | User agent for HTTP requests |
| `check_jsonld` | bool | `true` | Check JSON-LD format |
| `check_microdata` | bool | `true` | Check Microdata format |
| `check_rdfa` | bool | `true` | Check RDFa format |
| `max_blocks` | int | `50` | Maximum blocks to analyze |

## Output Example

### Normal Verbosity

```
Structured Data
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Summary
─────────────────────────────────────
  Total Blocks      3
  Valid             2
  Invalid           1
  Warnings          4

Formats Found
─────────────────────────────────────
  JSON-LD           1 block(s)
  Microdata         2 block(s)

Schema Types
─────────────────────────────────────
  Organization      1 instance(s)
  Product           1 instance(s)
  BreadcrumbList    1 instance(s)

Issues Found
─────────────────────────────────────
  ✗ [Organization] url: Missing required field: 'url'
  ⚠ [Product] description: Missing recommended field: 'description'
  ⚠ [Article] datePublished: Invalid date format: '2024-01-15'
  ⚠ [Offer] price: Expected Number, got String: '99.99'
```

### Quiet Mode Summary

```
Structured Data: 2 valid
```

### JSON Output

```json
{
  "domain": "example.com",
  "url": "https://example.com",
  "success": true,
  "has_structured_data": true,
  "summary": {
    "total_blocks": 3,
    "valid_blocks": 2,
    "invalid_blocks": 1,
    "jsonld_blocks": 1,
    "microdata_blocks": 2,
    "rdfa_blocks": 0,
    "error_count": 1,
    "warning_count": 3,
    "info_count": 0
  },
  "schema_types_found": ["Organization", "Product", "BreadcrumbList"],
  "duplicate_ids": [],
  "blocks": [
    {
      "format": "json-ld",
      "schema_type": "Organization",
      "is_valid": false,
      "issues": [
        {
          "schema_type": "Organization",
          "field": "url",
          "issue": "Missing required field: 'url'",
          "severity": "error",
          "suggestion": "Add the 'url' field"
        }
      ]
    }
  ]
}
```

## Usage

### CLI

```bash
# Run with all analyzers
wdt analyze example.com

# Run only structured data analysis
wdt analyze --only structured-data example.com

# Skip structured data analysis
wdt analyze --skip structured-data example.com

# JSON output for programmatic use
wdt analyze --format json example.com | jq '.structured_data'
```

### Programmatic

```python
from webmaster_domain_tool.analyzers.structured_data import (
    StructuredDataAnalyzer,
    StructuredDataConfig,
)

analyzer = StructuredDataAnalyzer()
config = StructuredDataConfig(
    check_jsonld=True,
    check_microdata=True,
    check_rdfa=True,
)

result = analyzer.analyze("example.com", config)

print(f"Found {result.total_blocks} blocks")
print(f"Valid: {result.valid_blocks}, Invalid: {result.invalid_blocks}")

for block in result.blocks:
    print(f"{block.format}: {block.schema_type} - {'✓' if block.is_valid else '✗'}")
```

## Common Issues and Fixes

### Missing Required Fields

**Issue:** `[ERROR] Product - missing required field: 'name'`

**Fix:** Add the required field to your structured data:

```json
{
  "@context": "https://schema.org",
  "@type": "Product",
  "name": "Product Name"
}
```

### Invalid Date Format

**Issue:** `[WARNING] datePublished has invalid format (expected ISO 8601)`

**Fix:** Use ISO 8601 date format:

```json
{
  "datePublished": "2024-01-15",
  "dateModified": "2024-01-15T14:30:00Z"
}
```

### Price as String

**Issue:** `[WARNING] price should be Number, got String`

**Fix:** Remove quotes from numeric values:

```json
// Wrong
"price": "99.99"

// Correct
"price": 99.99
```

### Invalid Availability Enum

**Issue:** `[WARNING] Invalid enum value: 'In Stock'`

**Fix:** Use valid Schema.org enum values:

```json
{
  "availability": "https://schema.org/InStock"
}
```

### Duplicate @id

**Issue:** `Duplicate @id values found: #product-123`

**Fix:** Ensure each entity has a unique @id:

```json
{
  "@id": "#product-123"
}

// Another block should use different @id
{
  "@id": "#product-456"
}
```

## Best Practices

1. **Use JSON-LD** - Google's recommended format for structured data
2. **Include @context** - Always use `https://schema.org`
3. **Use @id** - Provide unique identifiers for entities
4. **Include all required fields** - Essential for rich result eligibility
5. **Add recommended fields** - Improves rich result appearance
6. **Validate dates** - Use ISO 8601 format consistently
7. **Test with Google** - Use [Google Rich Results Test](https://search.google.com/test/rich-results) to verify

## Google Rich Results

Valid structured data enables rich results in Google Search:

- **Product** - Price, availability, review stars in search results
- **Article** - Author, date, image in news carousel
- **Recipe** - Cooking time, rating, image in recipe carousel
- **FAQ** - Expandable FAQ sections in search results
- **BreadcrumbList** - Breadcrumb trail in search results
- **LocalBusiness** - Business info in knowledge panel

## Dependencies

- **http** - Requires HTTP analyzer to determine the URL to analyze

## See Also

- [Schema.org](https://schema.org/) - Official schema documentation
- [Google Search Central](https://developers.google.com/search/docs/advanced/structured-data/intro-structured-data) - Google's structured data guide
- [JSON-LD](https://json-ld.org/) - JSON-LD specification
