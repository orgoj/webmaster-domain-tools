# Cookies & Consent Analyzer

## Overview

The Cookies & Consent analyzer detects cookie consent mechanisms, Consent Management Platforms (CMPs), and assesses GDPR/ePrivacy compliance for websites.

## Features

- **CMP Detection**: Identifies 15+ known Consent Management Platforms
- **Banner Detection**: Finds consent banners and analyzes their features
- **Cookie Policy Detection**: Locates cookie policy pages
- **Compliance Scoring**: Provides GDPR compliance indicators and recommendations

## Supported Consent Management Platforms

The analyzer detects the following CMPs:

| CMP | Detection Confidence |
|-----|---------------------|
| OneTrust | High |
| Cookiebot | High |
| Quantcast Choice | High |
| CookieYes (GDPR Cookie Consent) | High |
| TrustArc | High |
| iubenda | High |
| Didomi | High |
| Usercentrics | High |
| ConsentManager | High |
| Sourcepoint | High |
| Borlabs Cookie | High |
| CookieFirst | High |
| Civic Cookie Control | High |
| Osano | High |
| CookiePro (OneTrust) | High |

## Compliance Checks

The analyzer checks for the following GDPR/ePrivacy compliance indicators:

1. **Consent Mechanism**: Is there a cookie consent banner?
2. **Known CMP**: Is a recognized GDPR-compliant CMP in use?
3. **Cookie Policy**: Is there a link to a cookie policy page?
4. **Reject Option**: Does the banner allow users to reject cookies?
5. **Customize Option**: Can users customize their cookie preferences?

### Compliance Scoring

| Feature | Points |
|---------|--------|
| Consent mechanism present | 30 |
| Uses known CMP | 25 |
| Has cookie policy | 20 |
| Provides reject option | 15 |
| Provides customize option | 10 |

**Total**: 100 points

- **70+ points**: Likely GDPR compliant
- **50-69 points**: Moderate compliance, improvements recommended
- **<50 points**: Low compliance, significant issues detected

## Usage

### CLI

```bash
# Run cookies/consent analysis
webmaster-domain-tools analyze example.com --analyzers cookies_consent

# Run with verbose output
webmaster-domain-tools analyze example.com --analyzers cookies_consent -v
```

### Python API

```python
from webmaster_domain_tool.analyzers import registry

# Get the analyzer
metadata = registry.get("cookies_consent")
analyzer = metadata.plugin_class()

# Run analysis
config = metadata.config_class()
result = analyzer.analyze("example.com", config)

# Check results
if result.likely_gdpr_compliant:
    print(f"GDPR compliant with score: {result.compliance.compliance_score}/100")
else:
    print(f"Compliance issues detected: {result.compliance.issues}")
```

### With Context (HTTP analyzer)

```python
from webmaster_domain_tool.analyzers import registry

# Run HTTP analyzer first
http_meta = registry.get("http")
http_analyzer = http_meta.plugin_class()
http_result = http_analyzer.analyze("example.com", http_meta.config_class())

# Run cookies analyzer with HTTP context
cookies_meta = registry.get("cookies_consent")
cookies_analyzer = cookies_meta.plugin_class()
cookies_result = cookies_analyzer.analyze(
    "example.com", 
    cookies_meta.config_class(),
    context={"http": http_result}
)
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | True | Enable/disable the analyzer |
| `timeout` | float | 15.0 | HTTP request timeout in seconds |
| `user_agent` | string | WebmasterDomainTool/1.0 | User agent for requests |
| `check_cookie_policy` | bool | True | Check for cookie policy page |
| `detect_cmp` | bool | True | Detect known CMPs |
| `check_banner_presence` | bool | True | Check for consent banners |

### Example Configuration

```toml
[analyzers.cookies_consent]
enabled = true
timeout = 20.0
check_cookie_policy = true
detect_cmp = true
check_banner_presence = true
```

## Output Structure

### Result Object

```python
@dataclass
class CookiesConsentResult:
    domain: str
    url: str
    success: bool
    
    # Detection results
    cmp_detected: CMPInfo | None        # Primary CMP detected
    banner: BannerInfo | None           # Consent banner info
    cookie_policy: CookiePolicyInfo | None  # Cookie policy info
    compliance: ComplianceIndicators | None  # Compliance assessment
    
    # Overall assessment
    has_consent_solution: bool
    likely_gdpr_compliant: bool
    
    # Issues
    errors: list[str]
    warnings: list[str]
```

### CMP Info

```python
@dataclass
class CMPInfo:
    cmp_id: str           # Internal ID (e.g., "onetrust")
    name: str             # Display name (e.g., "OneTrust")
    gdpr_compliant: bool  # Is this CMP GDPR compliant?
    detection_method: str # How it was detected ("script", "dom")
    confidence: str       # Detection confidence ("high", "medium", "low")
```

### Banner Info

```python
@dataclass
class BannerInfo:
    detected: bool
    has_accept_button: bool
    has_reject_button: bool
    has_customize_button: bool
    banner_text_preview: str | None
    detection_method: str | None
```

### Compliance Indicators

```python
@dataclass
class ComplianceIndicators:
    has_consent_mechanism: bool
    has_cookie_policy: bool
    uses_known_cmp: bool
    provides_reject_option: bool
    provides_customize_option: bool
    compliance_score: int  # 0-100
    issues: list[str]
    recommendations: list[str]
```

## Recommendations

The analyzer provides actionable recommendations based on detected issues:

### Missing Consent Banner

```
No consent banner detected - GDPR requires consent for non-essential cookies
```

**Action**: Implement a cookie consent banner or CMP.

### Missing Cookie Policy

```
No cookie policy found - GDPR requires transparent cookie information
```

**Recommendation**: Add a cookie policy page detailing cookie usage.

### Missing Reject Option

```
Recommendation: Add a 'Reject' option to the consent banner
```

**Action**: Include a clear "Reject" or "Decline" button.

### Missing Customize Option

```
Recommendation: Add cookie preferences/customization option
```

**Action**: Allow users to selectively enable/disable cookie categories.

## Detection Methods

### CMP Detection

1. **Script Analysis**: Checks external script sources for known CMP domains
2. **Inline Script Analysis**: Examines inline JavaScript for CMP initialization code
3. **DOM Analysis**: Searches for elements with CMP-specific class names or IDs

### Banner Detection

1. **Pattern Matching**: Searches for common banner class names/IDs
2. **Button Analysis**: Identifies Accept/Reject/Customize buttons
3. **Inferred Detection**: If a CMP is detected, banner is assumed present

### Cookie Policy Detection

1. **Link Analysis**: Searches for links containing "cookie", "privacy", etc.
2. **Accessibility Check**: Verifies the policy page is accessible

## Limitations

1. **JavaScript-Rendered Banners**: Banners rendered purely by JavaScript after page load may not be detected
2. **Custom CMPs**: Proprietary or custom consent solutions may not be recognized
3. **Cookie Analysis**: Only cookies set in the initial HTTP response are detected
4. **Regional Variations**: Some sites show consent banners only to EU visitors

## Related Analyzers

- **HTTP Analyzer**: Provides URL resolution and cookie context
- **Security Headers Analyzer**: Related privacy and security headers
- **Accessibility Analyzer**: Consent banners should be accessible

## References

- [GDPR Article 7](https://gdpr-info.eu/art-7-gdpr/) - Conditions for consent
- [ePrivacy Directive](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32002L0058) - Cookie requirements
- [IAB TCF 2.0](https://iabeurope.eu/tcf-2-0/) - Transparency and Consent Framework
