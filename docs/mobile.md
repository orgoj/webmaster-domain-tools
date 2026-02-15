# Mobile-Friendly Analyzer

The Mobile-Friendly analyzer performs comprehensive mobile-friendliness testing for websites, checking key factors that affect user experience on mobile devices.

## Overview

- **Analyzer ID:** `mobile`
- **Category:** SEO
- **Dependencies:** `http` (optional, for URL resolution)

## Usage

### CLI

```bash
# Run mobile analysis only
uv run wdt analyze example.com --only mobile

# Run with other analyzers
uv run wdt analyze example.com --analyzers http,ssl,mobile

# Verbose output
uv run wdt analyze example.com --only mobile -v
```

### Programmatic

```python
from webmaster_domain_tool.analyzers.mobile import MobileAnalyzer, MobileConfig

analyzer = MobileAnalyzer()
config = MobileConfig(
    min_touch_target_size=48,
    min_font_size=12,
)
result = analyzer.analyze("example.com", config)
print(f"Mobile Score: {result.mobile_score}/100")
print(f"Is Mobile-Friendly: {result.is_mobile_friendly}")
```

## Checks Performed

### 1. Viewport Meta Tag Configuration

Checks for proper viewport meta tag configuration:

- **Presence:** Verifies the viewport meta tag exists
- **Width:** Should be set to `device-width`
- **Initial Scale:** Should be 1.0
- **User Scalable:** Should not be disabled (accessibility issue)
- **Maximum Scale:** Should not be limited to 1.0 (prevents zooming)

**Example of good viewport tag:**
```html
<meta name="viewport" content="width=device-width, initial-scale=1.0">
```

**Common issues detected:**
- Missing viewport meta tag
- Fixed width instead of `device-width`
- Disabled user scaling
- Maximum scale set to 1.0 or less

### 2. Touch Targets Size Validation

Validates that touch targets (buttons, links, inputs) are large enough for mobile users:

- **Minimum Size:** 48x48 pixels (Google's recommendation)
- **Spacing:** Checks for crowded tap targets
- **Coverage:** Analyzes all interactive elements

**What is checked:**
- Links (`<a>` tags)
- Buttons (`<button>` tags)
- Form inputs (`<input>`, `<select>`, `<textarea>`)
- Labels

### 3. Font Readability

Ensures text is readable on mobile devices:

- **Minimum Font Size:** 12px recommended
- **Small Font Detection:** Identifies elements with tiny text
- **Context Analysis:** Reports elements with problematic font sizes

### 4. Responsive Design Detection

Detects responsive design patterns:

- **Media Queries:** CSS `@media` rules
- **Flexbox:** Modern flexible layouts
- **CSS Grid:** Modern grid layouts
- **Viewport Units:** `vw`, `vh`, `vmin`, `vmax`
- **Mobile Stylesheets:** Dedicated mobile CSS files
- **Responsive Images:** `srcset`, lazy loading
- **Framework Detection:** Bootstrap, Tailwind, etc.

### 5. Mobile Performance Indicators

Analyzes factors affecting mobile performance:

- **Page Size:** Total page weight
- **External Requests:** Number of CSS, JS, and image requests
- **Image Count:** Number of images on page
- **AMP:** Checks for Accelerated Mobile Pages usage
- **Lazy Loading:** Presence of lazy loading for images

## Scoring

The mobile score (0-100) is calculated based on:

| Check | Max Points |
|-------|------------|
| Viewport Configuration | 25 |
| Touch Targets | 25 |
| Font Readability | 20 |
| Responsive Design | 20 |
| Mobile Performance | 10 |

**Mobile-Friendly Threshold:** Score ≥ 70

## Output

### Summary Section
- Overall mobile score
- Mobile-friendly status
- Passed/failed checks count

### Viewport Configuration
- Viewport meta tag presence and content
- Width and scale settings
- User scalability status

### Touch Targets
- Total tap targets count
- Small targets detection
- Crowded areas warning

### Font Readability
- Smallest font size detected
- Elements with small fonts

### Responsive Design
- Responsive score (0-100)
- Detected patterns and frameworks

### Mobile Performance
- Page size
- External requests count
- Image count
- AMP and lazy loading status

### Recommendations
- Failed checks (must fix)
- Warnings (should fix)

## Configuration Options

```python
class MobileConfig(AnalyzerConfig):
    # Mobile user agent for requests
    user_agent_mobile: str = "Mozilla/5.0 (Linux; Android 13; ...)"
    
    # Desktop user agent for comparison
    user_agent_desktop: str = "Mozilla/5.0 (Windows NT 10.0; ...)"
    
    # Minimum touch target size (pixels)
    min_touch_target_size: int = 48
    
    # Minimum readable font size (pixels)
    min_font_size: int = 12
    
    # Request timeout
    timeout: float = 10.0
```

## JSON Output

```json
{
  "domain": "example.com",
  "url": "https://example.com",
  "success": true,
  "is_mobile_friendly": true,
  "mobile_score": 82,
  "viewport": {
    "present": true,
    "content": "width=device-width, initial-scale=1.0",
    "width": "device-width",
    "initial_scale": 1.0,
    "user_scalable": true,
    "issues": []
  },
  "touch_targets": {
    "total_tap_targets": 45,
    "small_targets": [],
    "close_targets": [],
    "passed": true,
    "issues": []
  },
  "font_readability": {
    "smallest_font_size": 14,
    "small_font_elements": [],
    "passed": true,
    "issues": []
  },
  "responsive": {
    "uses_media_queries": true,
    "uses_flexbox": true,
    "uses_grid": false,
    "uses_viewport_units": true,
    "has_mobile_stylesheets": false,
    "responsive_score": 65,
    "indicators": [
      "Uses CSS media queries",
      "Uses CSS flexbox",
      "Uses viewport units (vw, vh)"
    ]
  },
  "performance": {
    "page_size_bytes": 245760,
    "html_size_bytes": 45056,
    "image_count": 12,
    "external_requests": 25,
    "uses_amp": false,
    "has_lazy_loading": true,
    "issues": []
  },
  "passed_checks": [
    "Viewport meta tag properly configured",
    "Touch targets are appropriately sized",
    "Font sizes are readable on mobile"
  ],
  "failed_checks": [],
  "warnings": [],
  "errors": []
}
```

## Best Practices for Mobile Optimization

### Viewport
- Always include `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
- Never disable user scaling
- Don't set maximum-scale to 1.0

### Touch Targets
- Make all interactive elements at least 48x48 pixels
- Provide adequate spacing between targets (minimum 8px)
- Avoid clustering multiple links in small areas

### Typography
- Use base font size of at least 16px for body text
- Avoid font sizes below 12px for any content
- Ensure sufficient contrast for readability

### Responsive Design
- Use CSS media queries for different screen sizes
- Implement fluid layouts with flexbox or grid
- Use relative units (%, rem, vw/vh) over fixed pixels
- Provide responsive images with srcset

### Performance
- Keep page size under 1MB for mobile
- Limit external requests to under 50
- Implement lazy loading for images
- Consider AMP for content pages

## Related Analyzers

- **core-web-vitals:** Performance metrics (LCP, INP, CLS)
- **seo:** SEO files (robots.txt, sitemap.xml)
- **performance:** General performance analysis
- **http:** HTTP headers and response analysis
