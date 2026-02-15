# Lighthouse Analyzer

## Overview

The Lighthouse analyzer provides comprehensive website analysis using Google Lighthouse via the PageSpeed Insights API. It evaluates websites across four key categories:

- **Performance** - Page load speed and optimization
- **Accessibility** - WCAG compliance and assistive technology support
- **Best Practices** - Modern web development standards
- **SEO** - Search engine optimization

## Installation

The analyzer uses the Google PageSpeed Insights API, which is free and requires no API key for basic usage. However, there are daily quota limits.

For higher quotas, you can obtain a Google API key from the [Google Cloud Console](https://console.cloud.google.com/) and enable the PageSpeed Insights API.

## Usage

### CLI Usage

```bash
# Run Lighthouse analysis only
wdt analyze example.com --only lighthouse

# Run with verbose output
wdt analyze example.com --only lighthouse --verbosity verbose

# Run with JSON output
wdt analyze example.com --only lighthouse --format json

# Run mobile analysis
wdt analyze example.com --only lighthouse --config lighthouse-mobile.toml
```

### Configuration

Create a configuration file to customize the analyzer:

```toml
# lighthouse.toml
[analyzers.lighthouse]
enabled = true
timeout = 60.0
strategy = "desktop"  # or "mobile"
api_key = ""  # Optional: Google API key for higher quota
categories = ["performance", "accessibility", "best-practices", "seo"]
```

### Mobile Analysis

For mobile-specific analysis:

```toml
[analyzers.lighthouse]
strategy = "mobile"
```

### API Key Configuration

To use a Google API key:

```toml
[analyzers.lighthouse]
api_key = "YOUR_API_KEY_HERE"
```

## Output

The analyzer returns scores for each category (0-100):

| Score Range | Rating            | Description                           |
|-------------|-------------------|---------------------------------------|
| 90-100      | Good              | Excellent performance                 |
| 50-89       | Needs Improvement | Some issues to address                |
| 0-49        | Poor              | Significant problems                  |

### Example Output

```
Lighthouse Audit

Overall Score
  Lighthouse Score                     78/100

Category Scores
  ✓ Accessibility                      92/100
  ⚠ Best Practices                     83/100
  ⚠ Performance                        78/100
  ⚠ SEO                                60/100

Key Metrics (verbose)
  Largest Contentful Paint             2.5 s
  First Contentful Paint               1.2 s
  Total Blocking Time                  340 ms
  Cumulative Layout Shift              0.05
  Speed Index                          3.2 s

Performance Issues (3)
  ⚠ Eliminate render-blocking resources
    → Potential savings of 450 ms
  ⚠ Properly size images
    → Potential savings of 120 KB
  ⚠ Reduce unused JavaScript
    → Potential savings of 85 KB
```

## Scores Explained

### Performance
Measures page load performance including:
- Largest Contentful Paint (LCP)
- First Contentful Paint (FCP)
- Speed Index
- Total Blocking Time (TBT)
- Cumulative Layout Shift (CLS)

### Accessibility
Checks for WCAG compliance including:
- Color contrast
- ARIA attributes
- Form labels
- Image alt text
- Keyboard navigation

### Best Practices
Evaluates:
- HTTPS usage
- Modern JavaScript features
- Security practices
- Browser compatibility

### SEO
Analyzes search engine optimization:
- Meta tags
- Structured data
- Mobile friendliness
- Crawlability

## API Limitations

The free PageSpeed Insights API has daily quota limits. If you encounter a 429 error:

1. Wait for quota reset (daily)
2. Use an API key for higher quota
3. Reduce the number of categories analyzed at once

## Dependencies

- `httpx` - HTTP client for API requests
- No local Lighthouse CLI required (uses remote API)

## Integration with Other Analyzers

The Lighthouse analyzer can use results from the HTTP analyzer to:
- Determine the correct URL to analyze
- Handle redirects properly
- Use the preferred protocol (HTTP/HTTPS)

## Troubleshooting

### Quota Exceeded Error

```
PageSpeed API quota exceeded. Try again later or use an API key.
```

Solution: Wait for quota reset or configure an API key.

### Timeout Error

```
HTTP error: Timeout
```

Solution: Increase timeout in configuration:
```toml
[analyzers.lighthouse]
timeout = 120.0
```

### No Data Available

If the site has insufficient traffic, field data (CrUX) may not be available. Lab data from Lighthouse will still be provided.
