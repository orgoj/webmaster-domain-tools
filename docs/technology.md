# Technology Stack Analyzer

Detects web technologies, frameworks, and platforms used on websites.

## Overview

The Technology Stack analyzer (`technology`) identifies the technologies powering a website by analyzing:

- **HTML content** - meta tags, scripts, CSS classes, and other HTML signatures
- **HTTP headers** - Server, X-Powered-By, Via, and other header indicators
- **Script sources** - URLs and paths revealing frameworks and libraries
- **Meta tags** - Generator tags and other technology indicators

## Supported Technologies

### Content Management Systems (CMS)

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| WordPress | HTML patterns, meta tags | High |
| Drupal | HTML patterns, JS variables | High |
| Joomla | HTML patterns, meta tags | High |
| Ghost | Meta generator, paths | High |
| HubSpot CMS | Script URLs | High |
| Craft CMS | Paths | Medium |
| TYPO3 | Meta tags, paths | High |
| Contao | Meta tags, CSS | High |
| Bitrix | Paths, JS | High |
| Adobe Experience Manager | Paths, attributes | Medium |

### E-commerce Platforms

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| WooCommerce | HTML patterns | High |
| Shopify | CDN URLs, classes | High |
| Magento | Meta tags, paths | High |
| PrestaShop | Meta tags, paths | High |
| OpenCart | Paths | Medium |
| BigCommerce | Script URLs | High |
| Salesforce Commerce Cloud | Domain patterns | High |

### JavaScript Frameworks

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| React | Script files, DOM attributes | High |
| Vue.js | Script files, DOM attributes | High |
| Angular | DOM attributes, script files | High |
| Next.js | `__NEXT_DATA__` variable | High |
| Nuxt.js | `__NUXT__` variable | High |
| Gatsby | Script files, DOM attributes | High |
| Svelte | CSS classes | Medium |
| Ember.js | Script files, ENV variable | High |
| Backbone.js | Script files | High |
| Alpine.js | DOM attributes (`x-*`) | High |
| HTMX | DOM attributes (`hx-*`) | High |
| Stimulus | DOM attributes | High |
| Livewire | DOM attributes (`wire:*`) | High |
| Remix | Context variable | High |
| Astro | CSS classes | Medium |
| SolidJS | Script files | High |

### JavaScript Libraries

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| jQuery | Script files | High |
| Bootstrap | JS/CSS files | High |
| Tailwind CSS | CSS files | High |
| Foundation | JS/CSS files | High |
| Bulma | CSS files | High |
| Material Design | CSS classes | High |
| Material-UI | CSS classes | High |
| Ant Design | CSS classes | High |
| Lodash | Script files | High |
| Moment.js | Script files | High |
| D3.js | Script files | High |
| Three.js | Script files, global variable | High |
| Chart.js | Script files | High |
| GSAP | Script files, global variable | High |
| Axios | Script files | High |
| Redux | Script files, global variable | High |

### Server Software

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| nginx | Server header | High |
| Apache | Server header | High |
| Microsoft-IIS | Server header | High |
| LiteSpeed | Server header | High |
| OpenResty | Server header | High |
| Caddy | Server header | High |
| Cloudflare | Server header, CF-Ray header | High |
| Varnish | Via header, X-Varnish | High |
| Squid | Server/Via header | High |

### Analytics & Tracking

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| Google Analytics | Script URLs, tracking codes | High |
| Google Tag Manager | Script URLs, dataLayer | High |
| Hotjar | Script URLs, hj() calls | High |
| Mixpanel | Script URLs, tracking calls | High |
| Segment | Script URLs | High |
| Plausible | Script URLs | High |
| Fathom | Script URLs | High |
| Matomo | Script URLs, _paq.push | High |

### Web Fonts

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| Google Fonts | Font URLs | High |
| Adobe Fonts | Font URLs | High |
| Font Awesome | CSS classes, URLs | High |

### Server-side Frameworks

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| Laravel | HTML patterns | High |
| Django | Form tokens, admin paths | High |
| Ruby on Rails | HTML patterns, Turbolinks | High |
| ASP.NET | ViewState, form tokens | High |
| Express.js | X-Powered-By header | High |

### Other Technologies

| Technology | Detection Method | Confidence |
|------------|------------------|------------|
| PHP | X-Powered-By header | High |
| Webpack | Chunk variables | High |
| Vite | Path patterns | High |
| PWA | Manifest, service worker | High |
| AMP | HTML boilerplate | High |

## Configuration

### Basic Configuration

```toml
[technology]
enabled = true
timeout = 10.0
user_agent = "Mozilla/5.0 (compatible; WebmasterDomainTool/1.0)"
```

### Advanced Configuration

```toml
[technology]
enabled = true
timeout = 10.0
user_agent = "Mozilla/5.0 (compatible; WebmasterDomainTool/1.0)"

# Enable/disable specific detection methods
check_html = true      # Analyze HTML content
check_headers = true   # Analyze HTTP headers
check_scripts = true   # Analyze script sources
check_meta = true      # Analyze meta tags
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable the analyzer |
| `timeout` | float | `10.0` | HTTP request timeout in seconds |
| `user_agent` | string | `"Mozilla/5.0..."` | User agent for HTTP requests |
| `check_html` | bool | `true` | Check HTML content for technology signatures |
| `check_headers` | bool | `true` | Check HTTP headers for technology signatures |
| `check_scripts` | bool | `true` | Check script sources for technology signatures |
| `check_meta` | bool | `true` | Check meta tags for technology signatures |

## Usage

### CLI Usage

```bash
# Basic analysis
wdt analyze example.com --only technology

# With verbose output
wdt analyze example.com --only technology --verbose

# With JSON output
wdt analyze example.com --only technology --format json
```

### Example Output

```
╭──────────────────────────────────────────────────────────────────╮
│ Technology Stack                                                 │
├──────────────────────────────────────────────────────────────────┤
│ Technologies Detected: 8                                         │
│                                                                  │
│ CMS: WordPress                                                   │
│ Framework: React                                                 │
│ Server: nginx                                                    │
│                                                                  │
│ Content Management System                                        │
│   WordPress                                           High       │
│   WooCommerce                                         High       │
│                                                                  │
│ JavaScript Framework                                             │
│   React                                               High       │
│   Next.js                                             High       │
│                                                                  │
│ Server Software                                                  │
│   nginx                                               High       │
│                                                                  │
│ Analytics                                                        │
│   Google Analytics                                    High       │
│   Google Tag Manager                                  High       │
╰──────────────────────────────────────────────────────────────────╯
```

### JSON Output Example

```json
{
  "domain": "example.com",
  "total_technologies": 8,
  "cms": "WordPress",
  "framework": "React",
  "server": "nginx",
  "ecommerce": "WooCommerce",
  "technologies": [
    {
      "name": "WordPress",
      "category": "cms",
      "category_name": "Content Management System",
      "confidence": "high",
      "detection_method": "html",
      "evidence": ["wp-content/", "wp-includes/"]
    },
    {
      "name": "React",
      "category": "framework",
      "category_name": "JavaScript Framework",
      "confidence": "high",
      "detection_method": "script",
      "evidence": ["react.min.js"]
    }
  ],
  "categories": {
    "cms": {
      "category_id": "cms",
      "category_name": "Content Management System",
      "technologies": ["WordPress"]
    }
  }
}
```

## Detection Methods

### HTML Pattern Matching

The analyzer uses regular expressions to search for technology signatures in HTML content:

```html
<!-- Example: WordPress detection -->
<meta name="generator" content="WordPress 6.3">
<link rel='stylesheet' href='/wp-content/themes/...'>
<script src='/wp-includes/js/...'></script>
```

### HTTP Header Analysis

Server and framework information is extracted from HTTP response headers:

```http
HTTP/1.1 200 OK
Server: nginx/1.24.0
X-Powered-By: PHP/8.2.0
Via: 1.1 varnish
CF-Ray: 7a1b2c3d4e5f6g7h
```

### Script Source Detection

Technology signatures are detected in script URLs:

```html
<script src="/static/js/main.js"></script>
<script src="https://cdn.example.com/react.min.js"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID"></script>
```

### Meta Tag Detection

Generator meta tags and other indicators reveal CMS information:

```html
<meta name="generator" content="WordPress 6.3">
<meta name="generator" content="Drupal 10">
```

## Confidence Levels

| Level | Description |
|-------|-------------|
| **High** | Strong evidence found (e.g., meta generator tag, definitive paths) |
| **Medium** | Likely match based on patterns (e.g., similar paths, common classes) |
| **Low** | Weak evidence or generic indicators |

## Dependencies

The Technology analyzer depends on:

- `http` - HTTP/HTTPS Analysis (for HTML content and headers)

## API Integration

### Programmatic Usage

```python
from webmaster_domain_tool.analyzers.technology import TechnologyAnalyzer, TechnologyConfig

# Create analyzer instance
analyzer = TechnologyAnalyzer()

# Create configuration
config = TechnologyConfig(
    enabled=True,
    timeout=10.0,
    check_html=True,
    check_headers=True,
)

# Run analysis
result = analyzer.analyze("example.com", config)

# Access results
print(f"CMS: {result.cms}")
print(f"Framework: {result.framework}")
print(f"Server: {result.server}")
print(f"Total technologies: {result.total_technologies}")

# Get all detected technologies
for tech in result.technologies:
    print(f"  - {tech.name} ({tech.category}): {tech.confidence}")
```

## Limitations

### Static Analysis Only

The analyzer performs **static HTML analysis** - it does not:

- Execute JavaScript
- Render the page in a browser
- Wait for dynamic content to load

This means some technologies may not be detected if they:

- Are loaded dynamically via JavaScript
- Don't leave traces in static HTML
- Use obfuscated code

### Technology Version Detection

The analyzer detects technology **presence**, not version numbers. For version information:

- Check HTTP headers (Server, X-Powered-By)
- Look for version comments in HTML source
- Use dedicated security scanners

### False Positives/Negatives

**False positives** may occur when:
- Technology names appear in unrelated content
- Generic patterns match multiple technologies

**False negatives** may occur when:
- Technologies are heavily customized
- Detection patterns are outdated

## Best Practices

### For Accurate Detection

1. **Combine multiple detection methods** - Enable all check types for best results
2. **Use verbose output** - Review evidence for each detection
3. **Cross-reference** - Compare with manual inspection or other tools

### For Privacy & Performance

1. **Disable unused checks** - Turn off `check_scripts` if not needed
2. **Adjust timeout** - Lower for fast sites, raise for slow ones
3. **Custom user agent** - Use appropriate user agent for target sites

## Troubleshooting

### No Technologies Detected

1. **Check HTML access**: Verify the site returns HTML content
2. **Review headers**: Some sites block automated tools
3. **Enable verbose mode**: See what the analyzer is checking

### Unexpected Results

1. **Review evidence**: Check the `evidence` field in JSON output
2. **Confidence levels**: Focus on high-confidence detections
3. **Cross-check**: Verify with manual inspection

### Performance Issues

1. **Increase timeout**: If requests are timing out
2. **Disable heavy checks**: Turn off `check_html` for large pages
3. **Network conditions**: Check internet connectivity

## Related Analyzers

- **`cdn`** - CDN Detection (identifies CDN providers)
- **`third-party`** - Third-Party Auditor (tracks external resources)
- **`performance`** - Performance Analysis (page load metrics)
- **`html`** - HTML Validator (HTML quality and SEO)

## Changelog

### v1.0.0 (Initial Release)

- Comprehensive technology detection database
- Support for 100+ technologies across 15+ categories
- Multiple detection methods (HTML, headers, scripts, meta)
- Confidence scoring system
- JSON serialization for programmatic access
