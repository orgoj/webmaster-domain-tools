# Webmaster Domain Tool

Comprehensive tool for webmasters that analyzes and clearly displays all important information about a domain.

## Features

### DNS Analysis
- ✅ A/AAAA records (IPv4/IPv6)
- ✅ MX records (mail servers)
- ✅ TXT records
- ✅ NS records (nameservers)
- ✅ SOA records
- ✅ CAA records (Certificate Authority Authorization)
- ✅ CNAME records
  - **Automatic DNS rule checking** (CNAME cannot coexist with A/AAAA)
  - Distinction between CNAME and direct A records
- ✅ **DNSSEC validation**
  - DNSKEY and DS record checking
  - Chain of trust validation
  - Warnings for invalid configuration
- ✅ Domain and www variant checking
- ✅ **Optional warning** when www is not a CNAME (best practice)

### HTTP/HTTPS Analysis
- ✅ Testing all variants (http/https, with/without www)
- ✅ Following all redirects in chain
- ✅ Detailed information for each step
- ✅ Response time checking
- ✅ Redirect problem detection
- ✅ Insecure HTTP warnings

### SSL/TLS Certificates
- ✅ Certificate validation
- ✅ Validity and expiration checking
- ✅ **Issuer information** (Certificate Authority name displayed in output)
- ✅ Subject Alternative Names (SAN)
- ✅ Days until expiration with color-coded warnings
- ✅ TLS protocol support (1.0, 1.1, 1.2, 1.3)
- ✅ Deprecated protocol warnings
- ✅ Certificate chain validation

### Email Security
- ✅ **SPF** (Sender Policy Framework)
  - SPF record validation
  - Mechanism analysis
  - Policy checking (soft fail / hard fail)
- ✅ **DKIM** (DomainKeys Identified Mail)
  - DKIM selector checking
  - Public key validation
  - Custom selector support
- ✅ **DMARC** (Domain-based Message Authentication)
  - DMARC policy validation
  - Reporting address checking
  - Subdomain policy analysis
- ✅ **BIMI** (Brand Indicators for Message Identification)
  - BIMI record detection
  - VMC (Verified Mark Certificate) validation
- ✅ **MTA-STS** (Mail Transfer Agent Strict Transport Security)
  - Policy file validation
  - Mode checking (testing/enforce/none)
  - MX host validation
- ✅ **TLS-RPT** (TLS Reporting)
  - Reporting endpoint validation
  - Email address verification

### WHOIS Information
- ✅ Domain registration details
- ✅ Registrar information (with special .cz domain support)
- ✅ Creation and expiration dates
- ✅ Days until expiration
- ✅ Name server listing
- ✅ Registrant organization and name (when available)
- ✅ Registrant email (when available)
- ✅ Administrator contact information (admin-c for .cz domains)
- ✅ Administrator name and email (when available)
- ✅ Expiration warnings (30/60 day thresholds)
- ✅ Special parsing for .cz domains to ensure correct registrar extraction

### CDN Detection
- ✅ Automatic CDN provider detection
- ✅ Header-based identification (Cloudflare, Fastly, Akamai, CloudFront, etc.)
- ✅ CNAME-based detection
- ✅ Confidence scoring (high/medium/low)
- ✅ Support for 12+ major CDN providers

### SEO Files Analysis
- ✅ **robots.txt** analysis
  - User-Agent directive parsing
  - Disallow/Allow rule detection
  - Sitemap URL extraction
  - Crawl-delay checking
- ✅ **llms.txt** detection
  - AI crawler configuration standard
- ✅ **sitemap.xml** analysis
  - XML validation
  - URL counting
  - Sitemap index support
  - Size warnings (>50,000 URLs)

### Favicon Analysis
- ✅ **Comprehensive format support**
  - PNG, ICO, JPEG, GIF, SVG
  - Multi-layer ICO detection (shows all embedded resolutions)
  - Real dimension extraction from image data
- ✅ **All standard locations**
  - HTML link tags (all rel types)
  - Apple Touch Icons (all sizes: 180x180, 167x167, 152x152, 120x120, 76x76, 60x60)
  - Safari mask-icon with color attribute
  - Microsoft Tile meta tags
  - Web App Manifest (manifest.json) parsing
  - Default paths (/favicon.ico, /favicon.svg, etc.)
- ✅ **Detailed information**
  - Source tracking (HTML vs default path vs manifest)
  - Actual dimensions (not just HTML sizes attribute)
  - File size in bytes
  - Purpose attribute for PWA icons
  - Deduplication (HTML sources take precedence)
- ✅ **Best practice warnings**
  - Missing favicon.ico
  - Favicon conflicts (default path vs HTML)

### RBL (Realtime Blacklist) Check
- ✅ IP address blacklist checking
- ✅ Support for major RBL services
  - Spamhaus ZEN
  - SpamCop
  - Barracuda Central
  - SORBS
- ✅ A records and MX server checking
- ✅ Configurable RBL servers

### Security Headers
- ✅ Strict-Transport-Security (HSTS)
- ✅ Content-Security-Policy (CSP)
- ✅ X-Frame-Options
- ✅ X-Content-Type-Options
- ✅ Referrer-Policy
- ✅ Permissions-Policy
- ✅ X-XSS-Protection
- ✅ Content-Type
- ✅ Security score (0-100)
- ✅ Detailed recommendations for each header

### Site Verification
- ✅ **Multi-platform verification support**
  - Google (DNS TXT, HTML file, meta tag)
  - Facebook (DNS TXT, meta tag)
  - Pinterest (DNS TXT, meta tag, HTML file)
  - Bing (meta tag)
  - Yandex (meta tag)
- ✅ **Auto-detection**
  - Automatically detects verification IDs from DNS and HTML
  - Shows all verification methods found for each service
  - Only displays services with actual results
- ✅ **Tracking Codes Detection** (Google-specific)
  - Google Tag Manager (GTM-XXXXXXX)
  - Google Analytics 4 (G-XXXXXXXXXX)
  - Google Ads Conversion (AW-XXXXXXXXX)
  - Universal Analytics (UA-XXXXXXX-X)
  - Google Optimize (OPT-XXXXXXX)
  - Google AdSense (ca-pub-XXXXXXXXXXXXXXXX)
  - Location tracking (HTML head vs body)
  - Minimum length validation to prevent false positives

## Installation

### Via uvx (recommended)

Run directly from git without installation:

```bash
uvx --from git+https://github.com/orgoj/webmaster-domain-tool webmaster-domain-tool analyze example.com
```

Or shortened alias:

```bash
uvx --from git+https://github.com/orgoj/webmaster-domain-tool wdt analyze example.com
```

### Installation via uv

```bash
uv tool install git+https://github.com/orgoj/webmaster-domain-tool
```

### Installation from local project (for development)

```bash
git clone https://github.com/orgoj/webmaster-domain-tool.git
cd webmaster-domain-tool
uv sync
```

Run in dev mode:

```bash
uv run webmaster-domain-tool analyze example.com
```

## Usage

### CLI Usage (Command Line)

```bash
webmaster-domain-tool analyze example.com
```

Or shortened command:

```bash
wdt analyze example.com
```

### GUI Application (Desktop & Mobile) 📱

The tool now includes a **cross-platform graphical application** built with [Flet](https://flet.dev), providing a modern, user-friendly interface for desktop and mobile platforms.

**Supported Platforms:**
- 🖥️ **Desktop**: Windows, macOS, Linux
- 📱 **Mobile**: Android, iOS (via Flet packaging)

**Launch the GUI:**

```bash
# Run the GUI application
wdt-app

# Or if running from source
uv run wdt-app
```

**System Requirements for GUI:**

The GUI application requires the `libmpv` multimedia library to be installed on your system:

- **Ubuntu/Debian**: `sudo apt-get install libmpv-dev libmpv2`
- **Fedora/RHEL/CentOS**: `sudo dnf install mpv-libs`
- **Arch Linux**: `sudo pacman -S mpv`
- **macOS**: `brew install mpv`

**Ubuntu 24.04+ Compatibility (Official Flet Solution):**

Ubuntu 24.04 ships with libmpv2, but Flet requires libmpv.so.1. This is a known issue documented in [Flet's official documentation](https://flet.dev/docs/getting-started/).

**Official fix from Flet team:**

```bash
# Install libmpv packages
sudo apt update
sudo apt install libmpv-dev libmpv2

# Create compatibility symlink (official Flet workaround)
sudo ln -s /usr/lib/x86_64-linux-gnu/libmpv.so.2 /usr/lib/x86_64-linux-gnu/libmpv.so.1
```

This solution is officially documented by the Flet team and is the standard workaround until Flet releases native libmpv2 support.

**Note**: The CLI version (`wdt`) does not require these system dependencies - only the GUI (`wdt-app`) needs them.

**Features:**
- ✅ **Modern, responsive UI** that adapts to desktop and mobile screens
- ✅ **Interactive domain input** with validation
- ✅ **Configurable analysis options** via checkboxes (enable/disable specific checks)
- ✅ **Real-time progress** with status updates during analysis
- ✅ **Expandable result panels** organized by category (DNS, HTTP, SSL, Email, etc.)
- ✅ **Color-coded errors and warnings** for easy identification
- ✅ **All analyzers available** - same functionality as CLI
- ✅ **Uses existing configuration** from config files

**Why GUI?**
- Perfect for webmasters who prefer graphical interfaces
- Easier to visualize complex results with expandable sections
- Mobile-friendly for on-the-go domain analysis
- No need to remember CLI flags and options

**Building for Mobile:**

To build standalone apps for Android/iOS, use Flet's packaging tools:

```bash
# Android
flet build apk

# iOS
flet build ipa
```

See [Flet documentation](https://flet.dev/docs/guides/python/packaging-desktop-app) for detailed packaging instructions.

### Configuration

The tool supports configuration files for default settings:

```bash
# Create user config file
wdt create-config

# Config will be created in ~/.config/webmaster-domain-tool/config.toml
```

**Config loading order** (higher overrides lower):
1. Package default config
2. System-wide config (`/etc/webmaster-domain-tool/config.toml`)
3. User config (`~/.config/webmaster-domain-tool/config.toml`)
4. Home config (`~/.webmaster-domain-tool.toml`)
5. Local config (`.webmaster-domain-tool.toml` in current directory)
6. **CLI parameters always have precedence!**

**Custom config file:**

```bash
# Use custom config file
wdt analyze --config /path/to/config.toml example.com
wdt analyze -c myconfig.toml example.com
```

**Example configuration:**

```toml
[dns]
nameservers = ["1.1.1.1", "8.8.8.8"]
timeout = 5.0
check_dnssec = true
# Warn when www subdomain is not a CNAME (best practice for easier management)
warn_www_not_cname = false

[http]
timeout = 10.0
max_redirects = 10

[email]
dkim_selectors = ["default", "google", "k1"]
check_rbl = true
rbl_servers = ["zen.spamhaus.org", "bl.spamcop.net"]

# Site verification - predefined services (Google, Facebook, Pinterest, Bing, Yandex)
[[site_verification.services]]
name = "Google"
ids = ["abc123def456"]  # Add your IDs here or use --verify CLI arg

[[site_verification.services]]
name = "Facebook"
ids = []  # Use --verify Facebook:your-id or add here

[output]
color = true
verbosity = "normal"  # quiet, normal, verbose, debug

[analysis]
skip_dns = false
skip_email = false
skip_site_verification = false
```

### Options

#### Verbosity (output levels)

```bash
# Quiet mode - errors only
wdt analyze --quiet example.com
wdt analyze -q example.com

# Normal mode - default
wdt analyze example.com

# Verbose mode - detailed information
wdt analyze --verbose example.com
wdt analyze -v example.com

# Debug mode - very detailed output
wdt analyze --debug example.com
wdt analyze -d example.com
```

#### Skipping Certain Checks

**Default state:**
- ✅ DNS analysis - enabled
- ✅ HTTP/HTTPS analysis - enabled
- ✅ SSL/TLS analysis - enabled
- ✅ Email security (SPF, DKIM, DMARC) - enabled
- ✅ Security headers - enabled
- ✅ Site verification - enabled (auto-detects verification IDs from multiple services)
- ❌ RBL check - disabled (enable with `--check-rbl`)

```bash
# Skip DNS analysis
wdt analyze --skip-dns example.com

# Skip HTTP/HTTPS analysis
wdt analyze --skip-http example.com

# Skip SSL/TLS analysis
wdt analyze --skip-ssl example.com

# Skip email security (SPF, DKIM, DMARC)
wdt analyze --skip-email example.com

# Skip security headers
wdt analyze --skip-headers example.com

# Skip site verification analysis
wdt analyze --skip-site-verification example.com

# Combination - DNS and SSL only
wdt analyze --skip-http --skip-email --skip-headers --skip-site-verification example.com
```

#### DKIM Selectors

By default, common selectors are checked (default, google, k1, k2, selector1, selector2, dkim, mail, s1, s2).
You can specify custom selectors:

```bash
# Custom DKIM selectors
wdt analyze --dkim-selectors "selector1,selector2,custom" example.com
```

#### HTTP Settings

```bash
# Custom timeout (default: 10s)
wdt analyze --timeout 5 example.com
wdt analyze -t 5 example.com

# Maximum number of redirects (default: 10)
wdt analyze --max-redirects 5 example.com
```

#### DNS Settings

```bash
# Custom DNS servers
wdt analyze --nameservers "8.8.8.8,1.1.1.1" example.com

# Warn when www subdomain is not a CNAME (best practice)
wdt analyze --warn-www-not-cname example.com

# Disable warning (if enabled in config)
wdt analyze --no-warn-www-not-cname example.com
```

**Why is CNAME for www better?**

When www subdomain has a direct A record instead of CNAME:
- ❌ More complex management when changing hosting/CDN
- ❌ Must change A records in multiple places
- ❌ Clients with cached A records may experience downtime

With CNAME:
- ✅ Only need to change CNAME target in one place
- ✅ Automatic IP address updates
- ✅ Easier migration between providers

#### Google Services

**Site Verification** - Verify your domain for multiple services (Google, Facebook, Pinterest, Bing, Yandex):

```bash
# Check single verification ID
wdt analyze --verify Google:abc123def456 example.com

# Check multiple services (comma-separated)
wdt analyze --verify "Google:abc123,Facebook:fb-code" example.com

# Or use --verify multiple times
wdt analyze --verify Google:abc123 --verify Facebook:fb-code example.com
```

**Supported services (built-in):**
- **Google**: DNS TXT, HTML file (`google{id}.html`), Meta tag
- **Facebook**: DNS TXT, Meta tag
- **Pinterest**: Meta tag
- **Bing**: HTML file (`BingSiteAuth.xml`), Meta tag
- **Yandex**: HTML file (`yandex_{id}.html`), Meta tag

All services have **auto-detection enabled** by default - the tool will find verification IDs even if you don't specify them!

**Tracking Codes Detection** - Automatically detects Google tracking codes (GTM, GA4, GAds, UA, etc.):
- Runs automatically when site verification analysis is enabled
- No configuration needed - just run the analysis
- Shows which tracking codes are found and where (HTML head vs body)

```bash
# View site verification and tracking codes (runs by default)
wdt analyze example.com

# Skip site verification entirely
wdt analyze --skip-site-verification example.com
```

You can also configure verification IDs in the config file:

```toml
[[site_verification.services]]
name = "Google"
ids = ["abc123def456", "ghi789jkl012"]

[[site_verification.services]]
name = "Facebook"
ids = ["your-facebook-id"]
```

#### RBL (Blacklist) Check

**Disabled by default** - RBL checking is disabled by default as it may slow down analysis.

```bash
# Enable RBL check
wdt analyze --check-rbl example.com

# Disable RBL check (if enabled in config)
wdt analyze --no-check-rbl example.com
```

When enabled, these RBL servers are checked:
- Spamhaus ZEN (`zen.spamhaus.org`)
- SpamCop (`bl.spamcop.net`)
- Barracuda Central (`b.barracudacentral.org`)
- SORBS (`dnsbl.sorbs.net`)

Custom RBL servers can be configured in the config file.

#### Output Settings

```bash
# Disable colored output
wdt analyze --no-color example.com
```

### Complex Usage Examples

```bash
# Quick check with custom DNS servers
wdt analyze --nameservers "1.1.1.1,8.8.8.8" example.com

# Detailed analysis with debug output
wdt analyze --debug --timeout 15 example.com

# Email security only with custom DKIM selectors
wdt analyze --skip-dns --skip-http --skip-ssl --skip-headers \
    --dkim-selectors "google,default,mail" example.com

# Verbose output without colors (for logging)
wdt analyze -v --no-color example.com > domain-report.txt

# Quick check without email security
wdt analyze --skip-email --timeout 5 example.com
```

## Output

The tool displays a clear colored output divided into sections:

### 1. DNS Records
- Table of all DNS records for domain and www.domain
- TTL values
- **DNSSEC status** (enabled/disabled, validation)
- Warnings for missing or problematic records

### 2. HTTP/HTTPS Analysis
- Redirect tree for each URL variant
- Status codes with colors (green 200, yellow 3xx, red 4xx/5xx)
- Response times
- Insecure redirect warnings

### 3. SSL/TLS Certificates
- Certificate details (subject, issuer)
- Validity and expiration (colored by urgency)
- SAN (Subject Alternative Names)
- Supported TLS protocols
- Warnings for expired or soon-to-expire certificates

### 4. Email Security
- ✅/✗ status for SPF, DKIM, DMARC
- Record details
- Validation and recommendations
- Warnings for weak configurations

### 5. Security Headers
- Security score (0-100)
- Table of all security headers
- Recommendations for missing headers
- Detailed warnings for each header

### 6. Google Services
- **Site Verification status** for each configured ID
  - ✅/✗ status
  - List of verification methods found (DNS, file, meta tag)
- **Tracking Codes table**
  - Type (GTM, GA4, GAds, etc.)
  - Code ID
  - Location (HTML head or body)
- Warnings for HTML fetch errors

### 7. RBL (Blacklist) Check
- Table of checked IP addresses
- Status of each IP (CLEAN / LISTED)
- List of blacklists where IP is found
- Warnings for found blacklists

### 8. Summary
- Total count of errors and warnings
- **Detailed list of all errors/warnings with categories**
- Each error/warning shown with precise description and category (DNS, HTTP, SSL, Email, Google, etc.)
- 100% accurate counting - count always matches displayed messages

## Requirements

- Python 3.10+
- Dependencies (installed automatically):
  - `dnspython` - DNS queries and DNSSEC validation
  - `httpx` - HTTP requests
  - `cryptography` - SSL/TLS analysis
  - `rich` - colored terminal output
  - `typer` - CLI framework
  - `pydantic` - data validation and settings
  - `tomli` - TOML config parser (Python <3.11)

## Development

### Development Environment Setup

```bash
git clone https://github.com/orgoj/webmaster-domain-tool.git
cd webmaster-domain-tool
uv sync --dev
```

### Running Tests

```bash
uv run pytest
```

### Code Quality

```bash
# Black formatting
uv run black src/

# Ruff linting
uv run ruff check src/

# Type checking
uv run mypy src/
```

## Project Structure

```
webmaster-domain-tool/
├── src/
│   └── webmaster_domain_tool/
│       ├── __init__.py
│       ├── cli.py                 # CLI interface (Typer)
│       ├── config.py              # Config management
│       ├── default_config.toml    # Default configuration
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── dns_analyzer.py        # DNS analysis + DNSSEC
│       │   ├── http_analyzer.py       # HTTP/HTTPS analysis
│       │   ├── ssl_analyzer.py        # SSL/TLS analysis
│       │   ├── email_security.py      # SPF, DKIM, DMARC
│       │   ├── security_headers.py    # Security headers
│       │   ├── site_verification_analyzer.py  # Universal site verification (Google, Facebook, etc.) + tracking codes
│       │   └── rbl_checker.py         # RBL blacklist check
│       └── utils/
│           ├── __init__.py
│           ├── logger.py       # Logging setup
│           └── output.py       # Rich output formatting
├── tests/
├── pyproject.toml
├── LICENSE
└── README.md
```

## Roadmap / Future Improvements

- [x] **DNSSEC validation** ✅
- [x] **RBL (blacklist) check** ✅
- [x] **Config file for default settings** ✅
- [ ] Export to JSON/YAML/HTML formats
- [ ] robots.txt / sitemap.xml checking
- [ ] Batch analysis of multiple domains
- [ ] Continuous monitoring with alerting
- [ ] Web UI / API
- [ ] Plugin system for custom analyzers

## Contributing

Pull requests are welcome! For major changes, please open an issue first for discussion.

## License

MIT

## Author

Webmaster Tools

## Support

For bugs and feature requests, use [GitHub Issues](https://github.com/orgoj/webmaster-domain-tool/issues).
