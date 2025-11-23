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

### Domain Configuration Validator
- ✅ **Multi-profile infrastructure validation**
  - IP address validation (IPv4/IPv6) with flexible matching modes
  - CDN provider detection and validation
  - Verification file checking (for ownership proof)
  - Email security validation (SPF, DKIM, DMARC requirements)
  - Multi-profile support for different server configurations
- ✅ **Security-hardened implementation**
  - SSRF protection (rejects IP addresses, localhost, private networks)
  - Path traversal prevention for verification paths
  - Response size limits (1MB max) to prevent resource exhaustion
  - Infrastructure detail hiding to prevent information disclosure
- ✅ **Flexible match modes**
  - `any` mode - at least one expected value must match
  - `all` mode - all expected values must match
  - Per-check configuration (IPs, CDN, email security)
- ✅ **Configurable strict/warning mode**
  - Strict mode - failures are errors
  - Warning mode - failures are warnings only

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

# Launch with specific profile and domain pre-filled
wdt-app --config myprofile example.com

# Short form
wdt-app -c myprofile example.com
```

**CLI Arguments:**
- `--config` / `-c`: Configuration profile name to use (from saved profiles)
- `domain`: Domain to pre-fill in the input field

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
- ✅ **Configuration profiles** - save, load, and switch between named configurations
- ✅ **Visual configuration editor** with tabbed interface for all settings
- ✅ **Client-side storage** - profiles persist across sessions
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

#### Configuration Profiles (GUI)

The GUI supports **named configuration profiles** for managing different analysis scenarios:

**Managing Profiles:**
1. **Select profile** from dropdown in header (default profiles: "default")
2. **Edit settings** via ⚙️ Settings button - opens tabbed configuration editor
3. **Save current config** as new profile via 💾 Save button
4. **Delete profiles** via 🗑️ Delete button (cannot delete "default")

**Configuration Editor Tabs:**
- **DNS**: Nameservers, timeout, DNSSEC checking, www CNAME warnings
- **HTTP**: Timeout, max redirects, custom user agent
- **SSL/TLS**: Certificate expiry warning thresholds
- **Email**: DKIM selectors, RBL checking, RBL servers
- **Advanced Email**: BIMI, MTA-STS, TLS-RPT options
- **Security Headers**: Individual header checks (HSTS, CSP, X-Frame-Options, etc.)
- **SEO**: robots.txt, llms.txt, sitemap.xml checks
- **Favicon**: HTML parsing, default path checking
- **WHOIS**: Domain expiry warning thresholds
- **Analysis Options**: Enable/disable individual analyzers
- **Output**: CLI verbosity settings (CLI only)

**Profile Storage:**
- Profiles stored in browser client storage (persistent across sessions)
- **Automatically restores your last used profile** when you reopen the app
- JSON format with Pydantic validation
- `default` profile auto-created on first run
- All CLI configuration options available in GUI

**Example Use Cases:**
- `fast` - Minimal checks for quick scans (skip heavy analyzers)
- `full` - All checks enabled for comprehensive analysis
- `security` - Focus on SSL, headers, and security checks only
- `email` - Detailed email configuration with custom DKIM selectors
- `production` - Production-ready settings with strict thresholds
- `testing` - Relaxed settings for development domains

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
# Global output settings
[global]
color = true
verbosity = "normal"  # quiet, normal, verbose, debug

# Per-analyzer configuration
# Each analyzer has its own section with isolated settings

[dns]
enabled = true
timeout = 5.0
nameservers = ["1.1.1.1", "8.8.8.8"]
check_dnssec = true
# Warn when www subdomain is not a CNAME (best practice)
warn_www_not_cname = false

[whois]
enabled = true
timeout = 10.0
expiry_warning_days = 30

[http]
enabled = true
timeout = 10.0
max_redirects = 10
user_agent = "webmaster-domain-tool/1.0"

[ssl]
enabled = true
timeout = 10.0
check_tls_versions = true
expiry_warning_days = 30
expiry_critical_days = 7

[email]
enabled = true
timeout = 10.0
check_spf = true
check_dkim = true
check_dmarc = true
check_bimi = true
check_mta_sts = true
check_tls_rpt = true
dkim_selectors = ["default", "google", "k1", "k2"]

[headers]
enabled = true
timeout = 10.0
# Individual header checks can be disabled
check_hsts = true
check_csp = true
check_x_frame_options = true
# ... more headers ...

[verification]
enabled = true
timeout = 10.0
check_google = true
check_facebook = true
check_pinterest = true
check_bing = true
check_yandex = true

[rbl]
enabled = false  # Disabled by default (can be slow)
timeout = 5.0
check_a_records = true
check_mx_records = true
rbl_servers = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net"
]

[cdn]
enabled = true
check_headers = true
check_cname = true

[seo]
enabled = true
timeout = 10.0
check_robots = true
check_sitemap = true
check_llms_txt = true

[favicon]
enabled = true
timeout = 10.0
check_html = true
check_default_paths = true
check_manifest = true

[domain-validator]
enabled = true
active_profile = ""  # Profile to use (empty = skip)
strict_mode = true  # Errors vs warnings for failures
hide_expected_values = true  # Security: hide infrastructure details

# Example: Web server profile
[domain-validator.profiles.web-server]
name = "Production Web Server"
expected_ips = ["203.0.113.10"]
verification_path = "/.well-known/verify.txt"
spf_includes = ["include:_spf.example.com"]
dkim_selectors = ["default"]
```

### Options

#### Output Formats

```bash
# CLI output (default) - colored terminal output
wdt analyze example.com
wdt analyze --format cli example.com

# JSON output - machine-readable format
wdt analyze --format json example.com
wdt analyze -f json example.com > output.json

# JSON Lines output - for bulk domain analysis (one JSON object per line)
wdt analyze --format jsonlines example.com
```

#### Bulk Domain Analysis

Analyze multiple domains from a file or stdin using **JSON Lines format** (one JSON object per domain per line):

```bash
# From a file (one domain per line)
wdt analyze --domain-file domains.txt --format jsonlines

# From stdin
cat domains.txt | wdt analyze --domain-file - --format jsonlines
echo "example.com" | wdt analyze --domain-file - --format jsonlines

# With custom configuration
wdt analyze --domain-file domains.txt --config custom.toml --format jsonlines

# Run specific analyzers only
wdt analyze --domain-file domains.txt --only html --format jsonlines

# Skip certain analyzers
wdt analyze --domain-file domains.txt --skip dns --skip whois --format jsonlines

# Process and filter with jq
cat domains.txt | wdt analyze --domain-file - --format jsonlines | \
  jq 'select(.summary.total_errors > 0)'

# Extract specific data (e.g., all domains with SSL issues)
wdt analyze --domain-file domains.txt --only ssl --format jsonlines | \
  jq 'select(.summary.total_warnings > 0) | {domain, warnings: .summary.warnings}'
```

**Domain file format:**
```
example.com
github.com
google.com
```

**JSON Lines output format:**
- Each line is a complete JSON object for one domain
- Streaming-friendly for large domain lists
- Easy to process with tools like `jq`, `grep`, or custom scripts
- Each domain analyzed independently (one failure doesn't stop others)

**Example output:**
```json
{"domain": "example.com", "analyzers": {...}, "summary": {"total_errors": 2, "total_warnings": 4, ...}}
{"domain": "github.com", "analyzers": {...}, "summary": {"total_errors": 0, "total_warnings": 3, ...}}
```

#### Verbosity (output levels)

```bash
# Quiet mode - minimal output
wdt analyze --verbosity quiet example.com
wdt analyze -v quiet example.com

# Normal mode - default
wdt analyze example.com
wdt analyze --verbosity normal example.com

# Verbose mode - detailed information
wdt analyze --verbosity verbose example.com
wdt analyze -v verbose example.com

# Debug mode - maximum detail with debug logs
wdt analyze --verbosity debug example.com
wdt analyze -v debug example.com
```

#### Skipping Certain Checks

**All analyzers are enabled by default.** Use the unified `--skip` parameter to disable specific analyzers:

**Available analyzers:**
- `dns` - DNS records and DNSSEC validation
- `whois` - Domain registration information
- `http` - HTTP/HTTPS redirect analysis
- `ssl` - SSL/TLS certificate analysis
- `email` - Email security (SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT)
- `headers` - Security headers checking
- `verification` - Site verification and tracking codes
- `rbl` - RBL blacklist checking
- `cdn` - CDN detection
- `seo` - robots.txt, sitemap.xml, llms.txt
- `favicon` - Favicon analysis
- `html` - HTML validation, SEO, and accessibility
- `domain-validator` - Domain configuration validation against infrastructure profiles

```bash
# Skip single analyzer
wdt analyze --skip dns example.com

# Skip multiple analyzers
wdt analyze --skip dns --skip whois example.com

# List all available analyzers
wdt list-analyzers

# Run only DNS and HTTP (skip everything else)
wdt analyze --skip whois --skip ssl --skip email \
    --skip headers --skip verification \
    --skip rbl --skip cdn --skip seo --skip favicon --skip html \
    example.com
```

#### DKIM Selectors

By default, common selectors are checked (default, google, k1, k2, selector1, selector2, dkim, mail, s1, s2).
You can specify custom selectors in your config file:

```toml
[email]
dkim_selectors = ["selector1", "selector2", "custom", "mailgun"]
```

#### HTTP Settings

HTTP analyzer settings are configured via the config file:

```toml
[http]
enabled = true
timeout = 5.0           # Connection timeout in seconds (default: 10.0)
max_redirects = 5       # Maximum redirects to follow (default: 10)
user_agent = "webmaster-domain-tool/1.0"
```

#### DNS Settings

DNS analyzer settings are configured via the config file:

```toml
[dns]
enabled = true
nameservers = ["8.8.8.8", "1.1.1.1"]  # Custom DNS servers
timeout = 5.0
check_dnssec = true
# Warn when www subdomain is not a CNAME (best practice)
warn_www_not_cname = true
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

#### Site Verification & Tracking Codes

**Auto-Detection** - The tool automatically detects verification codes for multiple services:

**Supported services (built-in):**
- **Google**: DNS TXT, HTML file (`google{id}.html`), Meta tag
- **Facebook**: DNS TXT, Meta tag
- **Pinterest**: Meta tag
- **Bing**: HTML file (`BingSiteAuth.xml`), Meta tag
- **Yandex**: HTML file (`yandex_{id}.html`), Meta tag

All services have **auto-detection enabled** by default - the tool will find verification IDs automatically!

**Tracking Codes Detection** - Automatically detects Google tracking codes (GTM, GA4, GAds, UA, etc.):
- Runs automatically when site verification analysis is enabled
- No configuration needed - just run the analysis
- Shows which tracking codes are found and where (HTML head vs body)

```bash
# View site verification and tracking codes (runs by default)
wdt analyze example.com

# Skip site verification entirely
wdt analyze --skip verification example.com
```

You can configure specific verification IDs to check in the config file:

```toml
[verification]
enabled = true
check_google = true
check_facebook = true
check_pinterest = true
check_bing = true
check_yandex = true

# Optional: specify verification IDs to verify (auto-detection still works)
[[verification.services]]
name = "Google"
ids = ["abc123def456", "ghi789jkl012"]

[[verification.services]]
name = "Facebook"
ids = ["your-facebook-id"]
```

#### RBL (Blacklist) Check

**Disabled by default** - RBL checking is disabled by default as it may slow down analysis.

Enable RBL checking in your config file:

```toml
[rbl]
enabled = true          # Enable RBL checking (default: false)
timeout = 5.0
check_a_records = true  # Check A record IPs
check_mx_records = true # Check MX server IPs
# Customize RBL servers to check
rbl_servers = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net"
]
```

When enabled, these RBL servers are checked by default:
- Spamhaus ZEN (`zen.spamhaus.org`)
- SpamCop (`bl.spamcop.net`)
- Barracuda Central (`b.barracudacentral.org`)
- SORBS (`dnsbl.sorbs.net`)

#### Output Settings

```bash
# Disable colored output
wdt analyze --no-color example.com
```

### Domain Configuration Validation

Validate that a domain is correctly configured for your infrastructure:

```bash
# Configure validation profile in config file
cat > ~/.webmaster-domain-tool.toml <<EOF
[domain-validator]
enabled = true
active_profile = "my-server"

[domain-validator.profiles.my-server]
name = "Production Server"
expected_ips = ["203.0.113.10"]
spf_includes = ["include:_spf.google.com"]
dkim_selectors = ["google"]
EOF

# Run validation
wdt analyze example.com
```

**Profile Options:**
- `expected_ips` / `expected_ipv6` - Expected IP addresses
- `expected_cdn` - Expected CDN provider (Cloudflare, Fastly, etc.)
- `verification_path` - File to check for ownership proof (e.g., `/.well-known/verify.txt`)
- `verification_content` - Expected file content (optional)
- `spf_includes` - Required SPF includes (e.g., `["include:_spf.google.com"]`)
- `spf_ips` - Required SPF IP addresses
- `dkim_selectors` - Required DKIM selectors (e.g., `["google", "default"]`)
- `dmarc_policy` - Required DMARC policy (e.g., `"quarantine"`)
- Match modes: `any` (at least one) or `all` (all must match)

**Security Features:**
- SSRF protection (rejects IP addresses, localhost, private networks in domain field)
- Path traversal protection (validates verification paths)
- Response size limits (1MB max to prevent resource exhaustion)
- Infrastructure detail hiding (prevents information disclosure when `hide_expected_values = true`)

**Example: Multiple Profiles**

```toml
[domain-validator]
enabled = true
active_profile = "cloudflare-prod"
strict_mode = true  # Errors vs warnings for failures
hide_expected_values = true  # Security: hide infrastructure details

# Cloudflare production server
[domain-validator.profiles.cloudflare-prod]
name = "Cloudflare Production"
expected_cdn = "Cloudflare"
spf_includes = ["include:_spf.google.com"]
dkim_selectors = ["google"]
dmarc_policy = "quarantine"

# Direct hosting on VPS
[domain-validator.profiles.vps-server]
name = "VPS Server"
expected_ips = ["203.0.113.10"]
expected_ipv6 = ["2001:db8::1"]
verification_path = "/.well-known/ownership.txt"
verification_content = "my-secret-token-123"
spf_ips = ["203.0.113.10"]
dkim_selectors = ["default"]

# Testing environment
[domain-validator.profiles.testing]
name = "Test Environment"
expected_ips = ["198.51.100.5"]
strict_mode = false  # Use warnings instead of errors
```

### Complex Usage Examples

```bash
# Detailed analysis with debug output
wdt analyze --verbosity debug example.com

# Email and security checks only
wdt analyze --skip dns --skip whois --skip http --skip ssl \
    --skip cdn --skip seo --skip favicon --skip html example.com

# JSON output for automated processing
wdt analyze --format json --verbosity verbose example.com > report.json

# Quick check (skip slow analyzers)
wdt analyze --skip whois --skip rbl example.com

# List all available analyzers and their categories
wdt list-analyzers
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
│       ├── cli.py                      # CLI interface (Typer)
│       ├── default_config.toml         # Default configuration
│       ├── core/
│       │   ├── __init__.py
│       │   ├── registry.py             # Analyzer registry with auto-discovery
│       │   └── config_manager.py       # Multi-layer config management
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── protocol.py             # Protocol definitions (AnalyzerPlugin)
│       │   ├── dns_analyzer.py         # DNS analysis + DNSSEC
│       │   ├── whois_analyzer.py       # WHOIS information
│       │   ├── http_analyzer.py        # HTTP/HTTPS redirect analysis
│       │   ├── ssl_analyzer.py         # SSL/TLS certificate analysis
│       │   ├── email_security.py       # SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT
│       │   ├── security_headers.py     # Security headers checking
│       │   ├── site_verification_analyzer.py  # Site verification + tracking codes
│       │   ├── rbl_checker.py          # RBL blacklist checking
│       │   ├── cdn_detector.py         # CDN provider detection
│       │   ├── seo_files_analyzer.py   # robots.txt, sitemap.xml, llms.txt
│       │   └── favicon_analyzer.py     # Favicon detection and analysis
│       ├── renderers/
│       │   ├── __init__.py
│       │   ├── base.py                 # Base renderer protocol
│       │   ├── cli_renderer.py         # CLI output with Rich
│       │   └── json_renderer.py        # JSON export renderer
│       └── utils/
│           ├── __init__.py
│           └── logger.py               # Logging setup
├── tests/
├── pyproject.toml
├── LICENSE
├── README.md
├── CLAUDE.md                           # AI assistant guide
└── CHANGELOG.md                        # Version history
```

## Roadmap / Future Improvements

**Completed:**
- [x] **DNSSEC validation** ✅
- [x] **RBL (blacklist) check** ✅
- [x] **Config file for default settings** ✅
- [x] **robots.txt / sitemap.xml / llms.txt checking** ✅
- [x] **JSON export format** ✅
- [x] **Modular plugin system for analyzers** ✅
- [x] **GUI application (Flet-based)** ✅
- [x] **CDN detection** ✅
- [x] **Favicon analysis** ✅
- [x] **Site verification (multiple platforms)** ✅

**Planned:**
- [ ] HTML/YAML export formats
- [ ] Batch analysis of multiple domains
- [ ] Continuous monitoring with alerting
- [ ] Web UI / REST API
- [ ] Custom analyzer plugins from external packages

## FAQ / Troubleshooting

### Installation Issues

**Q: I get "command not found: wdt" after installation**

A: Make sure `uv` installed the package correctly and the binary is in your PATH:
```bash
# Verify installation
uv pip list | grep webmaster-domain-tool

# Try running with full path
uv run wdt --help

# Or reinstall
uv pip install --force-reinstall webmaster-domain-tool
```

**Q: GUI won't start on Ubuntu 24.04**

A: The GUI requires libmpv. Install it:
```bash
sudo apt-get update
sudo apt-get install libmpv-dev libmpv2
```

### Analysis Issues

**Q: DNS queries are timing out**

A: Try these solutions:
1. **Use different nameservers** - Create a config file and specify reliable DNS servers:
   ```toml
   [dns]
   nameservers = ["1.1.1.1", "8.8.8.8"]
   timeout = 10.0
   ```

2. **Skip DNSSEC validation** if it's causing issues:
   ```toml
   [dns]
   check_dnssec = false
   ```

3. **Check firewall** - Ensure outbound DNS (port 53) is allowed

**Q: "NXDOMAIN" error for valid domain**

A: This means the domain doesn't exist in DNS. Check:
- Domain spelling (typos?)
- Domain actually exists (try `nslookup domain.com`)
- DNS propagation (newly registered domains take time)

**Q: SSL/TLS analysis fails**

A: Common causes:
- **Port 443 blocked** - Check firewall
- **Invalid certificate** - Tool correctly reports the issue
- **Network timeout** - Increase timeout in config:
  ```toml
  [ssl]
  timeout = 15.0
  ```

**Q: WHOIS lookup is very slow**

A: WHOIS queries can be slow. You can:
- **Skip WHOIS** temporarily: `wdt analyze example.com --skip whois`
- **Increase timeout** in config:
  ```toml
  [whois]
  timeout = 30.0
  ```

### Performance Issues

**Q: Analysis takes too long**

A: Optimize performance:
1. **Skip unnecessary analyzers**:
   ```bash
   wdt analyze example.com --skip whois --skip rbl --skip favicon
   ```

2. **Disable checks in config**:
   ```toml
   [rbl]
   enabled = false

   [favicon]
   enabled = false
   ```

3. **Use quiet mode** for faster output:
   ```bash
   wdt analyze example.com --verbosity quiet
   ```

**Q: Can I run analyzers in parallel?**

A: Parallel execution is planned but not yet implemented. Current execution is sequential due to dependency resolution (e.g., SSL depends on HTTP).

### Configuration Issues

**Q: Where is the config file located?**

A: Config files are loaded in this order (last wins):
1. `/etc/webmaster-domain-tool/config.toml` (system-wide)
2. `~/.config/webmaster-domain-tool/config.toml` (user)
3. `~/.webmaster-domain-tool.toml` (home)
4. `./.webmaster-domain-tool.toml` (project)

Create a default config:
```bash
wdt create-config
```

**Q: My config changes aren't being applied**

A: Check:
1. **File format** - Ensure valid TOML syntax
2. **Section names** - Must match analyzer IDs (`[dns]`, `[ssl]`, etc.)
3. **Location** - Use local config (`./.webmaster-domain-tool.toml`) for project-specific settings
4. **Validation** - Run with `--verbosity debug` to see config loading

Example valid config:
```toml
[global]
verbosity = "verbose"
color = true

[dns]
timeout = 10.0
check_dnssec = true
nameservers = ["1.1.1.1", "8.8.8.8"]

[ssl]
timeout = 15.0
expiry_warning_days = 30
```

### Output Issues

**Q: Output has weird characters/colors**

A: Your terminal might not support colors. Disable them:
```bash
# Via command line
wdt analyze example.com --no-color

# Via config
[global]
color = false
```

**Q: How do I save output to a file?**

A: Use shell redirection or JSON format:
```bash
# Save CLI output
wdt analyze example.com > output.txt

# Save as JSON
wdt analyze example.com --format json > output.json
```

### Common Errors

**Q: "Unknown analyzer: xyz"**

A: You specified an invalid analyzer ID in `--skip`. Valid IDs are:
```bash
wdt list-analyzers
```

**Q: "Circular dependency detected"**

A: This shouldn't happen in normal usage. If it does:
1. Report it as a bug
2. Try skipping some analyzers to isolate the issue

**Q: "Protocol validation failed"**

A: A custom analyzer isn't implementing the required protocol. If using built-in analyzers, this is a bug - please report it.

### Network/Firewall Issues

**Q: Tool works for some domains but not others**

A: Possible causes:
- **Geo-blocking** - Domain blocks your region
- **Rate limiting** - Too many requests
- **Firewall** - Corporate firewall blocking analysis
- **Domain configuration** - Domain actually has issues

**Q: Getting connection refused errors**

A: Check:
- **Firewall** - Outbound ports 53 (DNS), 80 (HTTP), 443 (HTTPS)
- **Proxy** - Tool doesn't support proxies yet
- **VPN** - Try without VPN if having issues

### Reporting Bugs

**Q: I found a bug, how do I report it?**

A: Include this information:
1. **Version**: `wdt version`
2. **Command**: Exact command you ran
3. **Error**: Complete error message
4. **Config**: Your config file (remove sensitive data)
5. **Environment**: OS, Python version (`python --version`)

Example bug report:
```
Version: 1.0.0
Command: wdt analyze example.com --skip whois
Error: [paste error here]
OS: Ubuntu 22.04
Python: 3.11.5
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

Pull requests are welcome! For major changes, please open an issue first for discussion.

## License

MIT

## Author

Webmaster Tools

## Support

For bugs and feature requests, use [GitHub Issues](https://github.com/orgoj/webmaster-domain-tool/issues).
