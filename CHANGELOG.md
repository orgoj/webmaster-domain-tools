# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Major Dependency Updates - All Packages Updated to Latest Stable Versions**
  - Updated all dependencies to eliminate technical debt
  - **Core dependencies:**
    - dnspython: 2.6.1 → 2.8.0
    - httpx: 0.27.0 → 0.28.1
    - cryptography: 42.0.0 → 46.0.3 (major security updates)
    - rich: 13.7.0 → 14.2.0
    - typer: 0.12.0 → 0.20.0
    - pydantic: 2.7.0 → 2.12.4
    - pydantic-settings: 2.2.0 → 2.12.0
    - tomli: 2.0.0 → 2.3.0
    - python-whois: 0.9.0 → 0.9.6
    - flet: 0.28.0 → 0.28.3
    - flet-desktop: 0.28.0 → 0.28.3
  - **Dev dependencies:**
    - pytest: 8.0.0 → 9.0.1
    - pytest-asyncio: 0.23.0 → 1.3.0
    - black: 24.0.0 → 25.11.0 (new 2025 stable style)
    - ruff: 0.3.0 → 0.14.1
    - mypy: 1.9.0 → 1.18.2
  - Removed duplicate dependency entries (pytest-cov, pre-commit) that conflicted between sections
  - All packages tested and working with latest versions

### Added
- **Enhanced WHOIS Information Display**
  - Added registrant email field extraction from WHOIS data
  - Added administrator contact (admin-c) display for .cz domains
  - Special parser for .cz domains to correctly extract registrar from domain section (not contact section)
  - Displays admin-c handle along with admin name and email when available
  - Both CLI and GUI updated to show new contact information

### Fixed
- **GUI Application Launch Issue**
  - Fixed `wdt-app` failing to launch with "No module named pip" error
  - Added explicit `flet-desktop` dependency to prevent auto-installation issues
  - The flet package was trying to auto-install flet-desktop using pip, which isn't available in uv virtual environments
  - Now flet-desktop is installed directly by uv during package installation
  - Documented system requirements for GUI (libmpv library) in README
  - Added Ubuntu 24.04+ compatibility workaround for libmpv.so.1/libmpv.so.2 version mismatch

- **WHOIS Registrar Display for .cz Domains**
  - Fixed incorrect registrar extraction for .cz domains
  - Previously showed registrar from contact records instead of domain record
  - Now correctly parses raw WHOIS text to extract domain-level registrar
  - Example: sahmgastro.cz now correctly shows "REG-ZONER" instead of "REG-MOJEID"

### Added
- **Cross-Platform GUI Application (Desktop & Mobile)**
  - Modern graphical interface built with Flet framework
  - Supports Windows, macOS, Linux desktop platforms
  - Mobile support for Android and iOS (via Flet packaging)
  - Responsive UI that adapts to different screen sizes
  - Interactive domain input with real-time validation
  - Configurable analysis options via checkboxes (enable/disable specific checks)
  - Real-time progress indicator with status updates
  - Expandable result panels organized by category (DNS, HTTP, SSL, Email, etc.)
  - Color-coded errors and warnings for easy identification
  - All CLI analyzers available in GUI
  - Uses existing configuration from config files
  - Launch command: `wdt-app`
  - Perfect for users who prefer graphical interfaces over command-line

### Changed
- **Major Code Refactoring: Improved Architecture and Reduced Duplication**
  - Introduced `BaseAnalyzer` abstract class for all analyzers, ensuring consistent interface
  - Introduced `BaseAnalysisResult` dataclass for all analysis results
  - Centralized DNS resolver creation in `analyzers/dns_utils.py` (eliminates ~50 lines of duplicated code)
  - Centralized HTTP utilities in `analyzers/http_utils.py` for consistent error handling
  - All 13 analyzers now inherit from `BaseAnalyzer[TResult]` with proper type safety
  - Refactored analyzer results to inherit from `BaseAnalysisResult`, removing duplicate `domain`, `errors`, and `warnings` fields
  - Improved code maintainability and consistency across all analyzers
  - No functional changes - all features work identically

### Added
- **WHOIS Information Analyzer**
  - Domain registration details (registrar, creation/expiration dates)
  - Days until expiration with warnings (30/60 day thresholds)
  - Name server listing
  - Registrant organization (when available)

- **Comprehensive Favicon Analysis**
  - Multi-format support (PNG, ICO, JPEG, GIF, SVG)
  - Multi-layer ICO file detection with all embedded resolutions
  - Real dimension extraction from image data (not just HTML attributes)
  - All standard locations: HTML link tags, Apple Touch Icons (all sizes), Safari mask-icon, Microsoft Tile, Web App Manifest
  - Source tracking (HTML vs default path vs manifest)
  - File size detection
  - Purpose attribute for PWA icons
  - Deduplication (HTML sources take precedence)
  - Best practice warnings

- **SEO Files Analysis**
  - robots.txt parser (User-Agent, Disallow/Allow, Sitemap, Crawl-delay)
  - llms.txt detection (AI crawler standard)
  - sitemap.xml parser with XML validation, URL counting, and index support
  - Size warnings for large sitemaps (>50,000 URLs)

- **Advanced Email Security**
  - BIMI (Brand Indicators for Message Identification) record detection
  - MTA-STS (Mail Transfer Agent Strict Transport Security) policy validation
  - TLS-RPT (TLS Reporting) endpoint validation

- **CDN Detection**
  - Automatic CDN provider detection (12+ providers)
  - Header-based identification (Cloudflare, Fastly, Akamai, CloudFront, etc.)
  - CNAME-based detection
  - Confidence scoring (high/medium/low)

- **Multi-Platform Site Verification**
  - Extended beyond Google to support Facebook, Pinterest, Bing, Yandex
  - Auto-detection of verification IDs from DNS and HTML
  - Only displays services with actual results

- **SSL Certificate Issuer Display**
  - Certificate Authority name shown in normal output mode
  - Helps identify certificate provider at a glance

### Changed
- Improved Site Verification output to hide empty services (Pinterest, Bing, Yandex when not configured)
- Merged Email Security and Advanced Email Security into single unified section
- Moved CDN Detection output between DNS and HTTP sections for better logical flow
- Enhanced sitemap output to show URL and count on same line
- Improved favicon output to show source and actual dimensions

### Fixed
- Tracking code regex patterns now require minimum lengths to prevent false positives
  - GTM: min 7 chars (GTM-XXXXXXX)
  - GA4: 8-12 chars (G-XXXXXXXXXX)
  - Google Ads: 9-12 digits (AW-XXXXXXXXX)
  - Google AdSense: exactly 16 digits (ca-pub-XXXXXXXXXXXXXXXX)
- Favicon warning logic only warns about default paths when HTML has favicons defined
- SSL issuer display logic now checks cert.issuer instead of cert.status
- Multi-layer ICO files now show all embedded dimensions instead of just first layer
- PTR record mismatch warning now shows actual IP address it resolves to instead of repeating original IP

## [0.1.0] - 2024-XX-XX

### Added
- Initial release
- DNS analysis with DNSSEC validation
- HTTP/HTTPS redirect analysis
- SSL/TLS certificate validation
- Email security (SPF, DKIM, DMARC)
- RBL blacklist checking
- Security headers analysis
- Google Site Verification

[Unreleased]: https://github.com/orgoj/webmaster-domain-tool/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/orgoj/webmaster-domain-tool/releases/tag/v0.1.0
