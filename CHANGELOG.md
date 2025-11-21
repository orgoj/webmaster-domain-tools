# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-01-21

### Added

- **Bulk Domain Analysis**
  - New `--domain-file` parameter for analyzing multiple domains from file or stdin
  - Support for stdin input via `--domain-file -`
  - JSON Lines output format (`--format jsonlines`) for streaming bulk results
  - Each domain outputs one JSON object per line (JSON Lines standard)
  - Domains analyzed independently - one failure doesn't stop processing
  - Easy to process with tools like `jq`, `grep`, or custom scripts
  - Compatible with all existing analyzers and configuration options
  - Examples:
    - `wdt analyze --domain-file domains.txt --format jsonlines`
    - `cat domains.txt | wdt analyze --domain-file - --format jsonlines`
    - `wdt analyze --domain-file domains.txt --only html --format jsonlines`

### Changed

- CLI `analyze` command now accepts optional `domain` argument when `--domain-file` is used
- Added `BulkJSONLinesRenderer` for efficient streaming output
- Refactored analyzer execution into reusable helper functions

## [1.0.0] - 2025-01-20

**BREAKING CHANGES - MAJOR ARCHITECTURE REFACTORING**

This is a complete rewrite of the internal architecture. While most user-facing functionality remains the same, there are breaking changes in CLI parameters and configuration file structure.

### ⚠️ Migration Guide

**CLI Changes:**
- `--skip-dns --skip-whois` → `--skip dns --skip whois` (unified parameter)
- `--quiet` / `-q` → `--verbosity quiet` / `-v quiet`
- `--verbose` / `-v` → `--verbosity verbose` / `-v verbose`
- `--debug` / `-d` → `--verbosity debug` / `-v debug`
- New: `--format cli|json` for output format selection
- New: `wdt list-analyzers` command to see all available analyzers

**Configuration Changes:**
- Config structure changed to per-analyzer sections
- Each analyzer has isolated `[analyzer-name]` section in TOML
- `enabled = true/false` field added to each analyzer section
- Old flat config structure no longer supported
- See README for complete new configuration example

**API/Import Changes (for developers):**
- Deleted: `core/analyzer.py` (old monolithic orchestration)
- Deleted: `utils/output.py` (old coupled OutputFormatter)
- Deleted: `config.py` (old monolithic Config class)
- New: `analyzers/protocol.py` (AnalyzerPlugin protocol)
- New: `core/registry.py` (analyzer auto-discovery)
- New: `core/config_manager.py` (per-analyzer config)
- New: `renderers/` directory (pluggable renderer system)

### Added

- **Protocol-Based Plugin System**
  - Analyzers implement `AnalyzerPlugin` protocol using `@runtime_checkable`
  - Auto-discovery via `@registry.register` decorator
  - Dependency resolution with topological sort
  - Circular dependency detection
  - Adding new analyzer now requires editing only ONE file

- **Semantic Output Styling (Theme-Agnostic)**
  - Analyzers define semantic styles: `success`, `error`, `warning`, `info`, `highlight`, `muted`
  - Renderers map semantic styles to theme-specific colors/formatting
  - Enables theme switching without code changes
  - Future-proof for HTML, GUI renderers without analyzer modifications

- **Per-Analyzer Configuration**
  - Isolated TOML sections: `[dns]`, `[ssl]`, `[email]`, etc.
  - Pydantic config classes defined in analyzer files
  - Multi-layer config merging preserved
  - No configuration cross-contamination

- **Auto-Discovery System**
  - Analyzers register themselves via decorator
  - CLI automatically discovers all registered analyzers
  - No manual integration in CLI code required
  - Dependency resolution ensures correct execution order

- **Unified Skip Parameter**
  - `--skip analyzer1 --skip analyzer2` replaces individual `--skip-*` flags
  - Cleaner, more scalable CLI interface
  - Tab completion for analyzer names
  - Validation with helpful error messages

- **Output Format Selection**
  - `--format cli` for colored terminal output (default)
  - `--format json` for machine-readable JSON export
  - Future formats (HTML, YAML) can be added without analyzer changes

- **Zero-Coupling Architecture**
  - Analyzers never import CLI, config, or renderers
  - Renderers never import specific analyzer code
  - Registry manages all coordination
  - Complete decoupling for maintainability and testability

### Changed

- **CLI Command Structure** (BREAKING)
  - Verbosity flags unified under `--verbosity` parameter
  - Skip parameters unified under repeatable `--skip` parameter
  - Added `wdt list-analyzers` command
  - Improved validation and error messages

- **Configuration System** (BREAKING)
  - Migrated from flat config to per-analyzer sections
  - Each analyzer section contains all analyzer-specific settings
  - `enabled` field added to control analyzers via config
  - Multi-layer merging logic preserved
  - Better isolation and maintainability

- **Output System**
  - Decoupled from analyzers via `OutputDescriptor`
  - Semantic styling instead of hardcoded colors
  - Verbosity filtering via `VerbosityLevel` enum
  - Error/warning tracking in renderers, not analyzers

- **All 11 Analyzers Refactored**
  - DNS, WHOIS, HTTP, SSL, Email, Security Headers, Site Verification, RBL, CDN, SEO Files, Favicon
  - All follow new protocol-based pattern
  - Self-contained with config, logic, and output formatting
  - Zero coupling to rest of system

### Removed

- **Old Architecture Files** (BREAKING)
  - `core/analyzer.py` (25KB) - monolithic orchestration removed
  - `utils/output.py` (78KB) - coupled formatter removed
  - `config.py` (16KB) - monolithic config removed
  - Individual `--skip-*` CLI flags removed
  - Shorthand verbosity flags (`-q`, `-v`, `-d`) removed

### Technical Details

- **Lines Changed**: +6,702 insertions, -3,699 deletions (26 files)
- **New Protocol**: `AnalyzerPlugin` with 3 required methods: `analyze()`, `describe_output()`, `to_dict()`
- **Registry**: Topological sort for dependency resolution, cycle detection
- **Config Manager**: Recursive dict merging with precedence: system → user → local → CLI
- **Renderers**: `BaseRenderer` → `CLIRenderer` (Rich-based) and `JSONRenderer`
- **Test Coverage**: Existing tests updated, new test suite planned (see roadmap)

### Developer Impact

**Simplified Workflow for Adding Analyzers:**

**Before (required 9 file edits):**
1. Create analyzer file
2. Edit config.py for schema
3. Edit default_config.toml
4. Edit cli.py for imports
5. Edit cli.py for CLI args
6. Edit cli.py for instantiation
7. Edit output.py for display
8. Edit analyzers/__init__.py
9. Update README.md

**After (requires 1 file edit):**
1. Create analyzer file with `@registry.register`
2. Update README.md (documentation only)

This represents a **90% reduction** in code changes needed to add new features.

### GUI Application CLI Arguments

- Added command-line argument support for wdt-app
  - `--config` / `-c`: Specify configuration profile name to use
  - Domain argument: Pre-fill domain input field
  - Example: `wdt-app --config myprofile example.com`
  - Enables scripting and quick access to specific profiles

### Email Configuration Consolidated

- Merged `AdvancedEmailConfig` into `EmailConfig` for simplified configuration
  - All email security settings (SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT) now in single `[email]` section
  - Removed `[advanced_email]` section from config files
  - Removed `skip_advanced_email` flag from analysis options

## [0.3.0] - 2024-11-17

### Added
- **Web Application Major Update**
  - SEO Analysis tools (robots.txt, sitemap.xml, favicon detection)
  - Export functionality (JSON, CSV, TXT, HTML formats)
  - Dark mode with localStorage persistence and system preference detection
  - DKIM detection with common selector scanning
  - Google AdSense integration with placeholder components
  - Cloudflare Pages deployment configuration
  - GitHub Actions CI/CD workflow for automatic deployment
  - Comprehensive SEO meta tags (Open Graph, Twitter Cards)
  - Google Analytics (GA4) integration
  - Security headers (_headers file for Cloudflare)
  - SPA routing support (_redirects file)
  - Production environment variables template

- **Comprehensive Testing**
  - 60+ new unit tests for all new features
  - Test coverage for SEO services, export functionality, dark mode
  - DKIM detection tests with multiple selectors

### Changed

### Changed
- **Pre-commit Hooks Configuration Updated and Automated**
  - Updated all pre-commit hook versions to latest stable releases
  - pre-commit-hooks: v4.5.0 → v5.0.0
  - black: 24.1.1 → 25.11.0 (new 2025 stable style)
  - ruff: v0.3.0 → v0.14.5 (migrated repo from charliermarsh to astral-sh)
  - isort: 5.13.2 → 7.0.0
  - Created SessionStart hook (.claude/hooks/SessionStart.md) for automatic pre-commit installation
  - Pre-commit hooks now auto-install on every Claude Code session start
  - All code formatted with Black 25.11.0 (new 2025 style)
  - Fixed all ruff linting errors (unused variables, missing imports)
  - Ensures consistent code quality across all commits

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
- **GUI Configuration Profiles System**
  - Named configuration profiles for managing different analysis scenarios
  - Profile dropdown in GUI header for quick switching between configs
  - **Last selected profile persistence** - automatically restores your last used profile on app restart
  - Save/load/delete profiles via GUI buttons with confirmation dialogs
  - Comprehensive config editor dialog with tabbed interface for all settings:
    - DNS tab: nameservers, timeout, DNSSEC, www CNAME warnings
    - HTTP tab: timeout, max redirects, custom user agent
    - SSL/TLS tab: certificate expiry thresholds
    - Email tab: DKIM selectors, RBL checking
    - Advanced Email tab: BIMI, MTA-STS, TLS-RPT
    - Security Headers tab: individual header checks
    - SEO tab: robots.txt, llms.txt, sitemap
    - Favicon tab: HTML parsing, default paths
    - WHOIS tab: domain expiry thresholds
    - Analysis Options tab: enable/disable analyzers
    - Output tab: CLI verbosity settings
  - Client-side storage using Flet's page.client_storage API
  - JSON format with Pydantic validation for data integrity
  - Default profile auto-created on first run
  - All CLI configuration options available in GUI
  - Key namespacing ("wdt.profile.{name}") to prevent conflicts
  - Comprehensive test coverage (14 tests, 91% coverage for manager)
  - Type-safe implementation with proper Callable type hints

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
  - Added Ubuntu 24.04+ compatibility fix using official Flet team solution
  - Ubuntu 24.04 ships with libmpv2, but Flet requires libmpv.so.1 (known Flet limitation)
  - Solution: `sudo ln -s /usr/lib/x86_64-linux-gnu/libmpv.so.2 /usr/lib/x86_64-linux-gnu/libmpv.so.1`
  - Corrected symlink command to point to actual libmpv.so.2 file
  - Documented in README with link to official Flet documentation

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
