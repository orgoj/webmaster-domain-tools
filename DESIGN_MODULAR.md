# Modular Analyzer Architecture - Design Document

**Version:** 1.0.0 (Breaking Change - Complete Rewrite)
**Status:** Design Review
**Author:** AI Assistant
**Date:** 2025-11-20

## Overview

Complete redesign of analyzer architecture for:
- **KISS principle** - adding analyzer = 1 file + decorator
- **Zero coupling** - renderers don't know about analyzers
- **Theme-agnostic output** - semantic styles, not colors
- **Unified CLI** - `--skip AAA --skip BBB` pattern
- **No backward compatibility** - clean slate

## Key Design Decisions

### 1. Semantic Output Styling (NOT colors)

**WRONG (old approach):**
```python
descriptor.add_row(label="Status", value="OK", color="green")
```

**CORRECT (new approach):**
```python
descriptor.add_row(
    label="Status",
    value="OK",
    style_class="success",  # Semantic class
    severity="info"         # Error level
)
```

**Semantic Style Classes:**
- `success` - positive outcome (renderer decides: green, #00FF00, checkmark, etc.)
- `error` - critical issue
- `warning` - non-critical issue
- `info` - informational
- `neutral` - default
- `highlight` - emphasis
- `muted` - de-emphasized

**Severity Levels:**
- `critical` - must be fixed
- `error` - should be fixed
- `warning` - nice to fix
- `info` - informational
- `debug` - debug information

**Renderer Mapping Examples:**

```python
# CLI Renderer (Rich library)
STYLE_MAP = {
    "success": "green",
    "error": "red",
    "warning": "yellow",
    "info": "blue",
    "muted": "dim"
}

# GUI Renderer (dark theme)
STYLE_MAP = {
    "success": "#00FF00",
    "error": "#FF4444",
    "warning": "#FFAA00",
    "info": "#4488FF",
    "muted": "#666666"
}

# GUI Renderer (light theme)
STYLE_MAP = {
    "success": "#008000",
    "error": "#CC0000",
    "warning": "#FF8800",
    "info": "#0066CC",
    "muted": "#999999"
}

# JSON Renderer
# Just exports: {"style_class": "success", "severity": "info"}
```

### 2. Unified CLI Skip Parameter

**WRONG (old approach):**
```bash
wdt analyze example.com --skip-dns --skip-whois --skip-ssl
```

**CORRECT (new approach):**
```bash
wdt analyze example.com --skip dns --skip whois --skip ssl
```

**Implementation:**
```python
@app.command()
def analyze(
    domain: str,
    skip: Annotated[list[str] | None, typer.Option(help="Analyzers to skip")] = None,
    verbose: bool = False,
):
    skip_analyzers = set(skip or [])

    # Validate
    for analyzer_id in skip_analyzers:
        if analyzer_id not in registry.get_all():
            raise ValueError(f"Unknown analyzer: {analyzer_id}")
```

### 3. OutputRow Protocol

```python
@dataclass
class OutputRow:
    """
    Renderer-agnostic output row.

    Describes WHAT to display, not HOW.
    """
    # Content
    label: str | None = None
    value: Any = None

    # Presentation hints (semantic, NOT specific)
    style_class: str = "neutral"  # success, error, warning, info, highlight, muted
    severity: str = "info"        # critical, error, warning, info, debug

    # Structure
    section_type: str = "key_value"  # key_value, list, table, heading, text, badge, link
    section_name: str | None = None  # Group rows

    # Behavior
    verbosity: VerbosityLevel = VerbosityLevel.NORMAL
    show_if_empty: bool = True

    # Icons (semantic names, NOT unicode)
    icon: str | None = None  # "check", "cross", "warning", "info", "arrow"

    # Links (semantic, renderer decides if clickable)
    link_url: str | None = None
    link_text: str | None = None

    # Badges (semantic)
    badge_label: str | None = None
    badge_value: str | None = None
    badge_style: str = "neutral"  # success, error, warning, info
```

**Icon Mapping (renderer decides):**
```python
# CLI Renderer
ICON_MAP = {
    "check": "✓",
    "cross": "✗",
    "warning": "⚠",
    "info": "ℹ",
    "arrow": "→"
}

# GUI Renderer
ICON_MAP = {
    "check": QtGui.QIcon(":/icons/check.svg"),
    "cross": QtGui.QIcon(":/icons/cross.svg"),
    "warning": QtGui.QIcon(":/icons/warning.svg"),
    # ...
}
```

## Architecture Components

### 1. Analyzer Protocol

```python
# src/webmaster_domain_tool/analyzers/protocol.py

from typing import Protocol, Any, runtime_checkable
from pydantic import BaseModel

class AnalyzerConfig(BaseModel):
    """Base config - all analyzers extend this."""
    enabled: bool = True
    timeout: float = 10.0


@runtime_checkable
class AnalyzerPlugin(Protocol):
    """Protocol all analyzers must implement."""

    # Metadata
    analyzer_id: str          # "dns", "whois", "ssl"
    name: str                 # "DNS Analysis"
    description: str          # Short description
    category: str             # "general", "security", "seo", "advanced"
    icon: str                 # "globe", "lock", "search", "shield"
    config_class: type[AnalyzerConfig]
    depends_on: list[str]     # Dependencies (e.g., ["http", "dns"])

    # Required methods
    def analyze(self, domain: str, config: AnalyzerConfig) -> Any:
        """Perform analysis, return result with errors/warnings."""
        ...

    def describe_output(self, result: Any) -> OutputDescriptor:
        """Describe how to render output (semantic, not specific)."""
        ...

    def to_dict(self, result: Any) -> dict[str, Any]:
        """Serialize to JSON."""
        ...
```

### 2. Registry System

```python
# src/webmaster_domain_tool/core/registry.py

class AnalyzerRegistry:
    """Auto-discovery registry for analyzer plugins."""

    def register(self, plugin_class: type) -> type:
        """
        Register analyzer plugin.

        Usage:
            @registry.register
            class DNSAnalyzer:
                analyzer_id = "dns"
                ...
        """
        # Validate implements protocol
        if not isinstance(plugin_class, AnalyzerPlugin):
            raise TypeError(f"{plugin_class} must implement AnalyzerPlugin")

        self._plugins[plugin_class.analyzer_id] = plugin_class
        return plugin_class

    def get_execution_order(
        self,
        requested: list[str],
        skip: set[str]
    ) -> list[str]:
        """Resolve dependencies and return execution order."""
        # Topological sort based on depends_on
        ...

# Global instance
registry = AnalyzerRegistry()
```

### 3. Config Manager

```python
# src/webmaster_domain_tool/core/config_manager.py

class ConfigManager:
    """Per-analyzer config isolation."""

    def load_from_toml(self, paths: list[Path]):
        """
        Load configs from TOML files.

        Example TOML:
            [global]
            verbosity = "normal"

            [dns]
            timeout = 5.0
            check_dnssec = true

            [ssl]
            min_tls_version = "1.2"
        """
        for path in paths:
            data = tomllib.load(path)

            # Each analyzer gets its own section
            for analyzer_id, metadata in registry.get_all().items():
                if analyzer_id in data:
                    config = metadata.config_class(**data[analyzer_id])
                    self.configs[analyzer_id] = config
```

### 4. Renderer System

```python
# src/webmaster_domain_tool/renderers/base.py

class BaseRenderer(ABC):
    """Base renderer - knows nothing about analyzers."""

    @abstractmethod
    def render(self, descriptor: OutputDescriptor) -> None:
        """Render output descriptor."""
        ...

    @abstractmethod
    def render_summary(self, all_descriptors: list[OutputDescriptor]) -> None:
        """Render final summary."""
        ...


# src/webmaster_domain_tool/renderers/cli_renderer.py

class CLIRenderer(BaseRenderer):
    """CLI renderer using Rich library."""

    STYLE_MAP = {
        "success": "green",
        "error": "red",
        "warning": "yellow",
        "info": "blue",
        "highlight": "bold",
        "muted": "dim",
        "neutral": ""
    }

    ICON_MAP = {
        "check": "✓",
        "cross": "✗",
        "warning": "⚠",
        "info": "ℹ",
        "arrow": "→"
    }

    def render(self, descriptor: OutputDescriptor) -> None:
        """Render using Rich library."""

        # Filter rows by verbosity
        rows = descriptor.filter_by_verbosity(self.verbosity)

        for row in rows:
            # Map semantic style to Rich markup
            style = self.STYLE_MAP.get(row.style_class, "")
            icon = self.ICON_MAP.get(row.icon, "")

            # Render based on section_type
            if row.section_type == "key_value":
                self.console.print(
                    f"{icon} {row.label}: [{style}]{row.value}[/{style}]"
                )
            # ... other section types
```

## Example: Complete Analyzer Implementation

```python
# src/webmaster_domain_tool/analyzers/cdn_detector.py

from dataclasses import dataclass, field
from pydantic import BaseModel, Field

from .protocol import AnalyzerConfig, OutputDescriptor, OutputRow, VerbosityLevel
from ..core.registry import registry


# 1. Config schema
class CDNConfig(AnalyzerConfig):
    """CDN detector configuration."""
    check_headers: bool = Field(default=True, description="Check HTTP headers")
    check_cname: bool = Field(default=True, description="Check DNS CNAME")


# 2. Result dataclass
@dataclass
class CDNResult:
    """CDN detection result."""
    domain: str
    detected: bool = False
    provider: str | None = None
    confidence: str = "none"  # high, medium, low, none
    evidence: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# 3. Analyzer implementation
@registry.register
class CDNDetector:
    """CDN detection analyzer - completely self-contained."""

    # Metadata
    analyzer_id = "cdn"
    name = "CDN Detection"
    description = "Detect Content Delivery Network usage"
    category = "advanced"
    icon = "cloud"
    config_class = CDNConfig
    depends_on = ["http", "dns"]

    def analyze(self, domain: str, config: CDNConfig) -> CDNResult:
        """Detect CDN."""
        result = CDNResult(domain=domain)

        # Analysis logic...
        if self._detect_cloudflare(domain):
            result.detected = True
            result.provider = "Cloudflare"
            result.confidence = "high"
            result.evidence.append("CF-Ray header present")

        return result

    def describe_output(self, result: CDNResult) -> OutputDescriptor:
        """Describe output (semantic, theme-agnostic)."""
        descriptor = OutputDescriptor(title=self.name, category=self.category)

        # Quiet summary
        descriptor.quiet_summary = lambda r: (
            f"CDN: {r.provider}" if r.detected else "CDN: None"
        )

        # Normal verbosity
        if result.detected:
            descriptor.add_row(
                label="Provider",
                value=result.provider,
                style_class="success",  # Semantic!
                icon="check",           # Semantic icon
                severity="info",
                verbosity=VerbosityLevel.NORMAL
            )

            descriptor.add_row(
                label="Confidence",
                value=result.confidence,
                style_class="highlight" if result.confidence == "high" else "muted",
                verbosity=VerbosityLevel.NORMAL
            )
        else:
            descriptor.add_row(
                label="CDN",
                value="Not detected",
                style_class="muted",
                verbosity=VerbosityLevel.NORMAL
            )

        # Verbose - show evidence
        if result.evidence:
            descriptor.add_row(
                label="Evidence",
                value=result.evidence,
                section_type="list",
                verbosity=VerbosityLevel.VERBOSE
            )

        # Errors/warnings
        for error in result.errors:
            descriptor.add_row(
                value=error,
                section_type="text",
                style_class="error",
                severity="error",
                icon="cross"
            )

        for warning in result.warnings:
            descriptor.add_row(
                value=warning,
                section_type="text",
                style_class="warning",
                severity="warning",
                icon="warning"
            )

        return descriptor

    def to_dict(self, result: CDNResult) -> dict:
        """Serialize to JSON."""
        return {
            "domain": result.domain,
            "detected": result.detected,
            "provider": result.provider,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "errors": result.errors,
            "warnings": result.warnings
        }
```

**That's it!** Analyzer is now:
- ✅ Auto-registered
- ✅ Available via `--skip cdn`
- ✅ Config isolated in `[cdn]` TOML section
- ✅ Renders in CLI/GUI/JSON/HTML
- ✅ Theme-agnostic (semantic styles)

## CLI Integration

```python
# src/webmaster_domain_tool/cli.py

import typer
from typing import Annotated

app = typer.Typer()

@app.command()
def analyze(
    domain: str,
    skip: Annotated[
        list[str] | None,
        typer.Option(help="Analyzers to skip (e.g., --skip dns --skip whois)")
    ] = None,
    verbosity: Annotated[
        str,
        typer.Option(help="Output verbosity: quiet, normal, verbose, debug")
    ] = "normal",
    output_format: Annotated[
        str,
        typer.Option(help="Output format: cli, json, html")
    ] = "cli",
):
    """Analyze a domain."""

    # Load config
    config_manager = ConfigManager()
    config_manager.load_from_files()

    # Get enabled analyzers
    skip_set = set(skip or [])
    enabled_analyzers = [
        aid for aid in registry.get_all().keys()
        if aid not in skip_set
        and config_manager.get_analyzer_config(aid).enabled
    ]

    # Resolve dependencies
    execution_order = registry.resolve_dependencies(enabled_analyzers)

    # Create renderer
    if output_format == "cli":
        renderer = CLIRenderer(verbosity=VerbosityLevel[verbosity.upper()])
    elif output_format == "json":
        renderer = JSONRenderer()
    elif output_format == "html":
        renderer = HTMLRenderer()

    # Execute analyzers
    results = {}
    for analyzer_id in execution_order:
        metadata = registry.get(analyzer_id)
        config = config_manager.get_analyzer_config(analyzer_id)

        # Instantiate and run
        analyzer = metadata.plugin_class()
        result = analyzer.analyze(domain, config)

        # Describe output
        descriptor = analyzer.describe_output(result)

        # Render
        renderer.render(descriptor)

        results[analyzer_id] = (descriptor, result)

    # Summary
    renderer.render_summary(results)
```

## Migration Plan - NO BACKWARD COMPATIBILITY

### Phase 1: Core Infrastructure
1. Create `analyzers/protocol.py` - protocols
2. Create `core/registry.py` - enhanced registry
3. Create `core/config_manager.py` - per-analyzer configs
4. Create `renderers/base.py` - renderer protocol
5. Create `renderers/cli_renderer.py` - Rich renderer
6. Create `renderers/json_renderer.py` - JSON export

### Phase 2: Migrate One Analyzer (Proof of Concept)
1. Migrate `cdn_detector.py` (simple, new analyzer)
2. Add `@registry.register` decorator
3. Implement `describe_output()` with semantic styles
4. Test with new renderer

### Phase 3: Migrate All Analyzers
1. Migrate each analyzer one-by-one:
   - `dns_analyzer.py`
   - `whois_analyzer.py`
   - `ssl_analyzer.py`
   - `http_analyzer.py`
   - `email_security.py`
   - `security_headers.py`
   - `rbl_checker.py`
   - `seo_analyzer.py`
   - `favicon_analyzer.py`
   - `site_verification.py`

### Phase 4: Delete Old Code
1. **DELETE** `core/analyzer.py` (old `run_domain_analysis()`)
2. **DELETE** `utils/output.py` (old `OutputFormatter`)
3. **DELETE** `config.py` (old monolithic config)
4. Update `cli.py` to use new system

### Phase 5: Update Tests
1. **DELETE** old tests
2. Write new tests:
   - `tests/test_protocol.py` - protocol validation
   - `tests/test_registry.py` - registry and dependency resolution
   - `tests/test_config_manager.py` - config loading
   - `tests/test_cli_renderer.py` - CLI rendering
   - `tests/test_analyzers/test_*.py` - each analyzer
   - `tests/test_integration.py` - full analysis flow

### Phase 6: Documentation
1. Update `README.md` - new CLI usage
2. Update `CLAUDE.md` - new architecture guide
3. Update `CHANGELOG.md` - breaking changes
4. Bump version to `1.0.0` (major breaking change)

## Benefits

### Before (Current System)
- ❌ Adding analyzer = modify 9 files
- ❌ Colors hardcoded (no theme support)
- ❌ CLI flags: `--skip-dns --skip-whois` (not scalable)
- ❌ Output formatting coupled to OutputFormatter
- ❌ Config monolithic
- ❌ Hard to add new output formats

### After (Modular System)
- ✅ Adding analyzer = 1 file + `@registry.register`
- ✅ Semantic styles (theme-agnostic)
- ✅ CLI: `--skip dns --skip whois` (scalable)
- ✅ Zero coupling (renderer ↔ analyzer)
- ✅ Config isolated per analyzer
- ✅ New output format = new renderer (20 lines)
- ✅ Dependency resolution built-in
- ✅ Type-safe with Pydantic

## Open Questions

1. **GUI Renderer Details** - Qt vs Web?
2. **HTML Export** - Static HTML or template engine?
3. **Progress Callbacks** - How to report progress during analysis?
4. **Parallel Execution** - Run independent analyzers in parallel?
5. **Result Caching** - Cache analyzer results for repeated runs?

## Review Checklist

- [ ] Protocol design reviewed
- [ ] Semantic styles comprehensive
- [ ] CLI skip parameter ergonomic
- [ ] Registry pattern correct
- [ ] Config isolation clean
- [ ] Renderer decoupling complete
- [ ] Migration plan feasible
- [ ] Test strategy comprehensive
- [ ] Performance acceptable
- [ ] Documentation complete
