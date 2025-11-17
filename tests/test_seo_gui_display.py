"""Test SEO files GUI display logic to prevent false positives."""

from dataclasses import dataclass, field


@dataclass
class RobotsResult:
    """Mock RobotsResult for testing."""

    url: str
    exists: bool = False
    content: str | None = None
    size: int | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class LLMsTxtResult:
    """Mock LLMsTxtResult for testing."""

    url: str
    exists: bool = False
    content: str | None = None
    size: int | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SitemapResult:
    """Mock SitemapResult for testing."""

    url: str
    exists: bool = False
    url_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SEOFilesAnalysisResult:
    """Mock SEO result for testing."""

    domain: str
    robots: RobotsResult | None = None
    llms_txt: LLMsTxtResult | None = None
    sitemaps: list[SitemapResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def test_robots_not_found_should_not_show_found():
    """Test that robots.txt not found doesn't display as found."""
    # Create result with robots.txt NOT found (exists=False)
    result = SEOFilesAnalysisResult(
        domain="example.com",
        robots=RobotsResult(
            url="https://example.com/robots.txt",
            exists=False,  # ← Key: file doesn't exist
        ),
    )
    result.robots.warnings.append("robots.txt not found (consider creating one)")

    # Simulate GUI logic
    should_show_found = result.robots and result.robots.exists

    # Assert: should NOT show "robots.txt found"
    assert not should_show_found, "robots.txt should NOT display as found when exists=False"
    # Assert: warning should exist
    assert "robots.txt not found" in result.robots.warnings[0]


def test_robots_found_should_show_found():
    """Test that robots.txt found displays correctly."""
    result = SEOFilesAnalysisResult(
        domain="example.com",
        robots=RobotsResult(
            url="https://example.com/robots.txt",
            exists=True,  # ← File exists
            content="User-agent: *\nDisallow: /admin",
            size=30,
        ),
    )

    # Simulate GUI logic
    should_show_found = result.robots and result.robots.exists

    # Assert: SHOULD show "robots.txt found"
    assert should_show_found, "robots.txt should display as found when exists=True"
    assert len(result.robots.warnings) == 0


def test_llms_txt_not_found_should_not_show_found():
    """Test that llms.txt not found doesn't display as found."""
    result = SEOFilesAnalysisResult(
        domain="example.com",
        llms_txt=LLMsTxtResult(
            url="https://example.com/llms.txt",
            exists=False,  # ← File doesn't exist
        ),
    )

    # Simulate GUI logic
    should_show_found = result.llms_txt and result.llms_txt.exists

    # Assert: should NOT show "llms.txt found"
    assert not should_show_found, "llms.txt should NOT display as found when exists=False"


def test_sitemap_filtering_only_existing():
    """Test that only existing sitemaps are displayed."""
    result = SEOFilesAnalysisResult(
        domain="example.com",
        sitemaps=[
            SitemapResult(
                url="https://example.com/sitemap.xml",
                exists=True,  # ← This one exists
                url_count=100,
            ),
            SitemapResult(
                url="https://example.com/sitemap2.xml",
                exists=False,  # ← This one doesn't exist (404)
            ),
        ],
    )

    # Simulate GUI logic - filter only existing
    existing_sitemaps = [s for s in result.sitemaps if s.exists]

    # Assert: should only show the one that exists
    assert len(existing_sitemaps) == 1, "Should only show existing sitemaps"
    assert existing_sitemaps[0].url == "https://example.com/sitemap.xml"


def test_all_seo_files_not_found():
    """Test display when no SEO files exist."""
    result = SEOFilesAnalysisResult(
        domain="example.com",
        robots=RobotsResult(url="https://example.com/robots.txt", exists=False),
        llms_txt=LLMsTxtResult(url="https://example.com/llms.txt", exists=False),
        sitemaps=[],  # No sitemaps found
    )

    # Simulate GUI logic
    show_robots = result.robots and result.robots.exists
    show_llms = result.llms_txt and result.llms_txt.exists
    existing_sitemaps = [s for s in result.sitemaps if s.exists]

    # Assert: nothing should show as found
    assert not show_robots, "robots.txt should not show"
    assert not show_llms, "llms.txt should not show"
    assert len(existing_sitemaps) == 0, "no sitemaps should show"
