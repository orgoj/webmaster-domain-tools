"""Tests for the Lighthouse analyzer."""

import pytest
from unittest.mock import patch, MagicMock
import httpx

from webmaster_domain_tool.analyzers.lighthouse import (
    LighthouseAnalyzer,
    LighthouseConfig,
    LighthouseResult,
    CategoryScore,
    AuditResult,
)


class TestLighthouseConfig:
    """Tests for LighthouseConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = LighthouseConfig()
        assert config.timeout == 60.0
        assert config.strategy == "desktop"
        assert config.locale == "en"
        assert config.api_key is None
        assert "performance" in config.categories
        assert "accessibility" in config.categories
        assert "best-practices" in config.categories
        assert "seo" in config.categories

    def test_mobile_strategy(self):
        """Test mobile strategy configuration."""
        config = LighthouseConfig(strategy="mobile")
        assert config.strategy == "mobile"

    def test_invalid_strategy(self):
        """Test that invalid strategy raises error."""
        with pytest.raises(ValueError):
            LighthouseConfig(strategy="invalid")

    def test_custom_categories(self):
        """Test custom categories configuration."""
        config = LighthouseConfig(categories=["performance", "seo"])
        assert config.categories == ["performance", "seo"]

    def test_invalid_category(self):
        """Test that invalid category raises error."""
        with pytest.raises(ValueError):
            LighthouseConfig(categories=["invalid"])


class TestLighthouseAnalyzer:
    """Tests for LighthouseAnalyzer."""

    def test_analyzer_metadata(self):
        """Test analyzer metadata."""
        analyzer = LighthouseAnalyzer()
        assert analyzer.analyzer_id == "lighthouse"
        assert analyzer.name == "Lighthouse Audit"
        assert analyzer.category == "performance"
        assert analyzer.icon == "lighthouse"
        assert analyzer.config_class == LighthouseConfig

    def test_to_dict(self):
        """Test JSON serialization."""
        analyzer = LighthouseAnalyzer()
        result = LighthouseResult(
            domain="example.com",
            url="https://example.com",
            success=True,
            overall_score=85,
            performance=CategoryScore(
                name="performance",
                display_name="Performance",
                score=0.85,
                score_int=85,
                rating="needs-improvement",
                audit_count=50,
                passed_audits=40,
                failed_audits=10,
            ),
        )

        data = analyzer.to_dict(result)

        assert data["domain"] == "example.com"
        assert data["url"] == "https://example.com"
        assert data["success"] is True
        assert data["overall_score"] == 85
        assert data["categories"]["performance"]["score_int"] == 85

    def test_describe_output(self):
        """Test output descriptor generation."""
        analyzer = LighthouseAnalyzer()
        result = LighthouseResult(
            domain="example.com",
            url="https://example.com",
            success=True,
            overall_score=78,
            performance=CategoryScore(
                name="performance",
                display_name="Performance",
                score=0.78,
                score_int=78,
                rating="needs-improvement",
            ),
            accessibility=CategoryScore(
                name="accessibility",
                display_name="Accessibility",
                score=0.92,
                score_int=92,
                rating="good",
            ),
            best_practices=CategoryScore(
                name="best-practices",
                display_name="Best Practices",
                score=0.83,
                score_int=83,
                rating="needs-improvement",
            ),
            seo=CategoryScore(
                name="seo",
                display_name="SEO",
                score=0.60,
                score_int=60,
                rating="needs-improvement",
            ),
        )

        descriptor = analyzer.describe_output(result)

        assert descriptor.title == "Lighthouse Audit"
        assert len(descriptor.rows) > 0

    def test_failed_analysis(self):
        """Test handling of failed analysis."""
        analyzer = LighthouseAnalyzer()
        result = LighthouseResult(
            domain="example.com",
            url="https://example.com",
            success=False,
            errors=["API error: 429"],
        )

        descriptor = analyzer.describe_output(result)
        assert any("Failed" in str(r.value) for r in descriptor.rows if r.value)

    def test_rating_styles(self):
        """Test rating style mapping."""
        analyzer = LighthouseAnalyzer()

        assert analyzer._get_rating_style("good") == "success"
        assert analyzer._get_rating_style("needs-improvement") == "warning"
        assert analyzer._get_rating_style("poor") == "error"
        assert analyzer._get_rating_style("unknown") == "muted"

    def test_rating_icons(self):
        """Test rating icon mapping."""
        analyzer = LighthouseAnalyzer()

        assert analyzer._get_rating_icon("good") == "check"
        assert analyzer._get_rating_icon("needs-improvement") == "warning"
        assert analyzer._get_rating_icon("poor") == "cross"
        assert analyzer._get_rating_icon("unknown") == "question"


class TestLighthouseAnalyzerWithMock:
    """Tests with mocked API responses."""

    @pytest.fixture
    def mock_pagespeed_response(self):
        """Mock PageSpeed API response."""
        return {
            "lighthouseResult": {
                "categories": {
                    "performance": {
                        "score": 0.85,
                        "auditRefs": [
                            {"id": "largest-contentful-paint", "weight": 1},
                        ],
                    },
                    "accessibility": {
                        "score": 0.92,
                        "auditRefs": [],
                    },
                    "best-practices": {
                        "score": 0.78,
                        "auditRefs": [],
                    },
                    "seo": {
                        "score": 0.90,
                        "auditRefs": [],
                    },
                },
                "audits": {
                    "largest-contentful-paint": {
                        "title": "Largest Contentful Paint",
                        "description": "LCP marks the time...",
                        "score": 0.8,
                        "numericValue": 2500,
                        "displayValue": "2.5 s",
                    },
                },
            },
        }

    @patch("httpx.Client.get")
    def test_analyze_with_mock(self, mock_get, mock_pagespeed_response):
        """Test analysis with mocked API response."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_pagespeed_response
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        analyzer = LighthouseAnalyzer()
        config = LighthouseConfig()
        result = analyzer.analyze("example.com", config)

        assert result.success is True
        assert result.performance is not None
        assert result.performance.score_int == 85
        assert result.accessibility.score_int == 92
        assert result.overall_score is not None

    @patch("httpx.Client.get")
    def test_analyze_api_error(self, mock_get):
        """Test handling of API errors."""
        mock_get.side_effect = httpx.HTTPStatusError(
            "Error",
            request=MagicMock(),
            response=MagicMock(status_code=429),
        )

        analyzer = LighthouseAnalyzer()
        config = LighthouseConfig()
        result = analyzer.analyze("example.com", config)

        assert result.success is False
        assert len(result.errors) > 0
        assert "429" in result.errors[0]


class TestAuditResult:
    """Tests for AuditResult dataclass."""

    def test_audit_result_creation(self):
        """Test creating an audit result."""
        audit = AuditResult(
            id="test-audit",
            title="Test Audit",
            description="A test audit",
            score=0.9,
            is_passed=True,
        )

        assert audit.id == "test-audit"
        assert audit.title == "Test Audit"
        assert audit.score == 0.9
        assert audit.is_passed is True


class TestCategoryScore:
    """Tests for CategoryScore dataclass."""

    def test_category_score_creation(self):
        """Test creating a category score."""
        score = CategoryScore(
            name="performance",
            display_name="Performance",
            score=0.85,
            score_int=85,
            rating="needs-improvement",
            audit_count=50,
            passed_audits=40,
            failed_audits=10,
        )

        assert score.name == "performance"
        assert score.score_int == 85
        assert score.rating == "needs-improvement"


class TestLighthouseResult:
    """Tests for LighthouseResult dataclass."""

    def test_result_defaults(self):
        """Test default values."""
        result = LighthouseResult(domain="example.com")

        assert result.domain == "example.com"
        assert result.success is False
        assert result.errors == []
        assert result.warnings == []
        assert result.performance is None
        assert result.overall_score is None
