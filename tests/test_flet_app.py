"""Tests for Flet GUI application."""

from webmaster_domain_tool.flet_app import DomainAnalyzerApp


class TestFletApp:
    """Test suite for Flet application."""

    def test_import_flet_app(self) -> None:
        """Test that flet_app module can be imported."""
        from webmaster_domain_tool import flet_app

        assert flet_app is not None
        assert hasattr(flet_app, "DomainAnalyzerApp")
        assert hasattr(flet_app, "main")

    def test_validate_domain_valid(self) -> None:
        """Test domain validation with valid domain."""

        # Mock page object (we don't need real Flet page for validation tests)
        class MockPage:
            title = "Test"
            theme_mode = None
            padding = 0
            scroll = None

            def add(self, control):  # noqa: ARG002
                pass

            def update(self):
                pass

        page = MockPage()
        app = DomainAnalyzerApp(page)  # type: ignore

        assert app.validate_domain("example.com") is True
        assert app.validate_domain("www.example.com") is True
        assert app.validate_domain("subdomain.example.com") is True
        assert app.validate_domain("test.co.uk") is True

    def test_validate_domain_invalid(self) -> None:
        """Test domain validation with invalid domain."""

        # Mock page object
        class MockPage:
            title = "Test"
            theme_mode = None
            padding = 0
            scroll = None

            def add(self, control):  # noqa: ARG002
                pass

            def update(self):
                pass

        page = MockPage()
        app = DomainAnalyzerApp(page)  # type: ignore

        assert app.validate_domain("") is False
        assert app.validate_domain("invalid") is False
        assert app.validate_domain("invalid..com") is False
        assert app.validate_domain("-invalid.com") is False

    def test_normalize_domain(self) -> None:
        """Test domain normalization."""

        # Mock page object
        class MockPage:
            title = "Test"
            theme_mode = None
            padding = 0
            scroll = None

            def add(self, control):  # noqa: ARG002
                pass

            def update(self):
                pass

        page = MockPage()
        app = DomainAnalyzerApp(page)  # type: ignore

        assert app.normalize_domain("example.com") == "example.com"
        assert app.normalize_domain("http://example.com") == "example.com"
        assert app.normalize_domain("https://example.com") == "example.com"
        assert app.normalize_domain("example.com/") == "example.com"
        assert app.normalize_domain("https://example.com/") == "example.com"
        assert app.normalize_domain("  example.com  ") == "example.com"
