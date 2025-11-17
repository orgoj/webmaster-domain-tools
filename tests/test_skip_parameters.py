"""Tests for skip parameters in run_domain_analysis.

This test file ensures all analyzers in ANALYZER_REGISTRY have corresponding
skip parameters in run_domain_analysis() function signature.
"""

from webmaster_domain_tool.config import load_config
from webmaster_domain_tool.core.analyzer import ANALYZER_REGISTRY, run_domain_analysis


class TestSkipParameters:
    """Test skip parameters for all analyzers."""

    def test_all_registry_skip_params_accepted(self):
        """Test that run_domain_analysis accepts all skip parameters from ANALYZER_REGISTRY.

        This is a regression test for the bug where GUI generates skip_seo, skip_favicon
        from the registry, but run_domain_analysis() doesn't accept those parameters.
        """
        config = load_config()

        # Build skip parameters from registry (like GUI does)
        skip_params = {}
        for analyzer_key, metadata in ANALYZER_REGISTRY.items():
            if metadata.skip_param_name:
                # For normal skip_* params, set to True (skip the analyzer)
                # For inverted do_* params, set to False (don't run)
                if metadata.skip_param_inverted:
                    skip_params[metadata.skip_param_name] = False
                else:
                    skip_params[metadata.skip_param_name] = True

        # This should NOT raise TypeError about unexpected keyword argument
        result = run_domain_analysis(
            "example.com",
            config,
            **skip_params,  # Should accept all parameters from registry!
        )

        assert result is not None
        assert result.domain == "example.com"

    def test_skip_seo_parameter(self):
        """Test that skip_seo parameter works (regression test)."""
        config = load_config()

        # Should accept skip_seo without raising TypeError
        result = run_domain_analysis(
            "example.com",
            config,
            skip_dns=True,
            skip_http=True,
            skip_ssl=True,
            skip_email=True,
            skip_headers=True,
            skip_site_verification=True,
            skip_seo=True,  # ← This was causing TypeError!
        )

        assert result is not None
        assert result.seo is None  # Should be None when skipped

    def test_skip_favicon_parameter(self):
        """Test that skip_favicon parameter works (regression test)."""
        config = load_config()

        # Should accept skip_favicon without raising TypeError
        result = run_domain_analysis(
            "example.com",
            config,
            skip_dns=True,
            skip_http=True,
            skip_ssl=True,
            skip_email=True,
            skip_headers=True,
            skip_site_verification=True,
            skip_favicon=True,  # ← This was also missing!
        )

        assert result is not None
        assert result.favicon is None  # Should be None when skipped

    def test_registry_skip_params_match_function_signature(self):
        """Verify all registry skip parameters exist in run_domain_analysis signature.

        This test ensures the registry and function stay in sync.
        """
        import inspect

        # Get run_domain_analysis signature
        sig = inspect.signature(run_domain_analysis)
        param_names = set(sig.parameters.keys())

        # Get all skip parameter names from registry
        registry_skip_params = set()
        for metadata in ANALYZER_REGISTRY.values():
            if metadata.skip_param_name:
                registry_skip_params.add(metadata.skip_param_name)

        # All registry skip params should be in function signature
        missing_params = registry_skip_params - param_names

        assert not missing_params, (
            f"ANALYZER_REGISTRY has skip parameters not in run_domain_analysis(): {missing_params}. "
            "Either add these parameters to the function signature or remove them from the registry."
        )
