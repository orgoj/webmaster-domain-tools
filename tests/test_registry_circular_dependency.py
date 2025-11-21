"""Test registry's circular dependency detection and dependency resolution.

This module tests the core registry functionality for v1.0.0 architecture:
- Circular dependency detection
- Topological sort correctness
- Skip propagation
"""

import pytest

from webmaster_domain_tool.analyzers.protocol import AnalyzerConfig, OutputDescriptor
from webmaster_domain_tool.core.registry import AnalyzerRegistry

# ============================================================================
# Mock Analyzer Classes for Testing
# ============================================================================


class MockConfigA(AnalyzerConfig):
    """Mock config for analyzer A."""

    pass


class MockConfigB(AnalyzerConfig):
    """Mock config for analyzer B."""

    pass


class MockConfigC(AnalyzerConfig):
    """Mock config for analyzer C."""

    pass


class MockAnalyzerA:
    """Mock analyzer A."""

    analyzer_id = "mock-a"
    name = "Mock A"
    description = "Mock analyzer A"
    category = "test"
    icon = "test"
    config_class = MockConfigA
    depends_on = []  # No dependencies

    def analyze(self, domain: str, config: MockConfigA):
        return {"domain": domain, "analyzer": "A"}

    def describe_output(self, result):
        return OutputDescriptor(title="Mock A")

    def to_dict(self, result):
        return result


class MockAnalyzerB:
    """Mock analyzer B that depends on A."""

    analyzer_id = "mock-b"
    name = "Mock B"
    description = "Mock analyzer B"
    category = "test"
    icon = "test"
    config_class = MockConfigB
    depends_on = ["mock-a"]  # Depends on A

    def analyze(self, domain: str, config: MockConfigB):
        return {"domain": domain, "analyzer": "B"}

    def describe_output(self, result):
        return OutputDescriptor(title="Mock B")

    def to_dict(self, result):
        return result


class MockAnalyzerC:
    """Mock analyzer C that depends on B."""

    analyzer_id = "mock-c"
    name = "Mock C"
    description = "Mock analyzer C"
    category = "test"
    icon = "test"
    config_class = MockConfigC
    depends_on = ["mock-b"]  # Depends on B

    def analyze(self, domain: str, config: MockConfigC):
        return {"domain": domain, "analyzer": "C"}

    def describe_output(self, result):
        return OutputDescriptor(title="Mock C")

    def to_dict(self, result):
        return result


class MockAnalyzerCircularA:
    """Mock analyzer with circular dependency: A→B."""

    analyzer_id = "circular-a"
    name = "Circular A"
    description = "Mock analyzer with circular dependency"
    category = "test"
    icon = "test"
    config_class = MockConfigA
    depends_on = ["circular-b"]  # Creates cycle

    def analyze(self, domain: str, config: MockConfigA):
        return {"domain": domain}

    def describe_output(self, result):
        return OutputDescriptor(title="Circular A")

    def to_dict(self, result):
        return result


class MockAnalyzerCircularB:
    """Mock analyzer with circular dependency: B→A."""

    analyzer_id = "circular-b"
    name = "Circular B"
    description = "Mock analyzer with circular dependency"
    category = "test"
    icon = "test"
    config_class = MockConfigB
    depends_on = ["circular-a"]  # Creates cycle

    def analyze(self, domain: str, config: MockConfigB):
        return {"domain": domain}

    def describe_output(self, result):
        return OutputDescriptor(title="Circular B")

    def to_dict(self, result):
        return result


# ============================================================================
# Test Cases
# ============================================================================


class TestRegistryCircularDependency:
    """Test registry's circular dependency detection."""

    def test_detect_circular_dependency_simple(self):
        """Test detection of simple circular dependency: A→B→A."""
        # Create fresh registry
        registry = AnalyzerRegistry()

        # Register analyzers with circular dependency
        registry.register(MockAnalyzerCircularA)
        registry.register(MockAnalyzerCircularB)

        # Should raise ValueError when resolving
        with pytest.raises(ValueError, match="Circular dependency detected"):
            registry.resolve_dependencies(["circular-a"])

    def test_detect_circular_dependency_complex(self):
        """Test detection of complex circular dependency: A→B→C→A."""
        # Create fresh registry
        registry = AnalyzerRegistry()

        # Create complex circular dependency
        class CircularA:
            analyzer_id = "complex-a"
            name = "Complex A"
            description = "Test"
            category = "test"
            icon = "test"
            config_class = MockConfigA
            depends_on = ["complex-b"]

            def analyze(self, domain: str, config):
                return {}

            def describe_output(self, result):
                return OutputDescriptor(title="A")

            def to_dict(self, result):
                return {}

        class CircularB:
            analyzer_id = "complex-b"
            name = "Complex B"
            description = "Test"
            category = "test"
            icon = "test"
            config_class = MockConfigB
            depends_on = ["complex-c"]

            def analyze(self, domain: str, config):
                return {}

            def describe_output(self, result):
                return OutputDescriptor(title="B")

            def to_dict(self, result):
                return {}

        class CircularC:
            analyzer_id = "complex-c"
            name = "Complex C"
            description = "Test"
            category = "test"
            icon = "test"
            config_class = MockConfigC
            depends_on = ["complex-a"]  # Back to A - creates cycle

            def analyze(self, domain: str, config):
                return {}

            def describe_output(self, result):
                return OutputDescriptor(title="C")

            def to_dict(self, result):
                return {}

        registry.register(CircularA)
        registry.register(CircularB)
        registry.register(CircularC)

        # Should detect cycle
        with pytest.raises(ValueError, match="Circular dependency detected"):
            registry.resolve_dependencies(["complex-a"])

    def test_topological_sort_correct_order(self):
        """Test that dependencies run in correct order: A before B before C."""
        # Create fresh registry
        registry = AnalyzerRegistry()

        # Register analyzers with chain: C→B→A
        registry.register(MockAnalyzerA)  # No dependencies
        registry.register(MockAnalyzerB)  # Depends on A
        registry.register(MockAnalyzerC)  # Depends on B

        # Request C (should include A and B)
        order = registry.resolve_dependencies(["mock-c"])

        # Should be ordered: A, B, C
        assert order == ["mock-a", "mock-b", "mock-c"]

        # Request just B (should include A)
        order = registry.resolve_dependencies(["mock-b"])
        assert order == ["mock-a", "mock-b"]

        # Request A (no dependencies)
        order = registry.resolve_dependencies(["mock-a"])
        assert order == ["mock-a"]

    def test_skip_propagation(self):
        """Test that skipping analyzer removes it from execution."""
        # Create fresh registry
        registry = AnalyzerRegistry()

        # Register analyzer chain
        registry.register(MockAnalyzerA)
        registry.register(MockAnalyzerB)
        registry.register(MockAnalyzerC)

        # Skip B (which C depends on)
        order = registry.resolve_dependencies(["mock-c"], skip={"mock-b"})

        # C should still run, but B is skipped
        # A runs because it has no dependencies and wasn't skipped
        # Note: This tests current behavior - if dependencies are strict,
        # C might fail at runtime without B
        assert "mock-b" not in order
        assert "mock-c" in order

        # Skip A (which B depends on)
        order = registry.resolve_dependencies(["mock-b"], skip={"mock-a"})
        assert "mock-a" not in order
        assert "mock-b" in order


class TestRegistryBasics:
    """Test basic registry functionality."""

    def test_register_analyzer(self):
        """Test registering an analyzer."""
        registry = AnalyzerRegistry()
        registry.register(MockAnalyzerA)

        # Should be registered
        metadata = registry.get("mock-a")
        assert metadata is not None
        assert metadata.analyzer_id == "mock-a"
        assert metadata.name == "Mock A"
        assert metadata.config_class == MockConfigA

    def test_get_all_analyzers(self):
        """Test getting all registered analyzers."""
        registry = AnalyzerRegistry()
        registry.register(MockAnalyzerA)
        registry.register(MockAnalyzerB)

        all_analyzers = registry.get_all()
        assert "mock-a" in all_analyzers
        assert "mock-b" in all_analyzers
        assert len(all_analyzers) == 2

    def test_validate_skip_list(self):
        """Test validating skip list."""
        registry = AnalyzerRegistry()
        registry.register(MockAnalyzerA)
        registry.register(MockAnalyzerB)

        # Valid skip list
        valid, unknown = registry.validate_skip_list(["mock-a"])
        assert valid is True
        assert len(unknown) == 0

        # Invalid skip list
        valid, unknown = registry.validate_skip_list(["mock-a", "nonexistent"])
        assert valid is False
        assert "nonexistent" in unknown

    def test_unknown_analyzer_dependency(self):
        """Test error when analyzer depends on unknown analyzer."""
        registry = AnalyzerRegistry()

        class BadAnalyzer:
            analyzer_id = "bad"
            name = "Bad"
            description = "Test"
            category = "test"
            icon = "test"
            config_class = MockConfigA
            depends_on = ["does-not-exist"]

            def analyze(self, domain: str, config):
                return {}

            def describe_output(self, result):
                return OutputDescriptor(title="Bad")

            def to_dict(self, result):
                return {}

        registry.register(BadAnalyzer)

        # Should raise error when resolving
        with pytest.raises(ValueError, match="Unknown analyzer"):
            registry.resolve_dependencies(["bad"])
