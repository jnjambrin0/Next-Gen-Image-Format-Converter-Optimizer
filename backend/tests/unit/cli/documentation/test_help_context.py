"""
Unit tests for Help Context Analyzer
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import typer

from app.cli.documentation.help_context import HelpContext, HelpContextAnalyzer


class TestHelpContext:
    """Test HelpContext dataclass"""
    
    def test_help_context_creation(self):
        """Test creating help context"""
        context = HelpContext(
            command_chain=["convert"],
            current_params={"format": "webp"},
            error_state=None,
            suggestions=["Try --help"],
            relevant_examples=["img convert photo.jpg -f webp"],
            related_topics=["batch", "optimize"]
        )
        
        assert context.command_chain == ["convert"]
        assert context.current_params == {"format": "webp"}
        assert context.error_state is None
        assert len(context.suggestions) == 1
        assert len(context.relevant_examples) == 1
        assert len(context.related_topics) == 2
    
    def test_help_context_to_dict(self):
        """Test converting context to dictionary"""
        context = HelpContext(
            command_chain=["batch"],
            current_params={"workers": 4}
        )
        
        data = context.to_dict()
        assert data["command_chain"] == ["batch"]
        assert data["current_params"] == {"workers": 4}
        assert data["error_state"] is None


class TestHelpContextAnalyzer:
    """Test HelpContextAnalyzer"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        return HelpContextAnalyzer()
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initialization"""
        assert analyzer.fuzzy_searcher is not None
        assert len(analyzer.help_topics) > 0
        assert "convert" in analyzer.help_topics
        assert "batch" in analyzer.help_topics
    
    def test_resolve_alias(self, analyzer):
        """Test command alias resolution"""
        assert analyzer._resolve_alias("c") == "convert"
        assert analyzer._resolve_alias("b") == "batch"
        assert analyzer._resolve_alias("o") == "optimize"
        assert analyzer._resolve_alias("unknown") == "unknown"
    
    def test_get_command_suggestions(self, analyzer):
        """Test command suggestions"""
        # Test partial match
        suggestions = analyzer._get_command_suggestions("conv")
        assert len(suggestions) > 0
        assert any("convert" in s for s in suggestions)
        
        # Test fuzzy match
        suggestions = analyzer._get_command_suggestions("btch")
        assert len(suggestions) > 0
        assert any("batch" in s for s in suggestions)
    
    def test_search_help(self, analyzer):
        """Test help search functionality"""
        # Search for "convert"
        results = analyzer.search_help("convert")
        assert len(results) > 0
        assert results[0]["command"] == "convert"
        
        # Search for "webp"
        results2 = analyzer.search_help("webp")
        assert len(results2) > 0
        
        # Search for error code
        results3 = analyzer.search_help("CONV001")
        assert len(results3) > 0
    
    def test_get_context_with_command(self, analyzer):
        """Test getting context with command"""
        # Create mock Typer context
        ctx = Mock(spec=typer.Context)
        ctx.command_path = "img convert"
        ctx.params = {"format": "webp"}
        ctx.obj = {}
        
        context = analyzer.get_context(ctx)
        
        assert context.command_chain == ["convert"]
        assert context.current_params == {"format": "webp"}
        assert len(context.relevant_examples) > 0
        assert len(context.related_topics) > 0
    
    def test_get_context_with_error(self, analyzer):
        """Test getting context with error state"""
        # Create error string with error code
        error = "CONV001: File not found error"
        
        # Create mock context
        ctx = Mock(spec=typer.Context)
        ctx.command_path = "img convert"
        ctx.params = {}
        ctx.obj = {"last_error": error}
        
        context = analyzer.get_context(ctx)
        
        assert context.error_state == error
        assert len(context.suggestions) > 0
        assert any("not found" in s.lower() for s in context.suggestions)
    
    def test_get_context_caching(self, analyzer):
        """Test context caching"""
        ctx = Mock(spec=typer.Context)
        ctx.command_path = "img convert"
        ctx.params = {"format": "webp"}
        ctx.obj = {}
        
        # First call
        context1 = analyzer.get_context(ctx)
        
        # Second call should use cache
        context2 = analyzer.get_context(ctx)
        
        assert context1.command_chain == context2.command_chain
        assert context1.current_params == context2.current_params
    
    def test_clear_cache(self, analyzer):
        """Test cache clearing"""
        ctx = Mock(spec=typer.Context)
        ctx.command_path = "img convert"
        ctx.params = {}
        ctx.obj = {}
        
        # Populate cache
        analyzer.get_context(ctx)
        assert len(analyzer._help_cache) > 0
        
        # Clear cache
        analyzer.clear_cache()
        assert len(analyzer._help_cache) == 0
    
    @patch('app.cli.documentation.help_context.Console')
    def test_display_context_help(self, mock_console, analyzer):
        """Test displaying context help"""
        console = Mock()
        analyzer.console = console
        
        context = HelpContext(
            command_chain=["convert"],
            current_params={},
            relevant_examples=["img convert photo.jpg -f webp"],
            related_topics=["batch", "optimize"]
        )
        
        analyzer.display_context_help(context)
        console.print.assert_called()
    
    @patch('app.cli.documentation.help_context.Console')
    def test_display_general_help(self, mock_console, analyzer):
        """Test displaying general help"""
        console = Mock()
        analyzer.console = console
        
        context = HelpContext(
            command_chain=[],
            current_params={}
        )
        
        analyzer.display_context_help(context)
        console.print.assert_called()
    
    def test_help_topics_completeness(self, analyzer):
        """Test that help topics are complete"""
        required_commands = ["convert", "batch", "optimize", "analyze", "formats", "presets", "watch", "chain"]
        
        for cmd in required_commands:
            assert cmd in analyzer.help_topics
            topic = analyzer.help_topics[cmd]
            assert "brief" in topic
            assert "description" in topic
            assert "examples" in topic
            assert isinstance(topic["examples"], list)
            assert len(topic["examples"]) > 0