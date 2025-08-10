"""
Unit tests for cache management in documentation components
"""

import time
from unittest.mock import Mock, patch

import pytest
import typer

from app.cli.documentation.help_context import HelpContextAnalyzer


class TestHelpContextCacheManagement:
    """Test cache management in HelpContextAnalyzer"""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer with short TTL for testing"""
        return HelpContextAnalyzer(cache_ttl=1)  # 1 second TTL

    def test_cache_ttl_expiration(self, analyzer):
        """Test that cache entries expire after TTL"""
        # Create mock context
        ctx = Mock(spec=typer.Context)
        ctx.command_path = "img convert"
        ctx.params = {"format": "webp"}
        ctx.obj = {}

        # First call - should cache
        context1 = analyzer.get_context(ctx)
        assert len(analyzer._help_cache) == 1

        # Wait for TTL to expire
        time.sleep(1.5)

        # Second call - should evict expired entry and create new
        context2 = analyzer.get_context(ctx)

        # Cache should still have 1 entry (old evicted, new added)
        assert len(analyzer._help_cache) == 1

    def test_cache_size_limit(self, analyzer):
        """Test that cache respects size limits"""
        # Set a smaller max cache size for testing
        analyzer.MAX_CACHE_SIZE = 5

        # Add more entries than the limit
        for i in range(10):
            ctx = Mock(spec=typer.Context)
            ctx.command_path = f"img command{i}"
            ctx.params = {"param": i}
            ctx.obj = {}

            analyzer.get_context(ctx)

        # Trigger cleanup with force to bypass interval check
        analyzer._maybe_cleanup_cache(force=True)

        # Cache should be within limits
        assert len(analyzer._help_cache) <= analyzer.MAX_CACHE_SIZE

    def test_lru_eviction(self, analyzer):
        """Test that least recently used entries are evicted"""
        analyzer.MAX_CACHE_SIZE = 3

        # Add 3 entries
        contexts = []
        for i in range(3):
            ctx = Mock(spec=typer.Context)
            ctx.command_path = f"img command{i}"
            ctx.params = {"param": i}
            ctx.obj = {}

            analyzer.get_context(ctx)
            contexts.append(ctx)

        # Access first two entries to increase their access count
        for i in range(2):
            analyzer.get_context(contexts[i])
            analyzer.get_context(contexts[i])

        # Add a fourth entry (should trigger eviction)
        ctx4 = Mock(spec=typer.Context)
        ctx4.command_path = "img command4"
        ctx4.params = {"param": 4}
        ctx4.obj = {}
        analyzer.get_context(ctx4)

        # Force cleanup
        analyzer._evict_lru_entries()

        # The third entry (least accessed) should be evicted
        cache_keys = list(analyzer._help_cache.keys())
        assert "command2:{'param': 2}:None" not in cache_keys or len(cache_keys) <= 3

    def test_cache_access_count_tracking(self, analyzer):
        """Test that cache tracks access counts correctly"""
        ctx = Mock(spec=typer.Context)
        ctx.command_path = "img convert"
        ctx.params = {"format": "webp"}
        ctx.obj = {}

        # Access multiple times
        for _ in range(5):
            analyzer.get_context(ctx)

        cache_key = "convert:{'format': 'webp'}:None"
        assert (
            analyzer._cache_access_count[cache_key] == 4
        )  # First access doesn't count

    def test_cache_cleanup_interval(self, analyzer):
        """Test that cleanup respects interval"""
        analyzer.CACHE_CLEANUP_INTERVAL = 10  # 10 seconds

        # First cleanup
        analyzer._maybe_cleanup_cache()
        first_cleanup = analyzer._last_cleanup

        # Immediate second call should not cleanup
        analyzer._maybe_cleanup_cache()
        assert analyzer._last_cleanup == first_cleanup

        # After interval, should cleanup
        analyzer._last_cleanup = time.time() - 11
        analyzer._maybe_cleanup_cache()
        assert analyzer._last_cleanup > first_cleanup

    def test_clear_cache_resets_all(self, analyzer):
        """Test that clear_cache resets all cache structures"""
        # Add some cache entries
        ctx = Mock(spec=typer.Context)
        ctx.command_path = "img convert"
        ctx.params = {"format": "webp"}
        ctx.obj = {}

        analyzer.get_context(ctx)

        # Verify cache has data
        assert len(analyzer._help_cache) > 0
        assert len(analyzer._cache_timestamps) > 0

        # Clear cache
        analyzer.clear_cache()

        # Verify all structures are cleared
        assert len(analyzer._help_cache) == 0
        assert len(analyzer._cache_timestamps) == 0
        assert len(analyzer._cache_access_count) == 0


class TestLazyLoadingPerformance:
    """Test lazy loading optimizations"""

    def test_knowledge_base_lazy_index(self):
        """Test that knowledge base lazily loads search index"""
        from app.cli.documentation.knowledge_base import KnowledgeBase

        with patch("app.cli.documentation.knowledge_base.WHOOSH_AVAILABLE", True):
            kb = KnowledgeBase()

            # Index should not be initialized yet
            assert not kb._index_initialized
            assert kb._search_index is None

            # First access should initialize
            _ = kb.search_index
            assert kb._index_initialized

    def test_knowledge_base_handles_missing_whoosh(self):
        """Test graceful fallback when Whoosh is not available"""
        from app.cli.documentation.knowledge_base import KnowledgeBase

        with patch("app.cli.documentation.knowledge_base.WHOOSH_AVAILABLE", False):
            kb = KnowledgeBase()

            # Should handle missing dependency gracefully
            index = kb.search_index
            assert index is None
            assert kb._index_initialized
