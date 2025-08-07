"""
Integration tests for documentation flow
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile
import sqlite3

from app.cli.documentation.help_context import HelpContextAnalyzer
from app.cli.documentation.tutorial_engine import TutorialEngine, TutorialProgress
from app.cli.documentation.examples import ExampleDatabase, ExampleCategory
from app.cli.documentation.knowledge_base import KnowledgeBase, QuestionCategory, Question
from app.cli.documentation.reference_cards import ReferenceCardGenerator
from app.cli.documentation.ascii_demos import AsciiDemoPlayer
from app.cli.documentation.doc_browser import DocumentationBrowser


class TestDocumentationIntegration:
    """Test integrated documentation flow"""
    
    @pytest.fixture
    def temp_home(self, tmp_path):
        """Create temporary home directory"""
        with patch('pathlib.Path.home', return_value=tmp_path):
            yield tmp_path
    
    @pytest.fixture
    def help_analyzer(self):
        """Create help analyzer"""
        return HelpContextAnalyzer()
    
    @pytest.fixture
    def tutorial_engine(self, temp_home):
        """Create tutorial engine with temp directory"""
        engine = TutorialEngine()
        engine.config_dir = temp_home / ".image-converter"
        engine.progress_file = engine.config_dir / "tutorial_progress.json"
        engine.sandbox_dir = temp_home / "sandbox"
        return engine
    
    @pytest.fixture
    def example_db(self):
        """Create example database"""
        return ExampleDatabase()
    
    @pytest.fixture
    def knowledge_base(self, temp_home):
        """Create knowledge base with temp database"""
        kb = KnowledgeBase()
        kb.db_path = temp_home / ".image-converter" / "knowledge.db"
        kb._init_database()
        kb._populate_default_qa()
        return kb
    
    @pytest.fixture
    def doc_browser(self):
        """Create documentation browser"""
        return DocumentationBrowser()
    
    def test_help_search_integration(self, help_analyzer):
        """Test searching help across multiple topics"""
        # Search for "convert"
        results = help_analyzer.search_help("convert")
        assert len(results) > 0
        
        # Should find convert command
        commands = [r["command"] for r in results]
        assert "convert" in commands
        
        # Should also find related commands
        assert any(r["command"] in ["batch", "chain"] for r in results)
    
    def test_tutorial_progress_persistence(self, tutorial_engine):
        """Test tutorial progress saves and loads correctly"""
        # Start a tutorial
        progress = TutorialProgress(
            tutorial_id="basic_conversion",
            current_step=3,
            completed_steps=["intro", "first_convert", "quality_quiz"],
            total_steps=6
        )
        tutorial_engine.progress["basic_conversion"] = progress
        
        # Save progress
        tutorial_engine._save_progress()
        assert tutorial_engine.progress_file.exists()
        
        # Create new engine and load
        new_engine = TutorialEngine()
        new_engine.progress_file = tutorial_engine.progress_file
        new_engine._load_progress()
        
        # Check progress was loaded
        assert "basic_conversion" in new_engine.progress
        loaded_progress = new_engine.progress["basic_conversion"]
        assert loaded_progress.current_step == 3
        assert len(loaded_progress.completed_steps) == 3
        assert loaded_progress.completion_percentage == 50.0
    
    def test_example_search_and_validation(self, example_db):
        """Test searching examples and validation"""
        # Search for batch examples
        examples = example_db.search("batch")
        assert len(examples) > 0
        
        # Validate examples
        for example in examples:
            is_valid = example_db.validate_example(example)
            assert is_valid or not example.safe_to_run
        
        # Check categories
        batch_examples = example_db.get_by_category(ExampleCategory.BATCH)
        assert len(batch_examples) > 0
        
        # All batch examples should have batch tag
        for ex in batch_examples:
            assert "batch" in ex.tags
    
    def test_knowledge_base_qa_flow(self, knowledge_base):
        """Test Q&A flow in knowledge base"""
        # Search for common issues
        questions = knowledge_base.search("slow conversion")
        assert len(questions) > 0
        
        # Get by error code
        question = knowledge_base.get_by_error_code("CONV001")
        assert question is not None
        assert "not found" in question.answer.lower()
        
        # Test voting
        if question.id:
            original_votes = question.votes
            knowledge_base.vote(question.id, upvote=True)
            
            # Retrieve again
            updated = knowledge_base.get_question(question.id)
            assert updated.votes == original_votes + 1
        
        # Test categories
        troubleshooting = knowledge_base.get_by_category(QuestionCategory.TROUBLESHOOTING)
        assert len(troubleshooting) > 0
    
    def test_reference_card_generation(self, reference_cards):
        """Test reference card generation"""
        # Generate markdown
        markdown = reference_cards.generate_markdown("basic")
        assert "Image Converter CLI - Quick Reference" in markdown
        assert "Basic Commands" in markdown
        assert "img convert" in markdown
        
        # Generate text
        text = reference_cards.generate_text("basic")
        assert "Image Converter CLI" in text
        assert "convert" in text
        
        # List cards
        cards = reference_cards.list_cards()
        assert len(cards) > 0
        card_ids = [c["id"] for c in cards]
        assert "basic" in card_ids
        assert "advanced" in card_ids
    
    @pytest.mark.asyncio
    async def test_demo_playback(self, tmp_path):
        """Test ASCII demo playback"""
        player = AsciiDemoPlayer()
        
        # List demos
        demos = player.list_demos()
        assert len(demos) > 0
        
        # Search demos
        results = player.search_demos("conversion")
        assert len(results) > 0
        
        # Check demo properties
        demo = player.demos.get("basic_conversion")
        assert demo is not None
        assert len(demo.frames) > 0
        assert demo.duration > 0
    
    def test_documentation_browser_navigation(self, doc_browser):
        """Test documentation browser navigation"""
        # Get root section
        root = doc_browser.sections.get("root")
        assert root is not None
        assert len(root.children) > 0
        
        # Navigate to child
        getting_started = doc_browser.sections.get("getting-started")
        assert getting_started is not None
        assert getting_started.parent_id == "root"
        
        # Test breadcrumb
        breadcrumb = doc_browser._get_breadcrumb(getting_started)
        assert "Home" in breadcrumb
        assert "Getting Started" in breadcrumb
        
        # Search documentation
        results = doc_browser.search("convert")
        assert len(results) > 0
        
        # Should find convert command docs
        titles = [s.title for s in results]
        assert any("convert" in t.lower() for t in titles)
    
    def test_cross_component_search(self, help_analyzer, example_db, knowledge_base, doc_browser):
        """Test searching across all documentation components"""
        query = "webp"
        
        # Search in help
        help_results = help_analyzer.search_help(query)
        assert len(help_results) > 0
        
        # Search in examples
        example_results = example_db.search(query)
        assert len(example_results) > 0
        
        # Search in Q&A
        qa_results = knowledge_base.search(query)
        assert len(qa_results) > 0
        
        # Search in documentation
        doc_results = doc_browser.search(query)
        assert len(doc_results) > 0
        
        # All components should find relevant results
        assert help_results[0]["score"] > 0
        assert any("webp" in ex.command.lower() for ex in example_results)
        assert any(query in q.question.lower() or query in q.answer.lower() for q in qa_results)
        assert any(query in s.content.lower() for s in doc_results)
    
    def test_offline_operation(self, temp_home):
        """Test all documentation works offline"""
        # All components should work without network
        with patch('socket.socket') as mock_socket:
            # Block all network calls
            mock_socket.side_effect = OSError("Network disabled")
            
            # Create all components
            help_analyzer = HelpContextAnalyzer()
            tutorial_engine = TutorialEngine()
            example_db = ExampleDatabase()
            knowledge_base = KnowledgeBase()
            doc_browser = DocumentationBrowser()
            reference_cards = ReferenceCardGenerator()
            demo_player = AsciiDemoPlayer()
            
            # All should initialize without network
            assert len(help_analyzer.help_topics) > 0
            assert len(tutorial_engine.tutorials) > 0
            assert len(example_db.examples) > 0
            assert len(doc_browser.sections) > 0
            assert len(reference_cards.cards) > 0
            assert len(demo_player.demos) > 0
    
    def test_documentation_completeness(self, help_analyzer, tutorial_engine, example_db):
        """Test documentation covers all major commands"""
        commands = ["convert", "batch", "optimize", "analyze", "formats", "presets", "watch", "chain"]
        
        for cmd in commands:
            # Should have help topic
            assert cmd in help_analyzer.help_topics
            
            # Should have examples
            examples = example_db.search(cmd)
            assert len(examples) > 0, f"No examples for {cmd}"
        
        # Should have tutorials for core features
        tutorial_ids = list(tutorial_engine.tutorials.keys())
        assert "basic_conversion" in tutorial_ids
        assert "batch_processing" in tutorial_ids
    
    def test_error_code_coverage(self, help_analyzer, knowledge_base):
        """Test error codes are documented"""
        error_codes = ["CONV001", "CONV002", "CONV003", "BATCH001", "OPT001"]
        
        for code in error_codes[:3]:  # Test first 3 conversion errors
            # Should be in help topics
            found_in_help = False
            for topic in help_analyzer.help_topics.values():
                if "common_errors" in topic and code in topic["common_errors"]:
                    found_in_help = True
                    break
            assert found_in_help, f"Error {code} not in help topics"
    
    @pytest.mark.asyncio
    async def test_tutorial_sandbox_safety(self, tutorial_engine, temp_home):
        """Test tutorial sandbox is safe"""
        # Create sandbox
        tutorial_engine.sandbox_dir.mkdir(parents=True, exist_ok=True)
        
        # Try to run sandboxed command
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Success",
                stderr=""
            )
            
            result = await tutorial_engine._run_sandboxed_command("img convert test.jpg")
            
            # Should modify command to run in sandbox
            mock_run.assert_called()
            call_args = mock_run.call_args
            assert str(tutorial_engine.sandbox_dir) in call_args[0][0]