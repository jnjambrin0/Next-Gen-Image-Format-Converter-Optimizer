"""
Unit tests for Tutorial Engine
"""

import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from app.cli.documentation.tutorial_engine import (
    TutorialEngine,
    TutorialStep,
    TutorialProgress,
    TutorialStepType,
)


class TestTutorialStep:
    """Test TutorialStep dataclass"""

    def test_tutorial_step_creation(self):
        """Test creating tutorial step"""
        step = TutorialStep(
            id="test_step",
            type=TutorialStepType.INSTRUCTION,
            title="Test Step",
            content="This is a test step",
            hints=["Hint 1", "Hint 2"],
        )

        assert step.id == "test_step"
        assert step.type == TutorialStepType.INSTRUCTION
        assert step.title == "Test Step"
        assert len(step.hints) == 2

    def test_tutorial_step_to_dict(self):
        """Test converting step to dictionary"""
        step = TutorialStep(
            id="quiz",
            type=TutorialStepType.QUIZ,
            title="Quiz",
            content="What is the answer?",
            quiz_options=["A", "B", "C"],
            quiz_answer=1,
        )

        data = step.to_dict()
        assert data["id"] == "quiz"
        assert data["type"] == "quiz"
        assert data["quiz_options"] == ["A", "B", "C"]
        assert data["quiz_answer"] == 1

    def test_tutorial_step_from_dict(self):
        """Test creating step from dictionary"""
        data = {
            "id": "command",
            "type": "command",
            "title": "Command Demo",
            "content": "Run this command",
            "command": "img convert test.jpg",
            "expected_output": "Success",
        }

        step = TutorialStep.from_dict(data)
        assert step.id == "command"
        assert step.type == TutorialStepType.COMMAND
        assert step.command == "img convert test.jpg"


class TestTutorialProgress:
    """Test TutorialProgress dataclass"""

    def test_tutorial_progress_creation(self):
        """Test creating tutorial progress"""
        progress = TutorialProgress(
            tutorial_id="basic",
            current_step=2,
            completed_steps=["step1", "step2"],
            total_steps=5,
        )

        assert progress.tutorial_id == "basic"
        assert progress.current_step == 2
        assert len(progress.completed_steps) == 2
        assert progress.total_steps == 5

    def test_completion_percentage(self):
        """Test completion percentage calculation"""
        progress = TutorialProgress(
            tutorial_id="test",
            current_step=0,
            completed_steps=["s1", "s2", "s3"],
            total_steps=10,
        )

        assert progress.completion_percentage == 30.0

        # Test with no steps
        progress.total_steps = 0
        assert progress.completion_percentage == 0.0

    def test_progress_to_dict(self):
        """Test converting progress to dictionary"""
        progress = TutorialProgress(
            tutorial_id="test", current_step=1, achievements=["first_step"]
        )

        data = progress.to_dict()
        assert data["tutorial_id"] == "test"
        assert data["current_step"] == 1
        assert data["achievements"] == ["first_step"]


class TestTutorialEngine:
    """Test TutorialEngine"""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create engine instance with temp directory"""
        with patch(
            "app.cli.documentation.tutorial_engine.Path.home", return_value=tmp_path
        ):
            engine = TutorialEngine()
            engine.sandbox_dir = tmp_path / "sandbox"
            engine.config_dir = tmp_path / ".image-converter"
            engine.progress_file = engine.config_dir / "tutorial_progress.json"
            return engine

    def test_engine_initialization(self, engine):
        """Test engine initialization"""
        assert len(engine.tutorials) > 0
        assert "basic_conversion" in engine.tutorials
        assert "batch_processing" in engine.tutorials

    def test_list_tutorials(self, engine):
        """Test listing tutorials"""
        tutorials = engine.list_tutorials()

        assert len(tutorials) > 0
        for tutorial in tutorials:
            assert "id" in tutorial
            assert "title" in tutorial
            assert "steps" in tutorial
            assert "completed" in tutorial
            assert "status" in tutorial

    def test_get_tutorial_title(self, engine):
        """Test getting tutorial title"""
        assert (
            engine._get_tutorial_title("basic_conversion") == "Basic Image Conversion"
        )
        assert engine._get_tutorial_title("batch_processing") == "Batch Processing"
        assert engine._get_tutorial_title("unknown") == "Unknown"

    def test_get_tutorial_status(self, engine):
        """Test getting tutorial status"""
        # Not started
        status = engine._get_tutorial_status("basic_conversion")
        assert status == "Not Started"

        # Add progress
        engine.progress["basic_conversion"] = TutorialProgress(
            tutorial_id="basic_conversion", current_step=2, total_steps=5
        )
        status = engine._get_tutorial_status("basic_conversion")
        assert status == "In Progress"

        # Mark completed
        engine.progress["basic_conversion"].completed_at = 123456
        status = engine._get_tutorial_status("basic_conversion")
        assert status == "Completed"

    @pytest.mark.asyncio
    async def test_run_tutorial_not_found(self, engine):
        """Test running non-existent tutorial"""
        with patch.object(engine.console, "print") as mock_print:
            await engine.run_tutorial("nonexistent")
            mock_print.assert_called_with("[red]Tutorial 'nonexistent' not found[/red]")

    def test_save_and_load_progress(self, engine):
        """Test saving and loading progress"""
        # Add progress
        progress = TutorialProgress(
            tutorial_id="test",
            current_step=3,
            completed_steps=["s1", "s2"],
            total_steps=5,
        )
        engine.progress["test"] = progress

        # Save
        engine._save_progress()
        assert engine.progress_file.exists()

        # Load in new engine
        new_engine = TutorialEngine()
        new_engine.progress_file = engine.progress_file
        new_engine._load_progress()

        assert "test" in new_engine.progress
        assert new_engine.progress["test"].current_step == 3

    @pytest.mark.asyncio
    async def test_execute_instruction_step(self, engine):
        """Test executing instruction step"""
        step = TutorialStep(
            id="inst",
            type=TutorialStepType.INSTRUCTION,
            title="Instructions",
            content="Read this",
        )

        progress = TutorialProgress(tutorial_id="test", current_step=0, total_steps=1)

        with patch("app.cli.documentation.tutorial_engine.Prompt.ask", return_value=""):
            result = await engine._execute_step(step, progress)
            assert result is True

    def test_execute_quiz_step(self, engine):
        """Test executing quiz step"""
        step = TutorialStep(
            id="quiz",
            type=TutorialStepType.QUIZ,
            title="Quiz",
            content="What is 2+2?",
            quiz_options=["3", "4", "5"],
            quiz_answer=1,
        )

        progress = TutorialProgress(tutorial_id="test", current_step=0, total_steps=1)

        # Test correct answer
        with patch(
            "app.cli.documentation.tutorial_engine.Prompt.ask", return_value="2"
        ):
            with patch.object(engine.console, "print") as mock_print:
                result = engine._execute_quiz_step(step)
                assert result is True
                mock_print.assert_any_call("[green]✓ Correct![/green]")

        # Test wrong answer
        with patch(
            "app.cli.documentation.tutorial_engine.Prompt.ask", return_value="1"
        ):
            with patch.object(engine.console, "print") as mock_print:
                result = engine._execute_quiz_step(step)
                assert result is True  # Still continues

    def test_create_sample_image(self, engine, tmp_path):
        """Test creating sample image"""
        filepath = tmp_path / "test.png"
        engine._create_sample_image(filepath)

        assert filepath.exists()
        # Check PNG header
        data = filepath.read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"

    def test_validate_sandbox(self, engine, tmp_path):
        """Test sandbox validation"""
        engine.sandbox_dir = tmp_path

        # Test file exists check
        validation = {"check_output_exists": "output.webp"}
        assert engine._validate_sandbox(validation) is False

        # Create file
        (tmp_path / "output.webp").touch()
        assert engine._validate_sandbox(validation) is True

        # Test directory exists check
        validation = {"check_directory_exists": "converted"}
        assert engine._validate_sandbox(validation) is False

        # Create directory
        (tmp_path / "converted").mkdir()
        assert engine._validate_sandbox(validation) is True

    def test_reset_progress(self, engine):
        """Test resetting progress"""
        # Add some progress
        engine.progress["test"] = TutorialProgress(
            tutorial_id="test", current_step=3, total_steps=5
        )

        # Reset specific tutorial
        with patch.object(engine.console, "print"):
            engine.reset_progress("test")
            assert "test" not in engine.progress

        # Add again
        engine.progress["test"] = TutorialProgress(
            tutorial_id="test", current_step=1, total_steps=5
        )
        engine.progress["test2"] = TutorialProgress(
            tutorial_id="test2", current_step=2, total_steps=3
        )

        # Reset all
        with patch.object(engine.console, "print"):
            engine.reset_progress()
            assert len(engine.progress) == 0
