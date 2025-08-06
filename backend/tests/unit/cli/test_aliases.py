"""
Unit tests for alias system
"""

import pytest
from unittest.mock import Mock, patch, mock_open
from pathlib import Path
import json
import tempfile

from app.cli.utils.aliases import AliasManager


class TestAliasManager:
    """Test alias manager"""
    
    @pytest.fixture
    def temp_alias_file(self):
        """Create temporary alias file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            aliases = {
                "c": "convert",
                "b": "batch",
                "o": "optimize"
            }
            json.dump(aliases, f)
            temp_path = Path(f.name)
        
        yield temp_path
        temp_path.unlink(missing_ok=True)
    
    def test_alias_manager_init_no_file(self):
        """Test alias manager initialization without existing file"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = Path("/nonexistent/aliases.json")
            
            manager = AliasManager()
            
            # Should load default aliases
            assert "c" in manager.aliases
            assert manager.aliases["c"] == "convert"
            assert "b" in manager.aliases
            assert manager.aliases["b"] == "batch"
    
    def test_alias_manager_init_with_file(self, temp_alias_file):
        """Test alias manager initialization with existing file"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = temp_alias_file
            
            manager = AliasManager()
            
            assert "c" in manager.aliases
            assert manager.aliases["c"] == "convert"
            assert "b" in manager.aliases
            assert manager.aliases["b"] == "batch"
    
    def test_add_alias(self):
        """Test adding a new alias"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            temp_file = Path("/tmp/test_aliases.json")
            mock_get_file.return_value = temp_file
            
            with patch.object(AliasManager, '_save_aliases'):
                manager = AliasManager()
                
                result = manager.add_alias("test", "test_command")
                
                assert result == True
                assert "test" in manager.aliases
                assert manager.aliases["test"] == "test_command"
    
    def test_remove_alias(self):
        """Test removing an alias"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = Path("/tmp/test_aliases.json")
            
            with patch.object(AliasManager, '_save_aliases'):
                manager = AliasManager()
                manager.aliases = {"test": "test_command", "keep": "keep_command"}
                
                result = manager.remove_alias("test")
                
                assert result == True
                assert "test" not in manager.aliases
                assert "keep" in manager.aliases
    
    def test_remove_nonexistent_alias(self):
        """Test removing a non-existent alias"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = Path("/tmp/test_aliases.json")
            
            manager = AliasManager()
            
            result = manager.remove_alias("nonexistent")
            
            assert result == False
    
    def test_get_alias(self):
        """Test getting an alias"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = Path("/tmp/test_aliases.json")
            
            manager = AliasManager()
            manager.aliases = {"test": "test_command"}
            
            assert manager.get_alias("test") == "test_command"
            assert manager.get_alias("nonexistent") is None
    
    def test_list_aliases(self):
        """Test listing all aliases"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = Path("/tmp/test_aliases.json")
            
            manager = AliasManager()
            manager.aliases = {"a": "cmd_a", "b": "cmd_b"}
            
            aliases = manager.list_aliases()
            
            assert aliases == {"a": "cmd_a", "b": "cmd_b"}
            # Should be a copy, not the original
            aliases["c"] = "cmd_c"
            assert "c" not in manager.aliases
    
    def test_save_aliases(self, tmp_path):
        """Test saving aliases to file"""
        alias_file = tmp_path / "aliases.json"
        
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = alias_file
            
            manager = AliasManager()
            manager.aliases = {"test": "test_command"}
            manager._save_aliases()
            
            # Check file was created and contains correct data
            assert alias_file.exists()
            with open(alias_file, 'r') as f:
                saved_aliases = json.load(f)
            
            assert saved_aliases == {"test": "test_command"}
    
    def test_default_aliases(self):
        """Test default aliases are correct"""
        with patch('app.cli.utils.aliases.get_aliases_file') as mock_get_file:
            mock_get_file.return_value = Path("/nonexistent/aliases.json")
            
            manager = AliasManager()
            defaults = manager._get_default_aliases()
            
            # Check key default aliases
            assert defaults["c"] == "convert"
            assert defaults["b"] == "batch"
            assert defaults["o"] == "optimize"
            assert defaults["a"] == "analyze"
            assert defaults["f"] == "formats"
            assert defaults["p"] == "presets"