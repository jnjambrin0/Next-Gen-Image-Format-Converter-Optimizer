"""
Command History Management
Handles command history for undo/redo functionality
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from collections import deque

from app.cli.config import get_history_dir, get_config


class HistoryManager:
    """Manages command history for undo/redo"""
    
    def __init__(self):
        self.history_dir = get_history_dir()
        self.history_file = self.history_dir / "commands.json"
        self.undo_stack_file = self.history_dir / "undo_stack.json"
        self.redo_stack_file = self.history_dir / "redo_stack.json"
        
        self._ensure_history_dir()
        self.config = get_config()
        
        # Load history
        self.history = self._load_history()
        self.undo_stack = deque(self._load_stack(self.undo_stack_file), maxlen=self.config.history_size)
        self.redo_stack = deque(self._load_stack(self.redo_stack_file), maxlen=self.config.history_size)
    
    def _ensure_history_dir(self):
        """Ensure history directory exists"""
        self.history_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_history(self) -> List[Dict]:
        """Load command history"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []
    
    def _save_history(self):
        """Save command history"""
        # Keep only the most recent entries
        if len(self.history) > self.config.history_size:
            self.history = self.history[-self.config.history_size:]
        
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f, indent=2)
    
    def _load_stack(self, file: Path) -> List[Dict]:
        """Load undo/redo stack"""
        if file.exists():
            try:
                with open(file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []
    
    def _save_stack(self, stack: deque, file: Path):
        """Save undo/redo stack"""
        with open(file, 'w') as f:
            json.dump(list(stack), f, indent=2)
    
    def add_command(self, command: str, success: bool = True, result: Optional[Dict] = None):
        """Add a command to history"""
        if not self.config.history_enabled:
            return
        
        entry = {
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "success": success,
            "result": result
        }
        
        self.history.append(entry)
        self._save_history()
        
        # Add to undo stack if successful
        if success:
            self.undo_stack.append(entry)
            self._save_stack(self.undo_stack, self.undo_stack_file)
            
            # Clear redo stack on new command
            self.redo_stack.clear()
            self._save_stack(self.redo_stack, self.redo_stack_file)
    
    def get_history(self, count: int = 10) -> List[Dict]:
        """Get recent command history"""
        return self.history[-count:] if self.history else []
    
    def undo(self) -> Optional[Dict]:
        """Undo last command"""
        if not self.undo_stack:
            return None
        
        command = self.undo_stack.pop()
        self.redo_stack.append(command)
        
        self._save_stack(self.undo_stack, self.undo_stack_file)
        self._save_stack(self.redo_stack, self.redo_stack_file)
        
        return command
    
    def redo(self) -> Optional[Dict]:
        """Redo last undone command"""
        if not self.redo_stack:
            return None
        
        command = self.redo_stack.pop()
        self.undo_stack.append(command)
        
        self._save_stack(self.undo_stack, self.undo_stack_file)
        self._save_stack(self.redo_stack, self.redo_stack_file)
        
        return command
    
    def clear_history(self):
        """Clear all history"""
        self.history.clear()
        self.undo_stack.clear()
        self.redo_stack.clear()
        
        self._save_history()
        self._save_stack(self.undo_stack, self.undo_stack_file)
        self._save_stack(self.redo_stack, self.redo_stack_file)


# Global history manager
_history_manager = None


def get_history_manager() -> HistoryManager:
    """Get or create history manager"""
    global _history_manager
    if _history_manager is None:
        _history_manager = HistoryManager()
    return _history_manager


def record_command(command: str, success: bool = True, result: Optional[Dict] = None):
    """Record a command in history"""
    manager = get_history_manager()
    manager.add_command(command, success, result)