"""
Q&A Knowledge Base
Offline knowledge base with search and troubleshooting
"""

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

# Optional import for full-text search
try:
    from whoosh import fields, index, qparser
    from whoosh.analysis import StemmingAnalyzer
    from whoosh.filedb.filestore import RamStorage

    WHOOSH_AVAILABLE = True
except ImportError:
    WHOOSH_AVAILABLE = False


class QuestionCategory(str, Enum):
    """Categories for Q&A"""

    GENERAL = "general"
    TROUBLESHOOTING = "troubleshooting"
    CONVERSION = "conversion"
    OPTIMIZATION = "optimization"
    FORMATS = "formats"
    ERRORS = "errors"
    PERFORMANCE = "performance"
    ADVANCED = "advanced"


@dataclass
class Question:
    """Represents a Q&A entry"""

    id: Optional[int] = None
    question: str = ""
    answer: str = ""
    category: QuestionCategory = QuestionCategory.GENERAL
    tags: List[str] = field(default_factory=list)
    error_codes: List[str] = field(default_factory=list)
    votes: int = 0
    views: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "question": self.question,
            "answer": self.answer,
            "category": self.category.value,
            "tags": self.tags,
            "error_codes": self.error_codes,
            "votes": self.votes,
            "views": self.views,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Question":
        """Create from dictionary"""
        return cls(
            id=data.get("id"),
            question=data.get("question", ""),
            answer=data.get("answer", ""),
            category=QuestionCategory(data.get("category", "general")),
            tags=data.get("tags", []),
            error_codes=data.get("error_codes", []),
            votes=data.get("votes", 0),
            views=data.get("views", 0),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else None
            ),
            updated_at=(
                datetime.fromisoformat(data["updated_at"])
                if data.get("updated_at")
                else None
            ),
        )


class KnowledgeBase:
    """Q&A Knowledge Base with search capabilities"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.db_path = Path.home() / ".image-converter" / "knowledge.db"
        self._search_index = None  # Lazy loaded
        self._index_initialized = False

        self._init_database()
        # Defer search index initialization for lazy loading
        self._populate_default_qa()

    def _init_database(self):
        """Initialize SQLite database"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create questions table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                category TEXT NOT NULL,
                tags TEXT,
                error_codes TEXT,
                votes INTEGER DEFAULT 0,
                views INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Create error mapping table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS error_mappings (
                error_code TEXT PRIMARY KEY,
                question_id INTEGER,
                FOREIGN KEY (question_id) REFERENCES questions(id)
            )
        """
        )

        # Create indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON questions(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_votes ON questions(votes DESC)")

        conn.commit()
        conn.close()

    @property
    def search_index(self):
        """Lazy-load search index on first access"""
        if not self._index_initialized:
            self._init_search_index()
            self._index_initialized = True
        return self._search_index

    def _init_search_index(self):
        """Initialize full-text search index (called lazily)"""
        if not WHOOSH_AVAILABLE:
            self._search_index = None
            return

        try:
            # Import here to avoid errors when Whoosh not available
            from whoosh import fields

            # Create schema
            schema = fields.Schema(
                id=fields.ID(stored=True),
                question=fields.TEXT(analyzer=StemmingAnalyzer(), stored=True),
                answer=fields.TEXT(analyzer=StemmingAnalyzer()),
                category=fields.ID,
                tags=fields.KEYWORD(commas=True),
                error_codes=fields.KEYWORD(commas=True),
            )

            # Use RAM storage for speed
            storage = RamStorage()
            self._search_index = storage.create_index(schema)

            # Index existing questions
            self._reindex_all()
        except Exception as e:
            # Graceful fallback if Whoosh fails
            self.console.print(
                f"[yellow]Search index initialization failed: {e}[/yellow]"
            )
            self.console.print("[yellow]Full-text search will be unavailable[/yellow]")
            self._search_index = None

    def _populate_default_qa(self):
        """Populate with default Q&A entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check if already populated
        cursor.execute("SELECT COUNT(*) FROM questions")
        if cursor.fetchone()[0] > 0:
            conn.close()
            return

        # Default Q&A entries
        default_qa = [
            Question(
                question="How do I convert a JPEG to WebP?",
                answer="""To convert a JPEG image to WebP format:

```bash
img convert photo.jpg -f webp -o photo.webp
```

You can also control quality:
```bash
img convert photo.jpg -f webp --quality 85
```

WebP typically provides 25-35% better compression than JPEG with similar quality.""",
                category=QuestionCategory.CONVERSION,
                tags=["jpeg", "webp", "convert"],
                error_codes=[],
            ),
            Question(
                question="What does error CONV001 mean?",
                answer="""Error CONV001 indicates "File not found". This happens when:

1. The input file path is incorrect
2. The file doesn't exist at the specified location
3. You don't have permission to read the file

**Solutions:**
- Check the file path and spelling
- Use absolute paths if relative paths aren't working
- Verify file permissions with `ls -la filename`""",
                category=QuestionCategory.ERRORS,
                tags=["error", "CONV001", "file not found"],
                error_codes=["CONV001"],
            ),
            Question(
                question="How can I batch convert multiple images?",
                answer="""Use the batch command with glob patterns:

**Convert all PNG files:**
```bash
img batch *.png -f webp
```

**Recursive conversion:**
```bash
img batch '**/*.jpg' -f avif --recursive
```

**With parallel processing:**
```bash
img batch *.png -f webp --workers 8
```

**Specify output directory:**
```bash
img batch *.jpg -f webp --output-dir ./converted
```""",
                category=QuestionCategory.CONVERSION,
                tags=["batch", "multiple", "glob", "parallel"],
                error_codes=[],
            ),
            Question(
                question="How do I optimize images for web?",
                answer="""Use the optimize command with the web preset:

```bash
img optimize photo.jpg --preset web
```

This automatically:
- Chooses the best format (usually WebP)
- Sets appropriate quality (85%)
- Resizes if too large
- Strips unnecessary metadata

**For specific size targets:**
```bash
img optimize photo.jpg --target-size 100kb
```

**For lossless optimization:**
```bash
img optimize image.png --lossless
```""",
                category=QuestionCategory.OPTIMIZATION,
                tags=["optimize", "web", "preset", "performance"],
                error_codes=[],
            ),
            Question(
                question="Why is my conversion slow?",
                answer="""Slow conversions can have several causes:

**1. Large Images**
- Solution: Resize first with `--resize`

**2. Single-threaded Processing**
- Solution: Use `--workers N` for batch operations

**3. Complex Formats**
- AVIF and JPEG XL are slower to encode
- Consider WebP for faster processing

**4. High Quality Settings**
- Lower quality for faster conversion: `--quality 75`

**Performance Tips:**
```bash
# Use multiple workers
img batch *.jpg -f webp --workers 8

# Process in smaller batches
img batch *.jpg -f webp --chunk-size 10
```""",
                category=QuestionCategory.PERFORMANCE,
                tags=["slow", "performance", "speed", "optimization"],
                error_codes=[],
            ),
            Question(
                question="What formats are supported?",
                answer="""**Input Formats:**
- JPEG (.jpg, .jpeg)
- PNG (.png)
- WebP (.webp)
- HEIF/HEIC (.heif, .heic)
- BMP (.bmp)
- TIFF (.tif, .tiff)
- GIF (.gif)
- AVIF (.avif)

**Output Formats:**
- WebP - Best general purpose
- AVIF - Best compression
- JPEG XL - Next-gen JPEG
- HEIF - Apple ecosystem
- PNG - Lossless
- JPEG - Universal compatibility

Check current support:
```bash
img formats
```

For format details:
```bash
img formats --detailed webp
```""",
                category=QuestionCategory.FORMATS,
                tags=["formats", "support", "input", "output"],
                error_codes=[],
            ),
            Question(
                question="How do I handle 'out of memory' errors?",
                answer="""Memory errors (CONV500) occur with large images or batch operations.

**Solutions:**

1. **Reduce parallel workers:**
```bash
img batch *.jpg -f webp --workers 2
```

2. **Process smaller chunks:**
```bash
img batch *.jpg -f webp --chunk-size 5
```

3. **Lower quality for large images:**
```bash
img convert huge.jpg -f webp --quality 70
```

4. **Resize before conversion:**
```bash
img convert large.jpg -f webp --resize 2000x2000
```

5. **Use streaming mode (if available):**
```bash
img convert large.tiff -f jpeg --stream
```""",
                category=QuestionCategory.TROUBLESHOOTING,
                tags=["memory", "error", "CONV500", "large files"],
                error_codes=["CONV500"],
            ),
        ]

        # Insert default Q&A
        for qa in default_qa:
            self.add_question(qa)

        conn.close()

    def add_question(self, question: Question) -> int:
        """Add a new question to knowledge base"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO questions (question, answer, category, tags, error_codes, votes, views)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                question.question,
                question.answer,
                question.category.value,
                json.dumps(question.tags),
                json.dumps(question.error_codes),
                question.votes,
                question.views,
            ),
        )

        question_id = cursor.lastrowid

        # Map error codes
        for error_code in question.error_codes:
            cursor.execute(
                """
                INSERT OR REPLACE INTO error_mappings (error_code, question_id)
                VALUES (?, ?)
            """,
                (error_code, question_id),
            )

        conn.commit()
        conn.close()

        # Update search index
        if self.search_index:
            self._index_question(question_id, question)

        return question_id

    def _index_question(self, question_id: int, question: Question):
        """Add question to search index"""
        if not self.search_index:
            return

        writer = self.search_index.writer()
        writer.add_document(
            id=str(question_id),
            question=question.question,
            answer=question.answer,
            category=question.category.value,
            tags=",".join(question.tags),
            error_codes=",".join(question.error_codes),
        )
        writer.commit()

    def _reindex_all(self):
        """Reindex all questions"""
        if not self.search_index:
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM questions")
        rows = cursor.fetchall()

        writer = self.search_index.writer()
        for row in rows:
            writer.add_document(
                id=str(row[0]),
                question=row[1],
                answer=row[2],
                category=row[3],
                tags=row[4] if row[4] else "",
                error_codes=row[5] if row[5] else "",
            )
        writer.commit()

        conn.close()

    def search(self, query: str, limit: int = 10) -> List[Question]:
        """
        Search knowledge base

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of matching questions
        """
        if self.search_index and WHOOSH_AVAILABLE:
            # Use Whoosh for full-text search
            return self._whoosh_search(query, limit)
        else:
            # Fallback to SQL LIKE search
            return self._sql_search(query, limit)

    def _whoosh_search(self, query: str, limit: int) -> List[Question]:
        """Search using Whoosh full-text search"""
        parser = qparser.MultifieldParser(
            ["question", "answer", "tags", "error_codes"], self.search_index.schema
        )
        parsed_query = parser.parse(query)

        results = []
        with self.search_index.searcher() as searcher:
            search_results = searcher.search(parsed_query, limit=limit)

            for hit in search_results:
                question_id = int(hit["id"])
                question = self.get_question(question_id)
                if question:
                    results.append(question)

        return results

    def _sql_search(self, query: str, limit: int) -> List[Question]:
        """Search using SQL LIKE queries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Search in questions, answers, and tags
        cursor.execute(
            """
            SELECT * FROM questions
            WHERE question LIKE ? OR answer LIKE ? OR tags LIKE ?
            ORDER BY votes DESC, views DESC
            LIMIT ?
        """,
            (f"%{query}%", f"%{query}%", f"%{query}%", limit),
        )

        results = []
        for row in cursor.fetchall():
            question = self._row_to_question(row)
            results.append(question)

        conn.close()
        return results

    def get_question(self, question_id: int) -> Optional[Question]:
        """Get question by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM questions WHERE id = ?", (question_id,))
        row = cursor.fetchone()

        conn.close()

        if row:
            return self._row_to_question(row)
        return None

    def get_by_error_code(self, error_code: str) -> Optional[Question]:
        """Get question for specific error code"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT q.* FROM questions q
            JOIN error_mappings e ON q.id = e.question_id
            WHERE e.error_code = ?
        """,
            (error_code,),
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return self._row_to_question(row)
        return None

    def get_by_category(self, category: QuestionCategory) -> List[Question]:
        """Get questions by category"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM questions
            WHERE category = ?
            ORDER BY votes DESC, views DESC
        """,
            (category.value,),
        )

        results = []
        for row in cursor.fetchall():
            question = self._row_to_question(row)
            results.append(question)

        conn.close()
        return results

    def _row_to_question(self, row: Tuple) -> Question:
        """Convert database row to Question object"""
        return Question(
            id=row[0],
            question=row[1],
            answer=row[2],
            category=QuestionCategory(row[3]),
            tags=json.loads(row[4]) if row[4] else [],
            error_codes=json.loads(row[5]) if row[5] else [],
            votes=row[6],
            views=row[7],
            created_at=datetime.fromisoformat(row[8]) if row[8] else None,
            updated_at=datetime.fromisoformat(row[9]) if row[9] else None,
        )

    def vote(self, question_id: int, upvote: bool = True):
        """Vote on a question"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if upvote:
            cursor.execute(
                """
                UPDATE questions SET votes = votes + 1
                WHERE id = ?
            """,
                (question_id,),
            )
        else:
            cursor.execute(
                """
                UPDATE questions SET votes = votes - 1
                WHERE id = ?
            """,
                (question_id,),
            )

        conn.commit()
        conn.close()

    def increment_views(self, question_id: int):
        """Increment view count"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE questions SET views = views + 1
            WHERE id = ?
        """,
            (question_id,),
        )

        conn.commit()
        conn.close()

    def display_question(self, question: Question):
        """Display a question with formatting"""
        # Increment views
        if question.id:
            self.increment_views(question.id)

        # Build panel content
        content = []

        # Question
        content.append(f"[bold yellow]Q: {question.question}[/bold yellow]\n")

        # Answer with markdown formatting
        content.append(Markdown(question.answer))

        # Metadata
        meta = []
        if question.category:
            meta.append(f"Category: {question.category.value}")
        if question.tags:
            meta.append(f"Tags: {', '.join(question.tags)}")
        if question.error_codes:
            meta.append(f"Error Codes: {', '.join(question.error_codes)}")

        if meta:
            content.append("\n[dim]" + " | ".join(meta) + "[/dim]")

        # Stats
        content.append(f"\n[dim]👍 {question.votes} | 👁 {question.views} views[/dim]")

        # Create panel
        panel = Panel(
            content[0] + str(content[1]) + "".join(content[2:]),
            title="[cyan]Knowledge Base[/cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(panel)

    def get_troubleshooting_tree(self) -> Dict[str, List[str]]:
        """Get decision tree for troubleshooting"""
        return {
            "Conversion Issues": [
                "File not found → Check path and permissions",
                "Unsupported format → Use 'img formats' to verify",
                "Quality loss → Increase --quality value",
                "Large file size → Use optimization presets",
            ],
            "Performance Issues": [
                "Slow conversion → Use --workers for parallel",
                "Out of memory → Reduce workers or chunk size",
                "Timeout errors → Process smaller batches",
            ],
            "Format Issues": [
                "HEIC not working → Install pillow-heif",
                "AVIF not supported → Update to latest version",
                "WebP2 experimental → Use WebP instead",
            ],
        }

    def export_knowledge(self, filepath: Path):
        """Export knowledge base to JSON"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM questions ORDER BY category, votes DESC")

        questions = []
        for row in cursor.fetchall():
            question = self._row_to_question(row)
            questions.append(question.to_dict())

        conn.close()

        with open(filepath, "w") as f:
            json.dump(
                {
                    "questions": questions,
                    "total": len(questions),
                    "exported_at": datetime.now().isoformat(),
                },
                f,
                indent=2,
            )

        self.console.print(
            f"[green]✓[/green] Exported {len(questions)} Q&A entries to {filepath}"
        )
