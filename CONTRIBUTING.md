# Contributing to Next-Gen Image Format Converter & Optimizer

First off, thank you for considering contributing to our project! 🎉 Your help makes this privacy-focused image converter better for everyone.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Process](#development-process)
- [Setting Up Your Development Environment](#setting-up-your-development-environment)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Feature Requests](#feature-requests)
- [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

### Our Pledge

We are committed to providing a friendly, safe, and welcoming environment for all contributors, regardless of:
- Experience level
- Gender identity and expression
- Sexual orientation
- Disability
- Personal appearance
- Body size
- Race, ethnicity, or religion
- Nationality

### Our Standards

**Examples of behavior that contributes to a positive environment:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Examples of unacceptable behavior:**
- The use of sexualized language or imagery
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at jnjambrino@github.com. All complaints will be reviewed and investigated promptly and fairly.

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

1. **Clear Title**: Summarize the issue in one line
2. **Environment Details**:
   - OS and version
   - Python version
   - Node.js version (if frontend-related)
   - Browser (if web UI-related)
3. **Steps to Reproduce**:
   - List exact steps to reproduce the issue
   - Include code samples if applicable
   - Attach sample images (ensure no sensitive content)
4. **Expected vs Actual Behavior**: Clearly describe what should happen vs what actually happens
5. **Screenshots/Logs**: If applicable, add screenshots or error logs (sanitized of any PII)

**Bug Report Template:**
```markdown
## Bug Description
[Clear description of the bug]

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.11.5]
- Node.js: [e.g., 18.17.0]
- Browser: [e.g., Chrome 120]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [...]

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happens]

## Additional Context
[Any other relevant information, logs, screenshots]
```

### 💡 Suggesting Features

We love feature suggestions! Please provide:

1. **Use Case**: Explain the problem your feature would solve
2. **Proposed Solution**: Describe how you envision the feature working
3. **Alternatives Considered**: List any alternative solutions you've thought about
4. **Additional Context**: Add mockups, examples, or references

**Feature Request Template:**
```markdown
## Feature Description
[Clear description of the feature]

## Problem It Solves
[What problem does this feature address?]

## Proposed Implementation
[How would this feature work?]

## Alternatives Considered
[Other ways to solve this problem]

## Additional Context
[Mockups, examples, references]
```

### 🔧 Contributing Code

#### First-Time Contributors

Look for issues labeled with:
- `good first issue` - Simple tasks perfect for beginners
- `help wanted` - Issues where we need community help
- `documentation` - Documentation improvements

#### Areas We Need Help

1. **🌍 Internationalization**: Adding language support
2. **🧪 Testing**: Increasing test coverage
3. **📚 Documentation**: Improving guides and examples
4. **🎨 UI/UX**: Enhancing the web interface
5. **🚀 Performance**: Optimization opportunities
6. **🔧 New Formats**: Adding support for additional image formats

## Development Process

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/Next-Gen-Image-Format-Converter-Optimizer.git
cd Next-Gen-Image-Format-Converter-Optimizer
git remote add upstream https://github.com/jnjambrino/Next-Gen-Image-Format-Converter-Optimizer.git
```

### 2. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create your feature branch
git checkout -b feature/your-feature-name
# Or for bugs:
git checkout -b fix/bug-description
```

### 3. Make Your Changes

Follow our [coding standards](#coding-standards) and ensure all tests pass.

### 4. Commit Your Changes

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: <type>(<scope>): <subject>

# Examples:
git commit -m "feat(api): add HEIF format support"
git commit -m "fix(cli): resolve path traversal issue"
git commit -m "docs(readme): update installation instructions"
git commit -m "test(security): add sandboxing tests"
git commit -m "refactor(core): optimize memory usage"
```

**Commit Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `security`: Security improvements

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Setting Up Your Development Environment

### Backend Development

```bash
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Run the backend
uvicorn app.main:app --reload --port 8080
```

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

### CLI Development

```bash
cd backend

# Install in development mode
pip install -e .

# Test CLI commands
img --help
img convert test.jpg -f webp
```

### Running Tests

```bash
# Backend tests
cd backend
pytest                     # All tests
pytest tests/unit/        # Unit tests only
pytest tests/integration/ # Integration tests
pytest tests/security/    # Security tests
pytest --cov=app          # With coverage report

# Frontend tests
cd frontend
npm test                   # Run tests
npm run test:coverage     # With coverage
npm run test:ui           # Interactive UI
```

## Coding Standards

### Python (Backend)

1. **Style Guide**: Follow PEP 8
2. **Formatting**: Use Black formatter
   ```bash
   black backend/
   ```
3. **Type Hints**: Required for all functions
   ```python
   def convert_image(
       input_data: bytes,
       output_format: str,
       quality: int = 85
   ) -> Tuple[bytes, ConversionResult]:
       """Convert image to specified format.
       
       Args:
           input_data: Raw image bytes
           output_format: Target format (webp, avif, etc.)
           quality: Output quality (1-100)
           
       Returns:
           Tuple of converted bytes and result metadata
       """
   ```
4. **Docstrings**: Use Google style
5. **Imports**: Sort with isort
   ```bash
   isort backend/
   ```

### JavaScript (Frontend)

1. **Style Guide**: ESLint with Prettier
2. **Formatting**: 
   ```bash
   npm run format
   ```
3. **Linting**:
   ```bash
   npm run lint
   ```
4. **Component Structure**:
   ```javascript
   // Use functional components with clear naming
   export function ImageUploader({ onUpload, maxSize }) {
       // Component logic
   }
   ```

### Security Guidelines

**CRITICAL**: Always follow these security practices:

1. **Never log PII**: No filenames, paths, or user data in logs
2. **Validate all inputs**: Sanitize and validate before processing
3. **Use sandboxing**: All image processing must be sandboxed
4. **Memory management**: Clear sensitive data with secure patterns
5. **Path validation**: Prevent directory traversal attacks

Example of secure error handling:
```python
# CORRECT: Generic error without PII
logger.error("File processing failed: invalid format")

# WRONG: Exposes user data
logger.error(f"Failed to process {filename}")  # Never do this!
```

## Testing Guidelines

### Test Coverage Requirements

- **New features**: Must have >80% test coverage
- **Bug fixes**: Must include regression tests
- **Security features**: Must have comprehensive security tests

### Writing Tests

#### Python Tests
```python
import pytest
from app.core.conversion import convert_image

def test_webp_conversion():
    """Test JPEG to WebP conversion."""
    # Arrange
    with open("tests/fixtures/sample.jpg", "rb") as f:
        input_data = f.read()
    
    # Act
    result, output = convert_image(
        input_data,
        output_format="webp",
        quality=85
    )
    
    # Assert
    assert result.success
    assert result.output_format == "webp"
    assert len(output) > 0
```

#### JavaScript Tests
```javascript
import { describe, it, expect } from 'vitest';
import { validateImageSize } from '../utils/validation';

describe('Image Validation', () => {
    it('should reject oversized images', () => {
        const result = validateImageSize(100 * 1024 * 1024); // 100MB
        expect(result.valid).toBe(false);
        expect(result.error).toContain('size');
    });
});
```

## Submitting Changes

### Pull Request Process

1. **Update Documentation**: If your change affects usage, update relevant docs
2. **Add Tests**: Include tests for new functionality
3. **Pass CI Checks**: Ensure all automated tests pass
4. **Update CHANGELOG**: Add your changes to the unreleased section
5. **Request Review**: Tag appropriate reviewers

### PR Template

```markdown
## Description
[Describe your changes]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No security vulnerabilities introduced
- [ ] No PII in logs or error messages
```

### Review Process

1. **Automated Checks**: CI/CD runs tests and linting
2. **Code Review**: At least one maintainer reviews
3. **Security Review**: For security-related changes
4. **Testing**: Manual testing if needed
5. **Merge**: Squash and merge to main branch

## Reporting Issues

### Security Vulnerabilities

**NEVER** report security vulnerabilities through public issues. Instead:

1. Email: jnjambrino@github.com
2. Subject: "SECURITY: [Brief description]"
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work on a fix immediately.

### General Issues

Use GitHub Issues for:
- Bug reports
- Feature requests
- Documentation issues
- Performance problems

## Feature Requests

We're always looking for ideas to improve the project! When suggesting features:

1. **Check existing issues** to avoid duplicates
2. **Explain the use case** clearly
3. **Consider privacy implications**
4. **Think about performance impact**
5. **Suggest implementation approach** if possible

## Recognition

Contributors who make significant contributions will be:
- Added to the README contributors section
- Mentioned in release notes
- Given credit in relevant documentation

## Questions?

Feel free to:
- Open a discussion on GitHub Discussions
- Contact the maintainers
- Join our community chat (coming soon)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to making image conversion more private, secure, and efficient! 🚀