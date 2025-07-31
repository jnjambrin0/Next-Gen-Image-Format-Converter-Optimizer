# Contributing to Image Converter

Thank you for your interest in contributing to Image Converter! This document provides guidelines and instructions for setting up the development environment and contributing to the project.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Node.js 20 or higher
- Git
- Docker and Docker Compose (optional, for containerized development)

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/image-converter.git
   cd image-converter
   ```

2. **Set up Python backend**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements-dev.txt
   ```

3. **Set up frontend**
   ```bash
   cd ../frontend
   npm install
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

### Running the Application

#### Option 1: Local Development

1. **Start the backend** (from backend directory):
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

2. **Start the frontend** (from frontend directory):
   ```bash
   npm run dev
   ```

3. **Access the application** at http://localhost:5173

#### Option 2: Docker Development

```bash
docker-compose up
```

## Development Workflow

### Code Style

- **Python**: We use Black for formatting, Flake8 for linting, and MyPy for type checking
- **JavaScript**: We use ESLint for linting and Prettier for formatting
- **Commits**: Follow conventional commit format (e.g., `feat:`, `fix:`, `docs:`)

### Testing

#### Backend Tests
```bash
cd backend
pytest tests/ -v
pytest tests/ --cov=app  # With coverage
```

#### Frontend Tests
```bash
cd frontend
npm run lint
npm run build
```

### Pre-commit Hooks

Pre-commit hooks automatically run on every commit to ensure code quality:
- Python formatting with Black
- JavaScript formatting with Prettier
- Linting checks
- Security scans
- Large file prevention

To run manually:
```bash
pre-commit run --all-files
```

## Project Structure

```
image-converter/
├── backend/          # Python FastAPI backend
│   ├── app/         # Application code
│   ├── tests/       # Test files
│   └── Dockerfile   # Backend container
├── frontend/        # JavaScript frontend
│   ├── src/         # Source code
│   └── public/      # Static assets
├── ml_models/       # Machine learning models
├── scripts/         # Utility scripts
└── docs/           # Documentation
```

## Coding Standards

### Python
- Follow PEP 8 with Black formatting
- Use type hints for all functions
- Write docstrings for all public functions and classes
- Maintain test coverage above 80%

### JavaScript
- Use ES2022+ features
- Follow ESLint rules
- Use meaningful variable and function names
- Keep functions small and focused

### Security
- Never log sensitive information
- Always validate user input
- Use parameterized queries
- Keep dependencies updated

## Submitting Changes

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Run tests and linting**
5. **Commit with meaningful messages**
6. **Push to your fork**
7. **Create a Pull Request**

### Pull Request Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Ensure all tests pass
- Include screenshots for UI changes
- Update documentation as needed

## Getting Help

- Check existing issues and discussions
- Join our community chat (if available)
- Review the architecture documentation in `/docs/architecture/`
- Contact maintainers for complex questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.