# Frontend Environment Configuration

## Quick Start

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Update the values in `.env` as needed:
   ```bash
   # Default configuration
   VITE_API_PORT=8000
   VITE_API_HOST=localhost
   ```

## Available Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_PORT` | `8080` | Port where the backend API is running |
| `VITE_API_HOST` | `localhost` | Host where the backend API is running |

## Usage Examples

### Local Development (Default)
```bash
# .env
VITE_API_PORT=8080
VITE_API_HOST=localhost
```

### Different Backend Port
```bash
# .env
VITE_API_PORT=8080
VITE_API_HOST=localhost
```

### Remote Backend
```bash
# .env
VITE_API_PORT=3000
VITE_API_HOST=api.example.com
```

## Important Notes

- All environment variables must be prefixed with `VITE_` to be accessible in the frontend code
- Changes to `.env` require restarting the Vite dev server
- The `.env` file is gitignored and should not be committed
- Use `.env.local` for personal overrides (also gitignored)
- The proxy configuration is logged to console when starting the dev server

## Troubleshooting

If you're getting proxy errors like `ECONNREFUSED`:

1. Check that the backend is running on the configured port
2. Verify the environment variables are set correctly
3. Restart the Vite dev server after changing `.env`
4. Check the console output for the proxy configuration message