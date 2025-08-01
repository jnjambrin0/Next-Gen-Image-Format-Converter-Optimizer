import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  // Load env file based on mode
  const env = loadEnv(mode, process.cwd(), '')

  // Get backend configuration from environment variables
  const backendHost = env.VITE_API_HOST || 'localhost'
  const backendPort = env.VITE_API_PORT || '8080'
  const backendUrl = `http://${backendHost}:${backendPort}`
  const backendWsUrl = `ws://${backendHost}:${backendPort}`

  // Log configuration in development mode only
  if (mode === 'development') {
    // eslint-disable-next-line no-console
    console.log(`Vite proxy configured to forward requests to: ${backendUrl}`)
  }

  return {
    server: {
      port: 5173,
      proxy: {
        '/api': {
          target: backendUrl,
          changeOrigin: true,
        },
        '/ws': {
          target: backendWsUrl,
          ws: true,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
      rollupOptions: {
        output: {
          manualChunks: {
            lucide: ['lucide'],
          },
        },
      },
    },
  }
})
