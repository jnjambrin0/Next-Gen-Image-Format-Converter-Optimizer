import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  // Load env file based on mode
  const env = loadEnv(mode, process.cwd(), '')

  // Get backend configuration from environment variables
  const backendHost = env.VITE_API_HOST || 'localhost'
  const backendPort = env.VITE_API_PORT || '8000'
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
      sourcemap: mode === 'development',
      minify: 'terser',
      target: 'es2020',
      reportCompressedSize: false, // Speeds up build
      chunkSizeWarningLimit: 1000, // KB
      rollupOptions: {
        output: {
          // Optimize chunk splitting - only create chunks if they'll be substantial
          manualChunks(id) {
            // Only chunk vendor dependencies that are substantial
            if (id.includes('node_modules')) {
              // Group all vendor dependencies together for now
              return 'vendor'
            }
          },
          // Optimize asset names for caching
          chunkFileNames: mode === 'production' ? 'assets/[name]-[hash].js' : 'assets/[name].js',
          entryFileNames: mode === 'production' ? 'assets/[name]-[hash].js' : 'assets/[name].js',
          assetFileNames: mode === 'production' ? 'assets/[name]-[hash].[ext]' : 'assets/[name].[ext]',
        },
        treeshake: {
          moduleSideEffects: false,
          propertyReadSideEffects: false,
          tryCatchDeoptimization: false,
        },
      },
    },
    optimizeDeps: {
      // Pre-bundle dependencies for faster dev server startup
      include: ['lucide'],
      exclude: [],
    },
    // Enable CSS code splitting
    css: {
      devSourcemap: mode === 'development',
      preprocessorOptions: {
        css: {
          charset: false, // Avoid charset issues
        },
      },
    },
    // Performance optimizations
    esbuild: {
      drop: mode === 'production' ? ['console', 'debugger'] : [],
      legalComments: 'none',
    },
    // Environment optimization
    define: {
      __DEV__: mode === 'development',
      __PROD__: mode === 'production',
    },
  }
})
