/**
 * Application configuration constants
 */

// UI Timing Constants (in milliseconds)
export const UI_TIMING = {
  PROCESSING_SIMULATION: 1500,
  SUCCESS_MESSAGE_DURATION: 2000,
  ERROR_MESSAGE_DURATION: 5000,
  ANIMATION_DURATION: 300,
}

// API Configuration
export const API_CONFIG = {
  BASE_URL: '/api/v1', // Updated to use versioned API
  LEGACY_BASE_URL: '/api', // Fallback for legacy endpoints
  TIMEOUT: 30000, // 30 seconds
  VERSION: 'v1',
  ENDPOINTS: {
    // Core conversion endpoints
    CONVERT: '/convert',
    HEALTH: '/health',
    FORMATS: '/formats',

    // Detection and analysis
    DETECT_FORMAT: '/detection/detect-format',
    RECOMMEND_FORMAT: '/detection/recommend-format',
    FORMAT_COMPATIBILITY: '/detection/formats/compatibility',

    // Preset management with advanced features
    PRESETS: '/presets',
    PRESET_SEARCH: '/presets/search/advanced',
    PRESET_VERSIONS: (id) => `/presets/${id}/versions`,
    PRESET_RESTORE: (id, version) => `/presets/${id}/versions/${version}/restore`,
    PRESET_EXPORT: (id) => `/presets/${id}/export`,
    PRESET_IMPORT: '/presets/import',
    PRESETS_EXPORT_ALL: '/presets/export/all',

    // Batch processing with enhanced features
    BATCH: '/batch',
    BATCH_STATUS: (id) => `/batch/${id}/status`,
    BATCH_CANCEL: (id) => `/batch/${id}`,
    BATCH_CANCEL_ITEM: (id, index) => `/batch/${id}/items/${index}`,
    BATCH_DOWNLOAD: (id) => `/batch/${id}/download`,
    BATCH_RESULTS: (id) => `/batch/${id}/results`,
    BATCH_METRICS: (id) => `/batch/${id}/metrics`,
    BATCH_EVENTS: (id) => `/batch/${id}/events`, // Server-Sent Events
    BATCH_WEBSOCKET_TOKEN: (id) => `/batch/${id}/websocket-token`,

    // Monitoring and system info
    MONITORING_STATS: '/monitoring/stats',
    MONITORING_ERRORS: '/monitoring/errors',
    SECURITY_STATUS: '/security/status',
    INTELLIGENCE_CAPABILITIES: '/intelligence/capabilities',
    OPTIMIZATION_PRESETS: '/optimization/presets',
  },

  // Request headers for API versioning
  HEADERS: {
    'Accept-Version': 'v1',
    'Content-Type': 'application/json',
  },

  // Error code mappings for better error handling
  ERROR_CODES: {
    // Conversion errors
    CONV201: 'Invalid conversion request',
    CONV400: 'Bad conversion parameters',
    CONV413: 'File too large',
    CONV415: 'Unsupported file format',
    CONV422: 'Invalid image data',
    CONV500: 'Conversion failed',

    // Batch errors
    BAT201: 'Invalid batch request',
    BAT400: 'Bad batch parameters',
    BAT404: 'Batch job not found',
    BAT500: 'Batch processing failed',

    // Detection errors
    DET400: 'Invalid detection request',
    DET413: 'File too large for analysis',
    DET503: 'Detection service unavailable',

    // Preset errors
    PRE400: 'Invalid preset data',
    PRE403: 'Cannot modify built-in preset',
    PRE404: 'Preset not found',
    PRE409: 'Preset name conflict',
    PRE500: 'Preset operation failed',
  },
}

// File Processing Configuration
export const FILE_CONFIG = {
  MAX_SIZE: 50 * 1024 * 1024, // 50MB in bytes
  MAX_BATCH_SIZE: 100, // Maximum files per batch
  CHUNK_SIZE: 1024 * 1024, // 1MB chunks for large file handling
  SUPPORTED_FORMATS: {
    INPUT: ['jpg', 'jpeg', 'png', 'webp', 'heif', 'heic', 'bmp', 'tiff', 'gif', 'avif'],
    OUTPUT: [
      'webp',
      'avif',
      'jpeg',
      'png',
      'jxl',
      'heif',
      'jpeg_optimized',
      'png_optimized',
      'webp2',
    ],
  },
}

// UI State Transition Rules
export const STATE_TRANSITIONS = {
  IDLE: ['DRAGGING', 'PROCESSING'],
  DRAGGING: ['IDLE', 'PROCESSING'],
  PROCESSING: ['SUCCESS', 'ERROR'],
  SUCCESS: ['IDLE'],
  ERROR: ['IDLE'],
}

// Feature Flags
export const FEATURE_FLAGS = {
  // Enable unified settings panel for both single and batch modes
  UNIFIED_SETTINGS:
    process.env.NODE_ENV === 'development' ||
    localStorage.getItem('feature_unified_settings') === 'true',

  // Enable refactored unified settings with smaller sub-components
  REFACTORED_SETTINGS:
    process.env.NODE_ENV === 'development' ||
    localStorage.getItem('feature_refactored_settings') === 'true',

  // Helper function to check feature flag
  isEnabled(flag) {
    return this[flag] === true
  },

  // Helper function to enable/disable feature flag
  setFlag(flag, enabled) {
    if (flag === 'UNIFIED_SETTINGS') {
      localStorage.setItem('feature_unified_settings', enabled ? 'true' : 'false')
      // Reload to apply changes
      window.location.reload()
    }
  },
}
