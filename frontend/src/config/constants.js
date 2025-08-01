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
  BASE_URL: '/api',
  TIMEOUT: 30000, // 30 seconds
  ENDPOINTS: {
    CONVERT: '/convert',
    HEALTH: '/health',
    FORMATS: '/formats',
    DETECT: '/detect',
    PRESETS: '/presets',
  },
}

// File Processing Configuration
export const FILE_CONFIG = {
  MAX_SIZE: 50 * 1024 * 1024, // 50MB in bytes
  CHUNK_SIZE: 1024 * 1024, // 1MB chunks for large file handling
}

// UI State Transition Rules
export const STATE_TRANSITIONS = {
  IDLE: ['DRAGGING', 'PROCESSING'],
  DRAGGING: ['IDLE', 'PROCESSING'],
  PROCESSING: ['SUCCESS', 'ERROR'],
  SUCCESS: ['IDLE'],
  ERROR: ['IDLE'],
}
