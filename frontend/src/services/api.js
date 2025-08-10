import { API_CONFIG } from '../config/constants.js'

/**
 * API service for image conversion operations
 */

/**
 * Generic API client for making HTTP requests
 */
export const apiClient = {
  async get(endpoint) {
    const response = await fetch(`${API_CONFIG.BASE_URL}${endpoint}`)
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    return response
  },

  async post(endpoint, data) {
    const response = await fetch(`${API_CONFIG.BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    return response
  },

  async put(endpoint, data) {
    const response = await fetch(`${API_CONFIG.BASE_URL}${endpoint}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    return response
  },

  async delete(endpoint) {
    const response = await fetch(`${API_CONFIG.BASE_URL}${endpoint}`, {
      method: 'DELETE',
    })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    return response
  },

  /**
   * POST request with FormData (for file uploads)
   * @param {string} endpoint - API endpoint
   * @param {FormData} formData - FormData object with files and fields
   * @param {Object} options - Additional options (e.g., timeout)
   * @returns {Promise<Response>} The fetch response
   */
  async postForm(endpoint, formData, options = {}) {
    const controller = new AbortController()
    const timeoutId = setTimeout(
      () => controller.abort(),
      options.timeout || API_CONFIG.TIMEOUT
    )

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${endpoint}`, {
        method: 'POST',
        body: formData,
        signal: controller.signal,
        // Note: Don't set Content-Type header - browser will set it with boundary for FormData
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new APIError(
          response.status,
          errorData.detail || getDefaultErrorMessage(response.status),
          errorData.error_code
        )
      }

      return response
    } catch (error) {
      clearTimeout(timeoutId)

      if (error.name === 'AbortError') {
        throw new APIError(0, 'Request timed out. Please try again.', 'TIMEOUT')
      }

      if (error instanceof APIError) {
        throw error
      }

      throw new APIError(0, 'Network error. Please check your connection.', 'NETWORK_ERROR')
    }
  },
}

/**
 * Convert an image file to the specified format
 * @param {File} file - The image file to convert
 * @param {string} outputFormat - Target format (webp, avif, etc.)
 * @param {number} quality - Quality setting (1-100)
 * @param {boolean} preserveMetadata - Whether to preserve metadata (except GPS)
 * @param {string|null} presetId - Optional preset ID to apply
 * @returns {Promise<{blob: Blob, filename: string}>} The converted image blob and filename
 * @throws {Error} API errors with specific codes and messages
 */
export async function convertImage(
  file,
  outputFormat,
  quality = 85,
  preserveMetadata = false,
  presetId = null
) {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('output_format', outputFormat)
  formData.append('quality', quality.toString())
  formData.append('preserve_metadata', preserveMetadata.toString())
  formData.append('strip_metadata', (!preserveMetadata).toString())

  if (presetId) {
    formData.append('preset_id', presetId)
  }

  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT)

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CONVERT}`, {
      method: 'POST',
      body: formData,
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || getDefaultErrorMessage(response.status),
        errorData.error_code
      )
    }

    // Extract filename from Content-Disposition header
    const contentDisposition = response.headers.get('Content-Disposition')
    const filename = extractFilename(contentDisposition) || `converted_image.${outputFormat}`

    // Get the binary data
    const blob = await response.blob()

    return { blob, filename }
  } catch (error) {
    clearTimeout(timeoutId)

    if (error.name === 'AbortError') {
      throw new APIError(0, 'Request timed out. Please try again.', 'TIMEOUT')
    }

    if (error instanceof APIError) {
      throw error
    }

    throw new APIError(0, 'Network error. Please check your connection.', 'NETWORK_ERROR')
  }
}

/**
 * Custom error class for API errors
 */
export class APIError extends Error {
  constructor(status, message, errorCode) {
    super(message)
    this.name = 'APIError'
    this.status = status
    this.errorCode = errorCode
  }
}

/**
 * Extract filename from Content-Disposition header with improved parsing
 * @param {string} contentDisposition - The Content-Disposition header value
 * @returns {string|null} The extracted filename or null
 */
function extractFilename(contentDisposition) {
  if (!contentDisposition) {
    return null
  }

  // Try different filename patterns
  const patterns = [
    /filename\*=UTF-8''(.+)/, // RFC 5987 encoded
    /filename="([^"]+)"/, // Quoted filename
    /filename=([^;\s]+)/, // Unquoted filename
  ]

  for (const pattern of patterns) {
    const match = contentDisposition.match(pattern)
    if (match) {
      let filename = match[1]
      // Decode URI component if it looks encoded
      try {
        if (filename.includes('%')) {
          filename = decodeURIComponent(filename)
        }
      } catch (e) {
        // If decoding fails, use original
      }
      return filename
    }
  }

  return null
}

/**
 * Get default error message based on HTTP status code
 * @param {number} status - HTTP status code
 * @returns {string} Default error message
 */
function getDefaultErrorMessage(status) {
  const errorMessages = {
    400: 'Invalid request. Please check your file and try again.',
    413: 'File too large. Maximum allowed size is 50MB.',
    415: 'Unsupported file type. Please select a valid image file.',
    422: 'Invalid conversion parameters. Please try again.',
    500: 'Server error. Please try again later.',
    503: 'Service temporarily unavailable. Please try again in a moment.',
  }

  return errorMessages[status] || 'An unexpected error occurred. Please try again.'
}

/**
 * Map backend error codes to user-friendly messages
 * @param {string} errorCode - Backend error code (CONV201-CONV299)
 * @returns {string} User-friendly error message
 */
export function mapErrorCodeToMessage(errorCode) {
  const errorCodeMap = {
    CONV201: 'Invalid image file. The file may be corrupted.',
    CONV202: 'Unsupported input format.',
    CONV203: 'Unsupported output format.',
    CONV204: 'Image dimensions too large.',
    CONV205: 'Processing timeout. The image may be too complex.',
    CONV206: 'Memory limit exceeded. The image is too large to process.',
    CONV207: 'Invalid quality parameter. Must be between 1 and 100.',
    CONV250: 'Security check failed. The file may contain malicious content.',
    CONV299: 'Unknown conversion error.',
  }

  return errorCodeMap[errorCode] || 'An error occurred during conversion.'
}

// =============================================================================
// ENHANCED V1 API FUNCTIONS
// =============================================================================

/**
 * Detect image format from file content (v1 API)
 * @param {File} file - Image file to analyze
 * @returns {Promise<Object>} Format detection results
 */
export async function detectImageFormat(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await apiClient.postForm(API_CONFIG.ENDPOINTS.DETECT_FORMAT, formData)
  return response.json()
}

/**
 * Get format recommendations based on image content (v1 API)
 * @param {File} file - Image file to analyze
 * @returns {Promise<Object>} Format recommendations with scores
 */
export async function getFormatRecommendations(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await apiClient.postForm(API_CONFIG.ENDPOINTS.RECOMMEND_FORMAT, formData)
  return response.json()
}

/**
 * Get format compatibility matrix (v1 API)
 * @returns {Promise<Object>} Complete format compatibility information
 */
export async function getFormatCompatibility() {
  const response = await apiClient.get(API_CONFIG.ENDPOINTS.FORMAT_COMPATIBILITY)
  return response.json()
}

/**
 * List presets with advanced filtering and pagination (v1 API)
 * @param {Object} options - Filtering and pagination options
 * @returns {Promise<Object>} Paginated preset list with metadata
 */
export async function listPresets(options = {}) {
  const params = new URLSearchParams()

  if (options.search) {
    params.append('search', options.search)
  }
  if (options.formatFilter) {
    params.append('format_filter', options.formatFilter)
  }
  if (options.sortBy) {
    params.append('sort_by', options.sortBy)
  }
  if (options.sortOrder) {
    params.append('sort_order', options.sortOrder)
  }
  if (options.limit) {
    params.append('limit', options.limit)
  }
  if (options.offset) {
    params.append('offset', options.offset)
  }
  if (options.includeBuiltin !== undefined) {
    params.append('include_builtin', options.includeBuiltin)
  }

  const endpoint = params.toString()
    ? `${API_CONFIG.ENDPOINTS.PRESETS}?${params}`
    : API_CONFIG.ENDPOINTS.PRESETS
  const response = await apiClient.get(endpoint)
  return response.json()
}

/**
 * Advanced preset search with fuzzy matching (v1 API)
 * @param {string} query - Search query
 * @param {Object} filters - Advanced search filters
 * @returns {Promise<Object>} Ranked search results
 */
export async function searchPresets(query, filters = {}) {
  const params = new URLSearchParams()
  params.append('q', query)

  if (filters.formats) {
    params.append('formats', filters.formats.join(','))
  }
  if (filters.minQuality) {
    params.append('min_quality', filters.minQuality)
  }
  if (filters.maxQuality) {
    params.append('max_quality', filters.maxQuality)
  }
  if (filters.optimizationModes) {
    params.append('optimization_modes', filters.optimizationModes.join(','))
  }
  if (filters.minUsage) {
    params.append('min_usage', filters.minUsage)
  }
  if (filters.includeBuiltin !== undefined) {
    params.append('include_builtin', filters.includeBuiltin)
  }
  if (filters.limit) {
    params.append('limit', filters.limit)
  }
  if (filters.offset) {
    params.append('offset', filters.offset)
  }

  const response = await apiClient.get(`${API_CONFIG.ENDPOINTS.PRESET_SEARCH}?${params}`)
  return response.json()
}

/**
 * Get preset by ID with enhanced details (v1 API)
 * @param {string} presetId - Preset UUID
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} Complete preset details
 */
export async function getPreset(presetId, options = {}) {
  const params = new URLSearchParams()
  if (options.includeUsage) {
    params.append('include_usage', 'true')
  }
  if (options.version) {
    params.append('version', options.version)
  }

  const endpoint = params.toString()
    ? `${API_CONFIG.ENDPOINTS.PRESETS}/${presetId}?${params}`
    : `${API_CONFIG.ENDPOINTS.PRESETS}/${presetId}`
  const response = await apiClient.get(endpoint)
  return response.json()
}

/**
 * Create new preset with validation (v1 API)
 * @param {Object} presetData - Preset configuration
 * @returns {Promise<Object>} Created preset with version info
 */
export async function createPreset(presetData) {
  const response = await apiClient.post(API_CONFIG.ENDPOINTS.PRESETS, presetData)
  return response.json()
}

/**
 * Update existing preset with version tracking (v1 API)
 * @param {string} presetId - Preset UUID
 * @param {Object} updateData - Fields to update
 * @param {string} versionNote - Optional change description
 * @returns {Promise<Object>} Updated preset with new version
 */
export async function updatePreset(presetId, updateData, versionNote = null) {
  const params = new URLSearchParams()
  if (versionNote) {
    params.append('version_note', versionNote)
  }

  const endpoint = params.toString()
    ? `${API_CONFIG.ENDPOINTS.PRESETS}/${presetId}?${params}`
    : `${API_CONFIG.ENDPOINTS.PRESETS}/${presetId}`
  const response = await apiClient.put(endpoint, updateData)
  return response.json()
}

/**
 * Delete preset with safety checks (v1 API)
 * @param {string} presetId - Preset UUID
 * @param {boolean} force - Force deletion (admin only)
 * @returns {Promise<void>} Deletion confirmation
 */
export async function deletePreset(presetId, force = false) {
  const params = new URLSearchParams()
  if (force) {
    params.append('force', 'true')
  }

  const endpoint = params.toString()
    ? `${API_CONFIG.ENDPOINTS.PRESETS}/${presetId}?${params}`
    : `${API_CONFIG.ENDPOINTS.PRESETS}/${presetId}`
  await apiClient.delete(endpoint)
}

/**
 * Get preset version history (v1 API)
 * @param {string} presetId - Preset UUID
 * @param {Object} options - History options
 * @returns {Promise<Array>} Version history list
 */
export async function getPresetVersions(presetId, options = {}) {
  const params = new URLSearchParams()
  if (options.limit) {
    params.append('limit', options.limit)
  }
  if (options.includeContent) {
    params.append('include_content', 'true')
  }

  const endpoint = API_CONFIG.ENDPOINTS.PRESET_VERSIONS(presetId)
  const finalEndpoint = params.toString() ? `${endpoint}?${params}` : endpoint
  const response = await apiClient.get(finalEndpoint)
  return response.json()
}

/**
 * Restore preset to previous version (v1 API)
 * @param {string} presetId - Preset UUID
 * @param {string} version - Version to restore to
 * @param {string} restoreNote - Optional restoration note
 * @returns {Promise<Object>} Restored preset
 */
export async function restorePresetVersion(presetId, version, restoreNote = null) {
  const params = new URLSearchParams()
  if (restoreNote) {
    params.append('restore_note', restoreNote)
  }

  const endpoint = API_CONFIG.ENDPOINTS.PRESET_RESTORE(presetId, version)
  const finalEndpoint = params.toString() ? `${endpoint}?${params}` : endpoint
  const response = await apiClient.post(finalEndpoint)
  return response.json()
}

/**
 * Export preset with metadata (v1 API)
 * @param {string} presetId - Preset UUID
 * @param {Object} options - Export options
 * @returns {Promise<Object>} Export package
 */
export async function exportPreset(presetId, options = {}) {
  const params = new URLSearchParams()
  if (options.includeHistory) {
    params.append('include_history', 'true')
  }
  if (options.includeUsage) {
    params.append('include_usage', 'true')
  }
  if (options.formatVersion) {
    params.append('format_version', options.formatVersion)
  }

  const endpoint = API_CONFIG.ENDPOINTS.PRESET_EXPORT(presetId)
  const finalEndpoint = params.toString() ? `${endpoint}?${params}` : endpoint
  const response = await apiClient.get(finalEndpoint)
  return response.json()
}

/**
 * Import presets with conflict resolution (v1 API)
 * @param {Object} importData - Presets to import
 * @param {string} conflictStrategy - How to handle conflicts (skip, overwrite, rename)
 * @param {boolean} validateSettings - Perform deep validation
 * @returns {Promise<Array>} Successfully imported presets
 */
export async function importPresets(
  importData,
  conflictStrategy = 'skip',
  validateSettings = true
) {
  const params = new URLSearchParams()
  params.append('conflict_strategy', conflictStrategy)
  params.append('validate_settings', validateSettings)

  const response = await apiClient.post(
    `${API_CONFIG.ENDPOINTS.PRESET_IMPORT}?${params}`,
    importData
  )
  return response.json()
}

/**
 * Export all user presets (v1 API)
 * @param {Object} options - Export filtering options
 * @returns {Promise<Array>} All user presets for export
 */
export async function exportAllPresets(options = {}) {
  const params = new URLSearchParams()
  if (options.formatFilter) {
    params.append('format_filter', options.formatFilter)
  }
  if (options.includeUnused !== undefined) {
    params.append('include_unused', options.includeUnused)
  }
  if (options.exportFormat) {
    params.append('export_format', options.exportFormat)
  }

  const endpoint = params.toString()
    ? `${API_CONFIG.ENDPOINTS.PRESETS_EXPORT_ALL}?${params}`
    : API_CONFIG.ENDPOINTS.PRESETS_EXPORT_ALL
  const response = await apiClient.get(endpoint)
  return response.json()
}
