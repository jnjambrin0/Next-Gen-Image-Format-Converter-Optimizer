import { API_CONFIG } from '../config/constants.js'
import { APIError } from './api.js'

/**
 * Batch API service for batch conversion operations
 */

/**
 * Create a batch conversion job
 * @param {File[]} files - Array of image files to convert
 * @param {Object} settings - Conversion settings
 * @returns {Promise<Object>} Batch job creation response
 */
export async function createBatchJob(files, settings) {
  const formData = new FormData()

  // Add files
  files.forEach((file) => {
    formData.append('files', file)
  })

  // Add settings
  formData.append('output_format', settings.outputFormat)
  if (settings.quality !== undefined) {
    formData.append('quality', settings.quality.toString())
  }
  if (settings.optimizationMode) {
    formData.append('optimization_mode', settings.optimizationMode)
  }
  if (settings.presetId) {
    formData.append('preset_id', settings.presetId)
  }
  formData.append('preserve_metadata', settings.preserveMetadata || false)

  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT * 2) // Longer timeout for batch

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/batch/`, {
      method: 'POST',
      body: formData,
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || getDefaultBatchErrorMessage(response.status),
        errorData.error_code
      )
    }

    return await response.json()
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
 * Get batch job status
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Batch job status
 */
export async function getBatchStatus(jobId) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT)

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/batch/${jobId}/status`, {
      method: 'GET',
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || 'Failed to get batch status',
        errorData.error_code
      )
    }

    return await response.json()
  } catch (error) {
    clearTimeout(timeoutId)

    if (error.name === 'AbortError') {
      throw new APIError(0, 'Request timed out.', 'TIMEOUT')
    }

    if (error instanceof APIError) {
      throw error
    }

    throw new APIError(0, 'Network error.', 'NETWORK_ERROR')
  }
}

/**
 * Cancel a batch job
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Cancellation response
 */
export async function cancelBatchJob(jobId) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT)

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/batch/${jobId}`, {
      method: 'DELETE',
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || 'Failed to cancel batch job',
        errorData.error_code
      )
    }

    return await response.json()
  } catch (error) {
    clearTimeout(timeoutId)

    if (error.name === 'AbortError') {
      throw new APIError(0, 'Request timed out.', 'TIMEOUT')
    }

    if (error instanceof APIError) {
      throw error
    }

    throw new APIError(0, 'Network error.', 'NETWORK_ERROR')
  }
}

/**
 * Cancel a specific item in a batch job
 * @param {string} jobId - Batch job ID
 * @param {number} fileIndex - Index of file to cancel
 * @returns {Promise<Object>} Cancellation response
 */
export async function cancelBatchItem(jobId, fileIndex) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT)

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/batch/${jobId}/items/${fileIndex}`, {
      method: 'DELETE',
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || 'Failed to cancel item',
        errorData.error_code
      )
    }

    return await response.json()
  } catch (error) {
    clearTimeout(timeoutId)

    if (error.name === 'AbortError') {
      throw new APIError(0, 'Request timed out.', 'TIMEOUT')
    }

    if (error instanceof APIError) {
      throw error
    }

    throw new APIError(0, 'Network error.', 'NETWORK_ERROR')
  }
}

/**
 * Download batch results
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Blob>} ZIP file blob
 */
export async function downloadBatchResults(jobId) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT * 5) // Longer timeout for download

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/batch/${jobId}/download`, {
      method: 'GET',
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || 'Failed to download results',
        errorData.error_code
      )
    }

    return await response.blob()
  } catch (error) {
    clearTimeout(timeoutId)

    if (error.name === 'AbortError') {
      throw new APIError(0, 'Download timed out.', 'TIMEOUT')
    }

    if (error instanceof APIError) {
      throw error
    }

    throw new APIError(0, 'Network error.', 'NETWORK_ERROR')
  }
}

/**
 * Get batch results summary
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Results summary
 */
export async function getBatchResults(jobId) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT)

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/batch/${jobId}/results`, {
      method: 'GET',
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || 'Failed to get results',
        errorData.error_code
      )
    }

    return await response.json()
  } catch (error) {
    clearTimeout(timeoutId)

    if (error.name === 'AbortError') {
      throw new APIError(0, 'Request timed out.', 'TIMEOUT')
    }

    if (error instanceof APIError) {
      throw error
    }

    throw new APIError(0, 'Network error.', 'NETWORK_ERROR')
  }
}

/**
 * Create a new WebSocket token for a batch job
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Token response
 */
export async function createWebSocketToken(jobId) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT)

  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/batch/${jobId}/websocket-token`, {
      method: 'POST',
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new APIError(
        response.status,
        errorData.detail || 'Failed to create token',
        errorData.error_code
      )
    }

    return await response.json()
  } catch (error) {
    clearTimeout(timeoutId)

    if (error.name === 'AbortError') {
      throw new APIError(0, 'Request timed out.', 'TIMEOUT')
    }

    if (error instanceof APIError) {
      throw error
    }

    throw new APIError(0, 'Network error.', 'NETWORK_ERROR')
  }
}

/**
 * Get default error message for batch operations
 */
function getDefaultBatchErrorMessage(status) {
  const errorMessages = {
    400: 'Invalid batch request. Please check your files.',
    413: 'Batch too large. Maximum 100 files allowed.',
    415: 'One or more files have unsupported format.',
    422: 'Invalid batch parameters.',
    500: 'Server error. Please try again later.',
    503: 'Service temporarily unavailable.',
  }

  return errorMessages[status] || 'An unexpected error occurred.'
}
