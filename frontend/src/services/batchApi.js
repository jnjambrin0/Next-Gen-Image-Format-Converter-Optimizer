import { API_CONFIG } from '../config/constants.js'
import { APIError, apiClient } from './api.js'

/**
 * Enhanced Batch API service using v1 endpoints with filtering, pagination, and SSE support
 */

/**
 * Create a batch conversion job using enhanced v1 API
 * @param {File[]} files - Array of image files to convert
 * @param {Object} settings - Conversion settings
 * @returns {Promise<Object>} Batch job creation response with WebSocket URL and SSE endpoint
 */
export async function createBatchJob(files, settings) {
  if (!files || files.length === 0) {
    throw new APIError(400, 'No files provided for batch processing', 'BAT400')
  }

  const maxBatchSize = API_CONFIG.FILE_CONFIG?.MAX_BATCH_SIZE || 100
  if (files.length > maxBatchSize) {
    throw new APIError(400, `Maximum ${maxBatchSize} files allowed per batch`, 'BAT400')
  }

  const formData = new FormData()

  // Add files with validation
  files.forEach((file, index) => {
    if (!file || !file.name) {
      throw new APIError(400, `File at index ${index} is invalid`, 'BAT400')
    }
    formData.append('files', file)
  })

  // Add enhanced settings
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

  try {
    const response = await apiClient.postForm(API_CONFIG.ENDPOINTS.BATCH, formData, {
      timeout: API_CONFIG.TIMEOUT * 3, // Extended timeout for batch jobs
    })

    const result = await response.json()

    // Enhanced response includes WebSocket URL and SSE alternative
    return {
      ...result,
      // Add SSE endpoint as fallback
      sseUrl: API_CONFIG.ENDPOINTS.BATCH_EVENTS(result.job_id),
    }
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to create batch job', 'BAT500')
  }
}

/**
 * Get batch job status with filtering and pagination (v1 API)
 * @param {string} jobId - Batch job ID
 * @param {Object} options - Filtering and pagination options
 * @returns {Promise<Object>} Batch job status with filtered items
 */
export async function getBatchStatus(jobId, options = {}) {
  const params = new URLSearchParams()

  if (options.statusFilter) params.append('status_filter', options.statusFilter)
  if (options.limit) params.append('limit', options.limit)
  if (options.offset) params.append('offset', options.offset)

  const endpoint = API_CONFIG.ENDPOINTS.BATCH_STATUS(jobId)
  const finalEndpoint = params.toString() ? `${endpoint}?${params}` : endpoint

  try {
    const response = await apiClient.get(finalEndpoint)
    const result = await response.json()

    // Extract pagination metadata from headers if available
    if (response.headers.get('X-Total-Items')) {
      result.pagination = {
        totalItems: parseInt(response.headers.get('X-Total-Items')),
        returnedItems: parseInt(response.headers.get('X-Returned-Items')),
        offset: parseInt(response.headers.get('X-Offset')),
        limit: response.headers.get('X-Limit') ? parseInt(response.headers.get('X-Limit')) : null,
        statusFilter: response.headers.get('X-Status-Filter'),
      }
    }

    return result
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to get batch status', 'BAT500')
  }
}

/**
 * Cancel a batch job with enhanced cleanup (v1 API)
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Cancellation response with cleanup info
 */
export async function cancelBatchJob(jobId) {
  try {
    const response = await apiClient.delete(API_CONFIG.ENDPOINTS.BATCH_CANCEL(jobId))
    return await response.json()
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to cancel batch job', 'BAT500')
  }
}

/**
 * Cancel a specific item in a batch job (v1 API)
 * @param {string} jobId - Batch job ID
 * @param {number} fileIndex - Index of file to cancel
 * @returns {Promise<Object>} Cancellation response with item info
 */
export async function cancelBatchItem(jobId, fileIndex) {
  try {
    const response = await apiClient.delete(
      API_CONFIG.ENDPOINTS.BATCH_CANCEL_ITEM(jobId, fileIndex)
    )
    return await response.json()
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to cancel batch item', 'BAT500')
  }
}

/**
 * Download batch results with format options (v1 API)
 * @param {string} jobId - Batch job ID
 * @param {string} format - Download format ('zip' or 'json')
 * @returns {Promise<Blob>} Download blob with enhanced metadata
 */
export async function downloadBatchResults(jobId, format = 'zip') {
  const params = new URLSearchParams()
  if (format !== 'zip') params.append('format', format)

  const endpoint = API_CONFIG.ENDPOINTS.BATCH_DOWNLOAD(jobId)
  const finalEndpoint = params.toString() ? `${endpoint}?${params}` : endpoint

  try {
    const response = await apiClient.get(finalEndpoint, {
      timeout: API_CONFIG.TIMEOUT * 5, // Extended timeout for downloads
    })

    // Extract download metadata from headers
    const downloadMetadata = {
      contentFormat: response.headers.get('X-Content-Format'),
      totalFiles: parseInt(response.headers.get('X-Total-Files')),
      successfulFiles: parseInt(response.headers.get('X-Successful-Files')),
      failedFiles: parseInt(response.headers.get('X-Failed-Files')),
      contentLength: parseInt(response.headers.get('X-Content-Length')),
    }

    const blob = await response.blob()

    // Attach metadata to blob for UI use
    blob.downloadMetadata = downloadMetadata

    return blob
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to download batch results', 'BAT500')
  }
}

/**
 * Get batch results summary (v1 API)
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Enhanced results summary
 */
export async function getBatchResults(jobId) {
  try {
    const response = await apiClient.get(API_CONFIG.ENDPOINTS.BATCH_RESULTS(jobId))
    return await response.json()
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to get batch results', 'BAT500')
  }
}

/**
 * Get batch performance metrics (v1 API)
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Performance metrics with metadata
 */
export async function getBatchMetrics(jobId) {
  try {
    const response = await apiClient.get(API_CONFIG.ENDPOINTS.BATCH_METRICS(jobId))
    return await response.json()
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to get batch metrics', 'BAT500')
  }
}

/**
 * Create a new WebSocket token for a batch job (v1 API)
 * @param {string} jobId - Batch job ID
 * @returns {Promise<Object>} Token response with WebSocket URL and SSE fallback
 */
export async function createWebSocketToken(jobId) {
  try {
    const response = await apiClient.post(API_CONFIG.ENDPOINTS.BATCH_WEBSOCKET_TOKEN(jobId))
    const result = await response.json()

    // Add SSE endpoint as fallback
    result.sseUrl = API_CONFIG.ENDPOINTS.BATCH_EVENTS(jobId)

    return result
  } catch (error) {
    if (error instanceof APIError) {
      throw error
    }
    throw new APIError(0, 'Failed to create WebSocket token', 'BAT500')
  }
}

/**
 * Create Server-Sent Events connection for batch progress (v1 API)
 * @param {string} jobId - Batch job ID
 * @param {Function} onMessage - Callback for progress messages
 * @param {Function} onError - Callback for errors
 * @param {Function} onClose - Callback for connection close
 * @returns {EventSource} SSE connection object
 */
export function createBatchSSEConnection(jobId, onMessage, onError = null, onClose = null) {
  const sseUrl = `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.BATCH_EVENTS(jobId)}`

  try {
    const eventSource = new EventSource(sseUrl)

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        onMessage(data)
      } catch (e) {
        console.warn('Failed to parse SSE message:', event.data)
        if (onError) onError(new Error('Invalid SSE message format'))
      }
    }

    eventSource.onerror = (event) => {
      console.warn('SSE connection error:', event)
      if (onError) onError(new Error('SSE connection failed'))
    }

    if (onClose) {
      // Custom close handler
      const originalClose = eventSource.close.bind(eventSource)
      eventSource.close = () => {
        originalClose()
        onClose()
      }
    }

    return eventSource
  } catch (error) {
    if (onError) onError(error)
    throw new APIError(0, 'Failed to create SSE connection', 'BAT500')
  }
}

/**
 * Enhanced batch progress tracking with fallback support
 * @param {string} jobId - Batch job ID
 * @param {Function} onProgress - Progress callback
 * @param {Object} options - Connection options
 * @returns {Object} Connection manager with cleanup method
 */
export function createBatchProgressTracker(jobId, onProgress, options = {}) {
  const {
    preferSSE = false,
    fallbackToPolling = true,
    pollingInterval = 2000,
    onError = null,
    onComplete = null,
  } = options

  let connection = null
  let pollingTimer = null
  let isActive = true

  const cleanup = () => {
    isActive = false
    if (connection) {
      if (connection.close) connection.close()
      if (connection.terminate) connection.terminate()
      connection = null
    }
    if (pollingTimer) {
      clearInterval(pollingTimer)
      pollingTimer = null
    }
  }

  const startPolling = () => {
    if (!isActive || pollingTimer) return

    pollingTimer = setInterval(async () => {
      try {
        const status = await getBatchStatus(jobId)
        onProgress(status)

        // Stop polling if job is complete
        if (['completed', 'failed', 'cancelled'].includes(status.status)) {
          cleanup()
          if (onComplete) onComplete(status)
        }
      } catch (error) {
        if (onError) onError(error)
      }
    }, pollingInterval)
  }

  const connectSSE = () => {
    try {
      connection = createBatchSSEConnection(
        jobId,
        (data) => {
          onProgress(data)
          if (
            data.event === 'close' ||
            ['completed', 'failed', 'cancelled'].includes(data.status)
          ) {
            cleanup()
            if (onComplete) onComplete(data)
          }
        },
        (error) => {
          if (onError) onError(error)
          if (fallbackToPolling) {
            console.warn('SSE failed, falling back to polling')
            startPolling()
          }
        },
        () => {
          if (onComplete) onComplete({ event: 'close' })
        }
      )
    } catch (error) {
      if (onError) onError(error)
      if (fallbackToPolling) {
        startPolling()
      }
    }
  }

  // Start appropriate connection method
  if (preferSSE) {
    connectSSE()
  } else if (fallbackToPolling) {
    startPolling()
  }

  return {
    cleanup,
    isActive: () => isActive,
    switchToSSE: () => {
      if (pollingTimer) {
        clearInterval(pollingTimer)
        pollingTimer = null
      }
      connectSSE()
    },
    switchToPolling: () => {
      if (connection) {
        connection.close()
        connection = null
      }
      startPolling()
    },
  }
}
