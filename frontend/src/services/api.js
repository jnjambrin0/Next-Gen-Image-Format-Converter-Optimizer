import { API_CONFIG } from '../config/constants.js'

/**
 * API service for image conversion operations
 */

/**
 * Convert an image file to the specified format
 * @param {File} file - The image file to convert
 * @param {string} outputFormat - Target format (webp, avif, etc.)
 * @param {number} quality - Quality setting (1-100)
 * @returns {Promise<{blob: Blob, filename: string}>} The converted image blob and filename
 * @throws {Error} API errors with specific codes and messages
 */
export async function convertImage(file, outputFormat, quality = 85) {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('output_format', outputFormat)
  formData.append('quality', quality.toString())

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
 * Extract filename from Content-Disposition header
 * @param {string} contentDisposition - The Content-Disposition header value
 * @returns {string|null} The extracted filename or null
 */
function extractFilename(contentDisposition) {
  if (!contentDisposition) {
    return null
  }

  const filenameMatch = contentDisposition.match(/filename="(.+)"/)
  return filenameMatch ? filenameMatch[1] : null
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
