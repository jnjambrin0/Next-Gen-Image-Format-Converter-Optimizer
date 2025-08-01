import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { convertImage, APIError, mapErrorCodeToMessage } from '../../src/services/api.js'

describe('API Service', () => {
  beforeEach(() => {
    // Reset fetch mock before each test
    global.fetch = vi.fn()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('convertImage', () => {
    it('should successfully convert an image', async () => {
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' })
      const mockBlob = new Blob(['converted'], { type: 'image/webp' })

      global.fetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({
          'Content-Disposition': 'attachment; filename="test_converted.webp"',
        }),
        blob: vi.fn().mockResolvedValueOnce(mockBlob),
      })

      const result = await convertImage(mockFile, 'webp', 85)

      expect(result.blob).toBe(mockBlob)
      expect(result.filename).toBe('test_converted.webp')

      // Verify fetch was called with correct parameters
      expect(global.fetch).toHaveBeenCalledTimes(1)
      const [url, options] = global.fetch.mock.calls[0]
      expect(url).toBe('/api/convert')
      expect(options.method).toBe('POST')
      expect(options.body).toBeInstanceOf(FormData)
    })

    it('should handle missing Content-Disposition header', async () => {
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' })
      const mockBlob = new Blob(['converted'], { type: 'image/webp' })

      global.fetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({}),
        blob: vi.fn().mockResolvedValueOnce(mockBlob),
      })

      const result = await convertImage(mockFile, 'webp')

      expect(result.filename).toBe('converted_image.webp')
    })

    it('should handle 413 error (file too large)', async () => {
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' })

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 413,
        json: vi.fn().mockResolvedValueOnce({
          detail: 'File size exceeds limit',
          error_code: 'CONV204',
        }),
      })

      let caughtError
      try {
        await convertImage(mockFile, 'webp')
      } catch (error) {
        caughtError = error
      }

      expect(caughtError).toBeDefined()
      expect(caughtError).toBeInstanceOf(APIError)
      expect(caughtError.status).toBe(413)
      expect(caughtError.message).toBe('File size exceeds limit')
      expect(caughtError.errorCode).toBe('CONV204')
    })

    it('should handle timeout', async () => {
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' })

      // Mock fetch to simulate abort
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      global.fetch.mockRejectedValueOnce(abortError)

      let caughtError
      try {
        await convertImage(mockFile, 'webp')
      } catch (error) {
        caughtError = error
      }

      expect(caughtError).toBeDefined()
      expect(caughtError.message).toBe('Request timed out. Please try again.')
      expect(caughtError.errorCode).toBe('TIMEOUT')
    })

    it('should handle network errors', async () => {
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' })

      global.fetch.mockRejectedValueOnce(new Error('Network failure'))

      await expect(convertImage(mockFile, 'webp')).rejects.toThrow(APIError)

      try {
        await convertImage(mockFile, 'webp')
      } catch (error) {
        expect(error.message).toBe('Network error. Please check your connection.')
        expect(error.errorCode).toBe('NETWORK_ERROR')
      }
    })

    it('should handle error response without JSON body', async () => {
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' })

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: vi.fn().mockRejectedValueOnce(new Error('Invalid JSON')),
      })

      try {
        await convertImage(mockFile, 'webp')
      } catch (error) {
        expect(error.status).toBe(500)
        expect(error.message).toBe('Server error. Please try again later.')
      }
    })
  })

  describe('mapErrorCodeToMessage', () => {
    it('should map known error codes to user-friendly messages', () => {
      expect(mapErrorCodeToMessage('CONV201')).toBe(
        'Invalid image file. The file may be corrupted.'
      )
      expect(mapErrorCodeToMessage('CONV205')).toBe(
        'Processing timeout. The image may be too complex.'
      )
      expect(mapErrorCodeToMessage('CONV250')).toBe(
        'Security check failed. The file may contain malicious content.'
      )
    })

    it('should return default message for unknown error codes', () => {
      expect(mapErrorCodeToMessage('UNKNOWN')).toBe('An error occurred during conversion.')
      expect(mapErrorCodeToMessage('')).toBe('An error occurred during conversion.')
    })
  })

  describe('APIError', () => {
    it('should create error with correct properties', () => {
      const error = new APIError(404, 'Not found', 'CONV999')

      expect(error).toBeInstanceOf(Error)
      expect(error.name).toBe('APIError')
      expect(error.status).toBe(404)
      expect(error.message).toBe('Not found')
      expect(error.errorCode).toBe('CONV999')
    })
  })
})
