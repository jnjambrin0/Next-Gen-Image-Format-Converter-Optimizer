import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { BlobUrlManager } from '../../src/utils/blobUrlManager.js'

describe('BlobUrlManager', () => {
  let manager
  let mockUrls
  let urlCounter

  beforeEach(() => {
    manager = new BlobUrlManager()
    mockUrls = new Map()
    urlCounter = 0

    // Mock URL.createObjectURL and revokeObjectURL
    global.URL.createObjectURL = vi.fn((blob) => {
      const url = `blob:mock-url-${urlCounter++}`
      mockUrls.set(url, blob)
      return url
    })

    global.URL.revokeObjectURL = vi.fn((url) => {
      mockUrls.delete(url)
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('createUrl', () => {
    it('should create a new blob URL', () => {
      const blob = new Blob(['test'])
      const url = manager.createUrl(blob, 'test-key')

      expect(url).toBe('blob:mock-url-0')
      expect(global.URL.createObjectURL).toHaveBeenCalledWith(blob)
      expect(manager.hasUrl('test-key')).toBe(true)
    })

    it('should revoke existing URL when creating new one with same key', () => {
      const blob1 = new Blob(['test1'])
      const blob2 = new Blob(['test2'])

      const url1 = manager.createUrl(blob1, 'test-key')
      expect(global.URL.revokeObjectURL).not.toHaveBeenCalled()

      const url2 = manager.createUrl(blob2, 'test-key')
      expect(global.URL.revokeObjectURL).toHaveBeenCalledWith(url1)
      expect(manager.getUrl('test-key')).toBe(url2)
    })
  })

  describe('revokeUrl', () => {
    it('should revoke a specific URL by key', () => {
      const blob = new Blob(['test'])
      const url = manager.createUrl(blob, 'test-key')

      manager.revokeUrl('test-key')

      expect(global.URL.revokeObjectURL).toHaveBeenCalledWith(url)
      expect(manager.hasUrl('test-key')).toBe(false)
    })

    it('should handle revoking non-existent key gracefully', () => {
      expect(() => manager.revokeUrl('non-existent')).not.toThrow()
      expect(global.URL.revokeObjectURL).not.toHaveBeenCalled()
    })
  })

  describe('revokeAll', () => {
    it('should revoke all tracked URLs', () => {
      const blob1 = new Blob(['test1'])
      const blob2 = new Blob(['test2'])
      const blob3 = new Blob(['test3'])

      const url1 = manager.createUrl(blob1, 'key1')
      const url2 = manager.createUrl(blob2, 'key2')
      const url3 = manager.createUrl(blob3, 'key3')

      manager.revokeAll()

      expect(global.URL.revokeObjectURL).toHaveBeenCalledWith(url1)
      expect(global.URL.revokeObjectURL).toHaveBeenCalledWith(url2)
      expect(global.URL.revokeObjectURL).toHaveBeenCalledWith(url3)
      expect(manager.size).toBe(0)
    })
  })

  describe('getUrl', () => {
    it('should return URL for existing key', () => {
      const blob = new Blob(['test'])
      const url = manager.createUrl(blob, 'test-key')

      expect(manager.getUrl('test-key')).toBe(url)
    })

    it('should return undefined for non-existent key', () => {
      expect(manager.getUrl('non-existent')).toBeUndefined()
    })
  })

  describe('hasUrl', () => {
    it('should return true for existing key', () => {
      const blob = new Blob(['test'])
      manager.createUrl(blob, 'test-key')

      expect(manager.hasUrl('test-key')).toBe(true)
    })

    it('should return false for non-existent key', () => {
      expect(manager.hasUrl('non-existent')).toBe(false)
    })
  })

  describe('size', () => {
    it('should return the number of tracked URLs', () => {
      expect(manager.size).toBe(0)

      manager.createUrl(new Blob(['1']), 'key1')
      expect(manager.size).toBe(1)

      manager.createUrl(new Blob(['2']), 'key2')
      expect(manager.size).toBe(2)

      manager.revokeUrl('key1')
      expect(manager.size).toBe(1)

      manager.revokeAll()
      expect(manager.size).toBe(0)
    })
  })
})
