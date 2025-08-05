import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { UIPreferences } from '../../src/services/uiPreferences.js'

describe('UIPreferences', () => {
  let preferences
  let localStorageMock

  beforeEach(() => {
    // Mock localStorage
    localStorageMock = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
      length: 0,
      key: vi.fn(),
    }

    global.localStorage = localStorageMock

    preferences = new UIPreferences()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('initialization', () => {
    it('should return defaults when localStorage is empty', () => {
      localStorageMock.getItem.mockReturnValue(null)

      const result = preferences.init()

      expect(result).toEqual(preferences.defaults)
    })

    it('should load saved preferences', () => {
      const saved = {
        version: '1.0',
        advancedMode: true,
        groupStates: { quality: false },
      }

      localStorageMock.getItem.mockReturnValue(JSON.stringify(saved))

      const result = preferences.init()

      expect(result.advancedMode).toBe(true)
      expect(result.groupStates.quality).toBe(false)
    })

    it('should handle localStorage not available', () => {
      // Make localStorage unavailable
      localStorageMock.setItem.mockImplementation(() => {
        throw new Error('localStorage not available')
      })

      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const result = preferences.init()

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('localStorage is not available')
      )
      expect(result).toEqual(preferences.defaults)

      consoleSpy.mockRestore()
    })
  })

  describe('save', () => {
    it('should save preferences to localStorage', () => {
      const prefs = { ...preferences.defaults, advancedMode: true }

      const result = preferences.save(prefs)

      expect(result).toBe(true)
      expect(localStorageMock.setItem).toHaveBeenCalledWith(
        preferences.storageKey,
        expect.stringContaining('"advancedMode":true')
      )
    })

    it('should handle quota exceeded error', () => {
      localStorageMock.setItem.mockImplementation(() => {
        const error = new Error('QuotaExceededError')
        error.name = 'QuotaExceededError'
        throw error
      })

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const result = preferences.save(preferences.defaults)

      expect(result).toBe(false)
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('quota exceeded'))

      consoleSpy.mockRestore()
    })
  })

  describe('update', () => {
    it('should update specific preference path', () => {
      localStorageMock.getItem.mockReturnValue(JSON.stringify(preferences.defaults))

      preferences.update('advancedMode', true)

      expect(localStorageMock.setItem).toHaveBeenCalledWith(
        preferences.storageKey,
        expect.stringContaining('"advancedMode":true')
      )
    })

    it('should handle nested paths', () => {
      localStorageMock.getItem.mockReturnValue(JSON.stringify(preferences.defaults))

      preferences.update('groupStates.quality', false)

      const savedCall = localStorageMock.setItem.mock.calls[0][1]
      const saved = JSON.parse(savedCall)
      expect(saved.groupStates.quality).toBe(false)
    })
  })

  describe('get', () => {
    it('should get specific preference value', () => {
      const saved = {
        ...preferences.defaults,
        advancedMode: true,
      }
      localStorageMock.getItem.mockReturnValue(JSON.stringify(saved))

      const value = preferences.get('advancedMode')

      expect(value).toBe(true)
    })

    it('should handle nested paths', () => {
      localStorageMock.getItem.mockReturnValue(JSON.stringify(preferences.defaults))

      const value = preferences.get('groupStates.quality')

      expect(value).toBe(true)
    })

    it('should return default value for missing keys', () => {
      localStorageMock.getItem.mockReturnValue(JSON.stringify(preferences.defaults))

      const value = preferences.get('nonexistent.path', 'default')

      expect(value).toBe('default')
    })
  })

  describe('reset', () => {
    it('should remove preferences from localStorage', () => {
      const result = preferences.reset()

      expect(result).toBe(true)
      expect(localStorageMock.removeItem).toHaveBeenCalledWith(preferences.storageKey)
    })

    it('should handle errors gracefully', () => {
      localStorageMock.removeItem.mockImplementation(() => {
        throw new Error('Remove failed')
      })

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const result = preferences.reset()

      expect(result).toBe(false)
      expect(consoleSpy).toHaveBeenCalled()

      consoleSpy.mockRestore()
    })
  })

  describe('mergeWithDefaults', () => {
    it('should merge preferences with defaults', () => {
      const partial = {
        version: '1.0',
        advancedMode: true,
        // Missing other properties
      }

      const merged = preferences.mergeWithDefaults(partial)

      expect(merged.advancedMode).toBe(true)
      expect(merged.groupStates).toEqual(preferences.defaults.groupStates)
      expect(merged.lastUsedSettings).toEqual(preferences.defaults.lastUsedSettings)
    })

    it('should handle nested merging', () => {
      const partial = {
        version: '1.0',
        groupStates: {
          quality: false,
          // Missing other group states
        },
      }

      const merged = preferences.mergeWithDefaults(partial)

      expect(merged.groupStates.quality).toBe(false)
      expect(merged.groupStates.optimization).toBe(true) // From defaults
      expect(merged.groupStates.metadata).toBe(true) // From defaults
    })
  })

  describe('import/export', () => {
    it('should export preferences as JSON', () => {
      localStorageMock.getItem.mockReturnValue(JSON.stringify(preferences.defaults))

      const exported = preferences.export()

      expect(exported).toBe(JSON.stringify(preferences.defaults, null, 2))
    })

    it('should import preferences from JSON', () => {
      const toImport = {
        advancedMode: true,
        groupStates: { quality: false },
      }

      const result = preferences.import(JSON.stringify(toImport))

      expect(result).toBe(true)
      expect(localStorageMock.setItem).toHaveBeenCalled()

      const savedCall = localStorageMock.setItem.mock.calls[0][1]
      const saved = JSON.parse(savedCall)
      expect(saved.advancedMode).toBe(true)
    })

    it('should reject invalid JSON', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const result = preferences.import('invalid json')

      expect(result).toBe(false)
      expect(consoleSpy).toHaveBeenCalled()

      consoleSpy.mockRestore()
    })
  })

  describe('storage info', () => {
    it('should return storage usage info', () => {
      const testData = JSON.stringify(preferences.defaults)
      localStorageMock.getItem.mockReturnValue(testData)
      Object.defineProperty(localStorageMock, 'length', { value: 5 })

      const info = preferences.getStorageInfo()

      expect(info.available).toBe(true)
      expect(info.size).toBeGreaterThan(0)
      expect(info.itemCount).toBe(5)
      expect(info.sizeFormatted).toMatch(/\d+(\.\d+)? (Bytes|KB)/)
    })

    it('should format bytes correctly', () => {
      expect(preferences.formatBytes(0)).toBe('0 Bytes')
      expect(preferences.formatBytes(500)).toBe('500 Bytes')
      expect(preferences.formatBytes(1024)).toBe('1 KB')
      expect(preferences.formatBytes(1536)).toBe('1.5 KB')
    })
  })
})
