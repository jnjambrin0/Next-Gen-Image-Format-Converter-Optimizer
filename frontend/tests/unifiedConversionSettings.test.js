/**
 * Tests for UnifiedConversionSettings component
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { UnifiedConversionSettings } from '../src/components/unifiedConversionSettings.js'
import { uiPreferences } from '../src/services/uiPreferences.js'

// Mock dependencies
vi.mock('../src/services/presetApi.js', () => ({
  presetApi: {
    getPresets: vi.fn().mockResolvedValue([]),
    createPreset: vi.fn(),
    updatePreset: vi.fn(),
    deletePreset: vi.fn(),
  },
}))

vi.mock('../src/services/uiPreferences.js', () => ({
  uiPreferences: {
    init: vi.fn().mockReturnValue({
      advancedMode: false,
      lastUsedSettings: {
        outputFormat: 'webp',
        quality: 85,
        preserveMetadata: false,
      },
    }),
    update: vi.fn(),
    get: vi.fn(),
  },
}))

vi.mock('../src/utils/notifications.js', () => ({
  showNotification: vi.fn(),
}))

describe('UnifiedConversionSettings', () => {
  let component
  let container
  let mockOnChange
  let mockOnTestConvert

  beforeEach(() => {
    // Create container element
    container = document.createElement('div')
    document.body.appendChild(container)

    // Create mock callbacks
    mockOnChange = vi.fn()
    mockOnTestConvert = vi.fn()
  })

  afterEach(() => {
    // Clean up
    if (component) {
      component.destroy()
    }
    document.body.removeChild(container)
    vi.clearAllMocks()
  })

  describe('Initialization', () => {
    it('should initialize with default single mode', async () => {
      component = new UnifiedConversionSettings()
      const element = await component.init(mockOnChange, mockOnTestConvert)
      container.appendChild(element)

      expect(component.mode).toBe('single')
      expect(element).toBeDefined()
      expect(element.querySelector('.settings-header h3').textContent).toContain(
        'Conversion Settings'
      )
    })

    it('should initialize with batch mode', async () => {
      component = new UnifiedConversionSettings('batch')
      const element = await component.init(mockOnChange, mockOnTestConvert)
      container.appendChild(element)

      expect(component.mode).toBe('batch')
      expect(element.querySelector('.settings-header h3').textContent).toContain(
        'Batch Conversion Settings'
      )
      expect(element.querySelector('#optimization-mode')).toBeTruthy()
      expect(element.querySelector('#apply-to-all')).toBeTruthy()
    })

    it('should load saved preferences', async () => {
      const { uiPreferences } = await import('../src/services/uiPreferences.js')
      uiPreferences.init.mockReturnValue({
        advancedMode: false,
        lastUsedSettings: {
          outputFormat: 'avif',
          quality: 90,
          preserveMetadata: true,
        },
      })

      component = new UnifiedConversionSettings()
      await component.init(mockOnChange, mockOnTestConvert)

      expect(component.settings.outputFormat).toBe('avif')
      expect(component.settings.quality).toBe(90)
      expect(component.settings.preserveMetadata).toBe(true)
    })
  })

  describe('Mode Switching', () => {
    beforeEach(async () => {
      // Reset the mock to default values
      uiPreferences.init.mockReturnValue({
        advancedMode: false,
        lastUsedSettings: {
          outputFormat: 'webp',
          quality: 85,
          preserveMetadata: false,
        },
      })

      component = new UnifiedConversionSettings('single')
      const element = await component.init(mockOnChange, mockOnTestConvert)
      container.appendChild(element)
    })

    it('should switch from single to batch mode', () => {
      component.updateMode('batch')

      expect(component.mode).toBe('batch')
      expect(component.settings.applyToAll).toBe(true)
      expect(component.settings.optimizationMode).toBe(null)
    })

    it('should preserve settings when switching modes', () => {
      component.updateSetting('outputFormat', 'png')
      component.updateSetting('quality', 75)

      component.updateMode('batch')

      expect(component.settings.outputFormat).toBe('png')
      expect(component.settings.quality).toBe(75)
    })

    it('should not re-render if mode is the same', () => {
      const renderSpy = vi.spyOn(component, 'render')

      component.updateMode('single')

      expect(renderSpy).not.toHaveBeenCalled()
    })

    it('should notify change when mode switches', () => {
      component.updateMode('batch')

      expect(mockOnChange).toHaveBeenCalledWith(
        expect.objectContaining({
          outputFormat: 'webp',
          quality: 85,
          applyToAll: true,
        })
      )
    })
  })

  describe('Settings Management', () => {
    beforeEach(async () => {
      component = new UnifiedConversionSettings()
      const element = await component.init(mockOnChange, mockOnTestConvert)
      container.appendChild(element)
    })

    it('should update individual settings', () => {
      component.updateSetting('outputFormat', 'avif')

      expect(component.settings.outputFormat).toBe('avif')
      expect(mockOnChange).toHaveBeenCalledWith(
        expect.objectContaining({
          outputFormat: 'avif',
        })
      )
    })

    it('should update format description when format changes', () => {
      const formatSelect = container.querySelector('#output-format')
      formatSelect.value = 'jpeg'
      formatSelect.dispatchEvent(new Event('change'))

      const description = container.querySelector('.setting-description')
      expect(description.textContent).toContain('Universal compatibility')
    })

    it('should update quality when slider changes', () => {
      component.handleQualityChange({ detail: { value: 60 } })

      expect(component.settings.quality).toBe(60)
      expect(mockOnChange).toHaveBeenCalled()
    })

    it('should update metadata preservation setting', () => {
      const checkbox = container.querySelector('#preserve-metadata')
      checkbox.checked = true
      checkbox.dispatchEvent(new Event('change'))

      expect(component.settings.preserveMetadata).toBe(true)
    })

    it('should generate correct settings summary', () => {
      component.settings = {
        outputFormat: 'webp',
        quality: 85,
        preserveMetadata: true,
        presetName: 'Custom Preset',
      }

      const summary = component.generateSettingsSummary()

      expect(summary).toContain('Format: WEBP')
      expect(summary).toContain('Quality: 85%')
      expect(summary).toContain('Metadata: Preserved')
      expect(summary).toContain('Preset: Custom Preset')
    })
  })

  describe('Batch Mode Specific Features', () => {
    beforeEach(async () => {
      component = new UnifiedConversionSettings('batch')
      const element = await component.init(mockOnChange, mockOnTestConvert)
      container.appendChild(element)
    })

    it('should show batch-specific controls', () => {
      expect(container.querySelector('#optimization-mode')).toBeTruthy()
      expect(container.querySelector('#apply-to-all')).toBeTruthy()
    })

    it('should update optimization mode', () => {
      const select = container.querySelector('#optimization-mode')
      select.value = 'balanced'
      select.dispatchEvent(new Event('change'))

      expect(component.settings.optimizationMode).toBe('balanced')
    })

    it('should update apply to all setting', () => {
      const checkbox = container.querySelector('#apply-to-all')
      checkbox.checked = false
      checkbox.dispatchEvent(new Event('change'))

      expect(component.settings.applyToAll).toBe(false)
    })

    it('should include batch settings in summary', () => {
      component.settings.optimizationMode = 'quality'
      component.settings.applyToAll = false

      const summary = component.generateSettingsSummary()

      expect(summary).toContain('Optimization: quality')
      expect(summary).toContain('Apply to: Individual files')
    })
  })

  describe('Advanced Settings', () => {
    beforeEach(async () => {
      component = new UnifiedConversionSettings()
      const element = await component.init(mockOnChange, mockOnTestConvert)
      container.appendChild(element)
    })

    it('should toggle advanced settings visibility', () => {
      const toggleButton = container.querySelector('#advanced-toggle')
      const advancedContainer = container.querySelector('#advanced-settings')

      expect(advancedContainer.style.display).toBe('none')

      toggleButton.click()

      expect(advancedContainer.style.display).toBe('block')
      expect(toggleButton.getAttribute('aria-expanded')).toBe('true')
    })

    it('should save advanced mode preference', async () => {
      const { uiPreferences } = await import('../src/services/uiPreferences.js')
      const toggleButton = container.querySelector('#advanced-toggle')

      toggleButton.click()

      expect(uiPreferences.update).toHaveBeenCalledWith('advancedMode', true)
    })
  })

  describe('Preset Integration', () => {
    it('should apply preset settings', async () => {
      component = new UnifiedConversionSettings()
      await component.init(mockOnChange, mockOnTestConvert)

      const preset = {
        id: 'preset-1',
        name: 'Web Optimized',
        outputFormat: 'webp',
        quality: 80,
        preserveMetadata: false,
      }

      component.handlePresetChange(preset)

      expect(component.settings.outputFormat).toBe('webp')
      expect(component.settings.quality).toBe(80)
      expect(component.settings.preserveMetadata).toBe(false)
      expect(component.settings.presetId).toBe('preset-1')
      expect(component.settings.presetName).toBe('Web Optimized')
    })

    it('should clear preset when null is passed', async () => {
      component = new UnifiedConversionSettings()
      await component.init(mockOnChange, mockOnTestConvert)

      component.settings.presetId = 'preset-1'
      component.settings.presetName = 'Test Preset'

      component.handlePresetChange(null)

      expect(component.settings.presetId).toBe(null)
      expect(component.settings.presetName).toBe(null)
    })
  })

  describe('Public API', () => {
    beforeEach(async () => {
      component = new UnifiedConversionSettings()
      await component.init(mockOnChange, mockOnTestConvert)
    })

    it('should get current settings', () => {
      component.settings.outputFormat = 'png'
      component.settings.quality = 70

      const settings = component.getCurrentSettings()

      expect(settings).toEqual(
        expect.objectContaining({
          outputFormat: 'png',
          quality: 70,
        })
      )
      // Should return a copy, not the original
      expect(settings).not.toBe(component.settings)
    })

    it('should set settings programmatically', () => {
      component.setSettings({
        outputFormat: 'jpeg',
        quality: 60,
        preserveMetadata: true,
      })

      expect(component.settings.outputFormat).toBe('jpeg')
      expect(component.settings.quality).toBe(60)
      expect(component.settings.preserveMetadata).toBe(true)
      expect(mockOnChange).toHaveBeenCalled()
    })

    it('should set file info for quality slider', () => {
      const setFileInfoSpy = vi.fn()
      component.qualitySlider = { setFileInfo: setFileInfoSpy }

      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' })
      component.setFileInfo(file)

      expect(setFileInfoSpy).toHaveBeenCalledWith(file)
    })

    it('should not set file info in batch mode', () => {
      component.mode = 'batch'
      const setFileInfoSpy = vi.fn()
      component.qualitySlider = { setFileInfo: setFileInfoSpy }

      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' })
      component.setFileInfo(file)

      expect(setFileInfoSpy).not.toHaveBeenCalled()
    })
  })

  describe('Cleanup', () => {
    it('should clean up event listeners on destroy', async () => {
      component = new UnifiedConversionSettings()
      const element = await component.init(mockOnChange, mockOnTestConvert)
      container.appendChild(element)

      // Add some event handlers
      const formatSelect = container.querySelector('#output-format')
      const removeEventListenerSpy = vi.spyOn(formatSelect, 'removeEventListener')

      component.destroy()

      expect(removeEventListenerSpy).toHaveBeenCalled()
      expect(component.eventHandlers.size).toBe(0)
    })

    it('should clean up sub-components', async () => {
      component = new UnifiedConversionSettings()
      await component.init(mockOnChange, mockOnTestConvert)

      const presetDestroySpy = vi.fn()
      const qualityDestroySpy = vi.fn()

      component.presetSelector = { destroy: presetDestroySpy }
      component.qualitySlider = { destroy: qualityDestroySpy }

      component.destroy()

      expect(presetDestroySpy).toHaveBeenCalled()
      expect(qualityDestroySpy).toHaveBeenCalled()
    })
  })
})
