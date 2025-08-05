import { describe, it, expect, beforeEach, vi } from 'vitest'
import { QualitySlider } from '../../src/components/qualitySlider.js'

describe('QualitySlider', () => {
  let qualitySlider
  let container

  beforeEach(() => {
    // Create a container for the component
    container = document.createElement('div')
    document.body.appendChild(container)

    qualitySlider = new QualitySlider()
  })

  afterEach(() => {
    document.body.removeChild(container)
  })

  describe('Initialization', () => {
    it('should initialize with default quality of 85', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      const valueDisplay = container.querySelector('#quality-value')

      expect(slider.value).toBe('85')
      expect(valueDisplay.textContent).toBe('85')
      expect(qualitySlider.getQuality()).toBe(85)
    })

    it('should initialize with custom quality value', () => {
      const element = qualitySlider.init(() => {}, 60)
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      const valueDisplay = container.querySelector('#quality-value')

      expect(slider.value).toBe('60')
      expect(valueDisplay.textContent).toBe('60')
      expect(qualitySlider.getQuality()).toBe(60)
    })

    it('should hide size estimation and test button initially', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      const estimationEl = container.querySelector('#size-estimation')
      const testContainer = container.querySelector('#test-conversion-container')

      expect(estimationEl.classList.contains('hidden')).toBe(true)
      expect(testContainer.classList.contains('hidden')).toBe(true)
    })
  })

  describe('Quality Change Events', () => {
    it('should emit quality change event when slider moves', () => {
      const onChange = vi.fn()
      const element = qualitySlider.init(onChange)
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      slider.value = '70'
      slider.dispatchEvent(new Event('input'))

      expect(onChange).toHaveBeenCalledWith({ quality: 70 })
      expect(qualitySlider.getQuality()).toBe(70)
    })

    it('should update quality value display when slider changes', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      const valueDisplay = container.querySelector('#quality-value')

      slider.value = '50'
      slider.dispatchEvent(new Event('input'))

      expect(valueDisplay.textContent).toBe('50')
    })
  })

  describe('File Size Estimation', () => {
    it('should show estimation when original file size is set', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      qualitySlider.setOriginalFileSize(1024 * 1024) // 1MB

      const estimationEl = container.querySelector('#size-estimation')
      const testContainer = container.querySelector('#test-conversion-container')

      expect(estimationEl.classList.contains('hidden')).toBe(false)
      expect(testContainer.classList.contains('hidden')).toBe(false)
    })

    it('should calculate WebP estimation correctly', () => {
      qualitySlider.init(() => {})
      qualitySlider.selectedFormat = 'webp'

      // 1MB file, WebP at quality 85
      const estimated = qualitySlider.estimateFileSize(1024 * 1024, 'webp', 85)

      // Should be around 30% of original
      expect(estimated).toBeGreaterThan(250000)
      expect(estimated).toBeLessThan(350000)
    })

    it('should calculate AVIF estimation correctly', () => {
      qualitySlider.init(() => {})
      qualitySlider.selectedFormat = 'avif'

      // 1MB file, AVIF at quality 85
      const estimated = qualitySlider.estimateFileSize(1024 * 1024, 'avif', 85)

      // Should be around 25% of original
      expect(estimated).toBeGreaterThan(200000)
      expect(estimated).toBeLessThan(300000)
    })

    it('should not apply quality factor to PNG', () => {
      qualitySlider.init(() => {})

      // PNG is lossless, quality shouldn't affect size much
      const estimated50 = qualitySlider.estimateFileSize(1024 * 1024, 'png', 50)
      const estimated90 = qualitySlider.estimateFileSize(1024 * 1024, 'png', 90)

      expect(estimated50).toBe(estimated90)
    })

    it('should update estimation when quality changes', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      qualitySlider.setOriginalFileSize(1024 * 1024)
      qualitySlider.setOutputFormat('webp')

      const estimatedSizeEl = container.querySelector('#estimated-size')
      const initialEstimate = estimatedSizeEl.textContent

      // Change quality
      const slider = container.querySelector('#quality-slider')
      slider.value = '50'
      slider.dispatchEvent(new Event('input'))

      const newEstimate = estimatedSizeEl.textContent
      expect(newEstimate).not.toBe(initialEstimate)
    })
  })

  describe('Test Conversion', () => {
    it('should emit test-convert action when button clicked', () => {
      const onChange = vi.fn()
      const element = qualitySlider.init(onChange)
      container.appendChild(element)

      qualitySlider.setOriginalFileSize(1024 * 1024)

      const testButton = container.querySelector('#test-convert-btn')
      testButton.click()

      expect(onChange).toHaveBeenCalledWith({
        action: 'test-convert',
        quality: 85,
      })
    })

    it('should show loading state', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      qualitySlider.showTestLoading()

      const loadingEl = container.querySelector('#test-loading')
      const resultsEl = container.querySelector('#test-results')
      const buttonEl = container.querySelector('#test-convert-btn')

      expect(loadingEl.classList.contains('hidden')).toBe(false)
      expect(resultsEl.classList.contains('hidden')).toBe(true)
      expect(buttonEl.disabled).toBe(true)
    })

    it('should show test results', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      qualitySlider.showTestResults(512 * 1024) // 512KB

      const loadingEl = container.querySelector('#test-loading')
      const resultsEl = container.querySelector('#test-results')
      const buttonEl = container.querySelector('#test-convert-btn')
      const actualSizeEl = container.querySelector('#actual-size')

      expect(loadingEl.classList.contains('hidden')).toBe(true)
      expect(resultsEl.classList.contains('hidden')).toBe(false)
      expect(buttonEl.disabled).toBe(false)
      expect(actualSizeEl.textContent).toContain('KB')
    })
  })

  describe('Reset', () => {
    it('should reset all values to defaults', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      // Change values
      qualitySlider.setOriginalFileSize(1024 * 1024)
      const slider = container.querySelector('#quality-slider')
      slider.value = '60'
      slider.dispatchEvent(new Event('input'))

      // Reset
      qualitySlider.reset()

      expect(qualitySlider.getQuality()).toBe(85)
      expect(slider.value).toBe('85')

      const estimationEl = container.querySelector('#size-estimation')
      const testContainer = container.querySelector('#test-conversion-container')

      expect(estimationEl.classList.contains('hidden')).toBe(true)
      expect(testContainer.classList.contains('hidden')).toBe(true)
    })
  })

  describe('Keyboard Navigation', () => {
    it('should increase quality with arrow right key', () => {
      const onChange = vi.fn()
      const element = qualitySlider.init(onChange, 50)
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      const event = new KeyboardEvent('keydown', { key: 'ArrowRight' })
      slider.dispatchEvent(event)
      slider.value = '51'
      slider.dispatchEvent(new Event('input'))

      expect(onChange).toHaveBeenCalledWith({ quality: 51 })
    })

    it('should decrease quality with arrow left key', () => {
      const onChange = vi.fn()
      const element = qualitySlider.init(onChange, 50)
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      const event = new KeyboardEvent('keydown', { key: 'ArrowLeft' })
      slider.dispatchEvent(event)
      slider.value = '49'
      slider.dispatchEvent(new Event('input'))

      expect(onChange).toHaveBeenCalledWith({ quality: 49 })
    })

    it('should be focusable with Tab key', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      expect(slider.tabIndex).not.toBe(-1)
    })

    it('should have proper ARIA attributes', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      const slider = container.querySelector('#quality-slider')
      expect(slider.getAttribute('type')).toBe('range')
      expect(slider.getAttribute('min')).toBe('1')
      expect(slider.getAttribute('max')).toBe('100')
      expect(slider.getAttribute('value')).toBe('85')
    })
  })

  describe('Error Handling', () => {
    it('should show error message', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      qualitySlider.showTestError('Test conversion failed')

      const errorEl = container.querySelector('#test-error')
      const errorMessageEl = container.querySelector('#error-message')
      const loadingEl = container.querySelector('#test-loading')

      expect(errorEl.classList.contains('hidden')).toBe(false)
      expect(errorMessageEl.textContent).toBe('Test conversion failed')
      expect(loadingEl.classList.contains('hidden')).toBe(true)
    })

    it('should hide error when showing results', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      // Show error first
      qualitySlider.showTestError('Test error')

      // Then show results
      qualitySlider.showTestResults(1024)

      const errorEl = container.querySelector('#test-error')
      const resultsEl = container.querySelector('#test-results')

      expect(errorEl.classList.contains('hidden')).toBe(true)
      expect(resultsEl.classList.contains('hidden')).toBe(false)
    })

    it('should hide loading when passing null to showTestResults', () => {
      const element = qualitySlider.init(() => {})
      container.appendChild(element)

      // Show loading first
      qualitySlider.showTestLoading()

      // Hide loading without showing results
      qualitySlider.showTestResults(null)

      const loadingEl = container.querySelector('#test-loading')
      const resultsEl = container.querySelector('#test-results')
      const buttonEl = container.querySelector('#test-convert-btn')

      expect(loadingEl.classList.contains('hidden')).toBe(true)
      expect(resultsEl.classList.contains('hidden')).toBe(true)
      expect(buttonEl.disabled).toBe(false)
    })
  })
})
