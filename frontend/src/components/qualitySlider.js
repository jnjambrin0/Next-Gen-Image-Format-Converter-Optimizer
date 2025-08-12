import { formatFileSize } from '../utils/validators.js'

/**
 * Quality slider component with file size estimation
 */
export class QualitySlider {
  constructor() {
    this.element = null
    this.quality = 85
    this.onChange = null
    this.originalFileSize = null
    this.selectedFormat = 'webp'
  }

  /**
   * Initialize the quality slider
   * @param {Function} onChange - Callback when quality changes
   * @param {number} initialQuality - Initial quality value
   * @returns {HTMLElement} The quality slider element
   */
  init(onChange, initialQuality = 85) {
    this.onChange = onChange
    this.quality = initialQuality
    this.element = this.createElement()
    return this.element
  }

  /**
   * Create the slider element
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'quality-slider-container'
    container.innerHTML = `
      <div class="mb-4">
        <label for="quality-slider" class="block text-sm font-medium text-gray-700 mb-2">
          Quality: <span id="quality-value" class="text-blue-600 font-semibold">${this.quality}</span>
        </label>
        <input 
          type="range" 
          id="quality-slider" 
          min="1" 
          max="100" 
          value="${this.quality}" 
          aria-label="Quality setting"
          aria-valuemin="1"
          aria-valuemax="100"
          aria-valuenow="${this.quality}"
          class="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
        >
        <div class="flex justify-between text-xs text-gray-500 mt-1">
          <span>Small file</span>
          <span>High quality</span>
        </div>
      </div>
      
      <!-- File size estimation -->
      <div id="size-estimation" class="mb-4 text-sm text-gray-600 bg-gray-50 p-3 rounded-md ${this.originalFileSize ? '' : 'hidden'}">
        <div class="flex justify-between items-center">
          <span>Estimated size:</span>
          <span id="estimated-size" class="font-medium text-gray-900">-</span>
        </div>
      </div>
      
      <!-- Test conversion button and results -->
      <div id="test-conversion-container" class="mb-4 ${this.originalFileSize ? '' : 'hidden'}">
        <button 
          id="test-convert-btn" 
          type="button"
          class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
        >
          Test Convert
        </button>
        
        <!-- Loading state -->
        <div id="test-loading" class="hidden mt-3 flex items-center text-sm text-gray-600">
          <svg class="animate-spin h-4 w-4 mr-2 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          Testing conversion...
        </div>
        
        <!-- Test results -->
        <div id="test-results" class="hidden mt-3 text-sm bg-green-50 border border-green-200 rounded-md p-3">
          <div class="flex justify-between items-center text-green-800">
            <span>Actual size:</span>
            <span id="actual-size" class="font-medium">-</span>
          </div>
        </div>
        
        <!-- Test error -->
        <div id="test-error" class="hidden mt-3 text-sm bg-red-50 border border-red-200 rounded-md p-3">
          <div class="text-red-800">
            <span id="error-message">Error occurred</span>
          </div>
        </div>
      </div>
    `

    this.attachEventListeners(container)
    return container
  }

  /**
   * Attach event listeners
   */
  attachEventListeners(container) {
    const slider = container.querySelector('#quality-slider')
    const valueDisplay = container.querySelector('#quality-value')
    const testButton = container.querySelector('#test-convert-btn')

    // Quality change
    slider.addEventListener('input', (e) => {
      this.quality = parseInt(e.target.value)
      valueDisplay.textContent = this.quality

      // Update ARIA value
      slider.setAttribute('aria-valuenow', this.quality)

      // Update estimation
      this.updateSizeEstimation()

      // Notify parent
      if (this.onChange) {
        this.onChange({ quality: this.quality })
      }
    })

    // Test conversion
    if (testButton) {
      testButton.addEventListener('click', () => {
        if (this.onChange) {
          this.onChange({ action: 'test-convert', quality: this.quality })
        }
      })
    }
  }

  /**
   * Set the original file size for estimation
   * @param {number} size - File size in bytes
   */
  setOriginalFileSize(size) {
    this.originalFileSize = size

    // Show estimation and test button
    const estimationEl = this.element.querySelector('#size-estimation')
    const testContainer = this.element.querySelector('#test-conversion-container')

    if (estimationEl) {
      estimationEl.classList.remove('hidden')
    }
    if (testContainer) {
      testContainer.classList.remove('hidden')
    }

    this.updateSizeEstimation()
  }

  /**
   * Set the selected output format
   * @param {string} format - Output format
   */
  setOutputFormat(format) {
    this.selectedFormat = format
    this.updateSizeEstimation()
  }

  /**
   * Update file size estimation based on format and quality
   */
  updateSizeEstimation() {
    if (!this.originalFileSize || !this.element) {
      return
    }

    const estimatedSize = this.estimateFileSize(
      this.originalFileSize,
      this.selectedFormat,
      this.quality
    )

    const estimatedSizeEl = this.element.querySelector('#estimated-size')
    if (estimatedSizeEl) {
      estimatedSizeEl.textContent = formatFileSize(estimatedSize)
    }
  }

  /**
   * Estimate file size based on format and quality
   * @param {number} originalSize - Original file size
   * @param {string} format - Output format
   * @param {number} quality - Quality setting
   * @returns {number} Estimated file size
   */
  estimateFileSize(originalSize, format, quality) {
    // Base compression ratios at quality 85
    const baseRatios = {
      webp: 0.3,
      avif: 0.25,
      jpeg: 0.4,
      png: 0.9, // PNG is lossless, quality doesn't affect much
    }

    const baseRatio = baseRatios[format] || 0.5

    // Quality adjustment factor (except for PNG)
    let qualityFactor = 1
    if (format !== 'png') {
      // Higher quality = larger file
      // Lower quality = smaller file
      // Use a curve that's more aggressive at lower qualities
      qualityFactor = Math.pow(quality / 85, 1.5)
    }

    const estimatedSize = originalSize * baseRatio * qualityFactor

    // Ensure minimum size
    return Math.max(estimatedSize, 1000)
  }

  /**
   * Show loading state for test conversion
   */
  showTestLoading() {
    const loadingEl = this.element.querySelector('#test-loading')
    const resultsEl = this.element.querySelector('#test-results')
    const buttonEl = this.element.querySelector('#test-convert-btn')

    if (loadingEl) {
      loadingEl.classList.remove('hidden')
    }
    if (resultsEl) {
      resultsEl.classList.add('hidden')
    }
    if (buttonEl) {
      buttonEl.disabled = true
    }
  }

  /**
   * Show test conversion results
   * @param {number|null} actualSize - Actual converted file size or null to hide loading
   */
  showTestResults(actualSize) {
    const loadingEl = this.element.querySelector('#test-loading')
    const resultsEl = this.element.querySelector('#test-results')
    const errorEl = this.element.querySelector('#test-error')
    const buttonEl = this.element.querySelector('#test-convert-btn')
    const actualSizeEl = this.element.querySelector('#actual-size')

    if (loadingEl) {
      loadingEl.classList.add('hidden')
    }
    if (errorEl) {
      errorEl.classList.add('hidden')
    }

    if (actualSize === null) {
      // Just hide loading, don't show results
      if (buttonEl) {
        buttonEl.disabled = false
      }
      return
    }

    if (resultsEl) {
      resultsEl.classList.remove('hidden')
    }
    if (buttonEl) {
      buttonEl.disabled = false
    }
    if (actualSizeEl) {
      actualSizeEl.textContent = formatFileSize(actualSize)
    }
  }

  /**
   * Hide test results
   */
  hideTestResults() {
    const resultsEl = this.element.querySelector('#test-results')
    const errorEl = this.element.querySelector('#test-error')
    if (resultsEl) {
      resultsEl.classList.add('hidden')
    }
    if (errorEl) {
      errorEl.classList.add('hidden')
    }
  }

  /**
   * Show test error
   * @param {string} errorMessage - Error message to display
   */
  showTestError(errorMessage) {
    const loadingEl = this.element.querySelector('#test-loading')
    const resultsEl = this.element.querySelector('#test-results')
    const errorEl = this.element.querySelector('#test-error')
    const errorMessageEl = this.element.querySelector('#error-message')
    const buttonEl = this.element.querySelector('#test-convert-btn')

    if (loadingEl) {
      loadingEl.classList.add('hidden')
    }
    if (resultsEl) {
      resultsEl.classList.add('hidden')
    }
    if (errorEl) {
      errorEl.classList.remove('hidden')
    }
    if (errorMessageEl) {
      errorMessageEl.textContent = errorMessage
    }
    if (buttonEl) {
      buttonEl.disabled = false
    }
  }

  /**
   * Reset the slider
   */
  reset() {
    this.quality = 85
    this.originalFileSize = null

    if (this.element) {
      const slider = this.element.querySelector('#quality-slider')
      const valueDisplay = this.element.querySelector('#quality-value')
      const estimationEl = this.element.querySelector('#size-estimation')
      const testContainer = this.element.querySelector('#test-conversion-container')

      if (slider) {
        slider.value = 85
      }
      if (valueDisplay) {
        valueDisplay.textContent = 85
      }
      if (estimationEl) {
        estimationEl.classList.add('hidden')
      }
      if (testContainer) {
        testContainer.classList.add('hidden')
      }

      this.hideTestResults()
    }
  }

  /**
   * Get current quality value
   */
  getQuality() {
    return this.quality
  }

  /**
   * Set file information for size estimation
   * @param {File} file - The file object
   */
  setFileInfo(file) {
    if (file && file.size) {
      this.setOriginalFileSize(file.size)
    }
  }
}
