/**
 * Conversion settings component including format, quality, and presets
 */

import { PresetSelector } from './presetSelector.js'
import { QualitySlider } from './qualitySlider.js'
import { presetApi } from '../services/presetApi.js'
import { showNotification } from '../utils/notifications.js'

export class ConversionSettings {
  constructor() {
    this.element = null
    this.presetSelector = null
    this.qualitySlider = null
    this.settings = {
      outputFormat: 'webp',
      quality: 85,
      preserveMetadata: false,
      presetId: null,
      presetName: null,
    }
    this.onChange = null
    this.onTestConvert = null
  }

  /**
   * Initialize the conversion settings
   * @param {Function} onChange - Callback when settings change
   * @param {Function} onTestConvert - Callback for test conversion
   */
  async init(onChange, onTestConvert) {
    this.onChange = onChange
    this.onTestConvert = onTestConvert
    this.element = this.createElement()

    // Initialize preset selector
    this.presetSelector = new PresetSelector()
    const presetElement = await this.presetSelector.init(
      (preset) => this.handlePresetChange(preset),
      () => this.getCurrentSettings()
    )

    // Initialize quality slider
    this.qualitySlider = new QualitySlider()
    const qualityElement = this.qualitySlider.init(
      (event) => this.handleQualityChange(event),
      this.settings.quality
    )

    // Insert preset selector at the top
    this.element.insertBefore(presetElement, this.element.firstChild)

    // Replace the old quality slider with the new component
    const oldQualitySection = this.element.querySelector('#quality-section')
    if (oldQualitySection) {
      oldQualitySection.replaceWith(qualityElement)
    }

    return this.element
  }

  /**
   * Create the settings element
   */
  createElement() {
    const container = document.createElement('div')
    container.innerHTML = `
      <!-- Format Selection -->
      <div class="mb-4">
        <label for="output-format" class="block text-sm font-medium text-gray-700 mb-2">
          Output Format
        </label>
        <select id="output-format" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
          <option value="webp" selected>WebP - Best balance</option>
          <option value="avif">AVIF - Smaller files</option>
          <option value="jpeg">JPEG - Compatible</option>
          <option value="png">PNG - Lossless</option>
        </select>
      </div>

      <!-- Quality Slider Placeholder -->
      <div id="quality-section" class="mb-4">
        <!-- Will be replaced by QualitySlider component -->
      </div>

      <!-- Metadata Options -->
      <div class="mb-4">
        <label class="flex items-center">
          <input 
            type="checkbox" 
            id="preserve-metadata" 
            class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          >
          <span class="text-sm text-gray-700">Preserve metadata (except GPS)</span>
        </label>
      </div>

      <!-- Conversion Info -->
      <div id="conversion-info" class="text-sm text-gray-600 bg-gray-50 p-3 rounded-md hidden">
        <!-- Dynamic content -->
      </div>
    `

    this.attachEventListeners(container)
    return container
  }

  /**
   * Attach event listeners
   */
  attachEventListeners(container) {
    const formatSelect = container.querySelector('#output-format')
    const preserveMetadata = container.querySelector('#preserve-metadata')

    // Format change
    formatSelect.addEventListener('change', (e) => {
      this.settings.outputFormat = e.target.value
      this.updateConversionInfo()

      // Update quality slider format
      if (this.qualitySlider) {
        this.qualitySlider.setOutputFormat(e.target.value)
      }

      this.notifyChange()
    })

    // Metadata toggle
    preserveMetadata.addEventListener('change', (e) => {
      this.settings.preserveMetadata = e.target.checked
      this.notifyChange()
    })
  }

  /**
   * Handle quality slider changes
   */
  handleQualityChange(event) {
    if (event.quality !== undefined) {
      this.settings.quality = event.quality
      this.updateConversionInfo()
      this.notifyChange()
    } else if (event.action === 'test-convert') {
      if (this.onTestConvert) {
        this.onTestConvert()
      }
    }
  }

  /**
   * Handle preset selection change
   */
  handlePresetChange(preset) {
    if (preset) {
      // Apply preset settings
      const presetSettings = presetApi.applyPresetToSettings(preset)

      // Update UI
      const formatSelect = this.element.querySelector('#output-format')
      const preserveMetadata = this.element.querySelector('#preserve-metadata')

      formatSelect.value = presetSettings.outputFormat
      preserveMetadata.checked = presetSettings.preserveMetadata

      // Update quality slider
      if (this.qualitySlider) {
        const slider = this.qualitySlider.element.querySelector('#quality-slider')
        const valueDisplay = this.qualitySlider.element.querySelector('#quality-value')
        if (slider) {
          slider.value = presetSettings.quality
        }
        if (valueDisplay) {
          valueDisplay.textContent = presetSettings.quality
        }
        this.qualitySlider.quality = presetSettings.quality
        this.qualitySlider.setOutputFormat(presetSettings.outputFormat)
      }

      // Update internal settings
      this.settings = {
        ...this.settings,
        ...presetSettings,
      }

      this.updateConversionInfo()
      this.notifyChange()

      showNotification(`Applied preset: ${preset.name}`, 'info')
    } else {
      // Clear preset
      this.settings.presetId = null
      this.settings.presetName = null
      this.notifyChange()
    }
  }

  /**
   * Update conversion info display
   */
  updateConversionInfo() {
    const infoElement = this.element.querySelector('#conversion-info')
    const { outputFormat, quality, presetName } = this.settings

    let info = ''

    if (presetName) {
      info += `<div class="font-medium mb-1">Using preset: ${presetName}</div>`
    }

    // Format-specific info
    switch (outputFormat) {
      case 'webp':
        info += `<div>WebP provides excellent compression with ${quality < 95 ? 'lossy' : 'near-lossless'} quality.</div>`
        break
      case 'avif':
        info += `<div>AVIF offers superior compression but may take longer to process.</div>`
        break
      case 'jpeg':
        info += `<div>JPEG is widely compatible but doesn't support transparency.</div>`
        break
      case 'png':
        info += `<div>PNG provides lossless compression${quality < 100 ? ' (quality setting will be ignored)' : ''}.</div>`
        break
    }

    infoElement.innerHTML = info
    infoElement.classList.toggle('hidden', !info)
  }

  /**
   * Get current settings
   */
  getCurrentSettings() {
    return { ...this.settings }
  }

  /**
   * Notify settings change
   */
  notifyChange() {
    if (this.onChange) {
      this.onChange(this.getCurrentSettings())
    }
  }

  /**
   * Reset to default settings
   */
  reset() {
    this.settings = {
      outputFormat: 'webp',
      quality: 85,
      preserveMetadata: false,
      presetId: null,
      presetName: null,
    }

    // Update UI
    const formatSelect = this.element.querySelector('#output-format')
    const preserveMetadata = this.element.querySelector('#preserve-metadata')

    formatSelect.value = 'webp'
    preserveMetadata.checked = false

    // Reset quality slider
    if (this.qualitySlider) {
      this.qualitySlider.reset()
    }

    // Clear preset selection
    if (this.presetSelector) {
      this.presetSelector.clearSelection()
    }

    this.updateConversionInfo()
    this.notifyChange()
  }

  /**
   * Set file info for the quality slider
   * @param {File} file - The selected file
   */
  setFileInfo(file) {
    if (this.qualitySlider && file) {
      this.qualitySlider.setOriginalFileSize(file.size)
      this.qualitySlider.setOutputFormat(this.settings.outputFormat)
    }
  }

  /**
   * Show test conversion loading state
   */
  showTestLoading() {
    if (this.qualitySlider) {
      this.qualitySlider.showTestLoading()
    }
  }

  /**
   * Show test conversion results
   * @param {number} actualSize - Actual converted file size
   */
  showTestResults(actualSize) {
    if (this.qualitySlider) {
      this.qualitySlider.showTestResults(actualSize)
    }
  }

  /**
   * Show test conversion error
   * @param {string} errorMessage - Error message to display
   */
  showTestError(errorMessage) {
    if (this.qualitySlider) {
      this.qualitySlider.showTestError(errorMessage)
    }
  }
}
