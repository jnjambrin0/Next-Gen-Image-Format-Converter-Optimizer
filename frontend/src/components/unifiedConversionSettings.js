/**
 * Unified conversion settings component for both single and batch modes
 * Provides consistent UI regardless of file count
 */

import { PresetSelector } from './presetSelector.js'
import { QualitySlider } from './qualitySlider.js'
import { SettingsGroups } from './settingsGroups.js'
import { Tooltip } from './tooltip.js'
import { showNotification } from '../utils/notifications.js'
import { uiPreferences } from '../services/uiPreferences.js'

export class UnifiedConversionSettings {
  constructor(mode = 'single') {
    this.mode = mode // 'single' | 'batch'
    this.element = null
    this.presetSelector = null
    this.qualitySlider = null
    this.progressiveUI = null
    this.settingsGroups = null
    this.eventHandlers = new Map()

    // Unified settings structure
    this.settings = {
      outputFormat: 'webp',
      quality: 85,
      preserveMetadata: false,
      presetId: null,
      presetName: null,
      // Advanced settings
      losslessCompression: false,
      enableRegionOptimization: false,
      removeAllMetadata: false,
      // Batch-specific settings
      applyToAll: true,
      optimizationMode: null,
    }

    this.onChange = null
    this.onTestConvert = null

    // Output format options
    this.outputFormats = [
      { value: 'webp', label: 'WebP', description: 'Best for web, excellent compression' },
      { value: 'avif', label: 'AVIF', description: 'Next-gen format, smaller files' },
      { value: 'jpeg', label: 'JPEG', description: 'Universal compatibility' },
      { value: 'png', label: 'PNG', description: 'Lossless, supports transparency' },
      { value: 'jxl', label: 'JPEG XL', description: 'Advanced features, good compression' },
      { value: 'heif', label: 'HEIF', description: 'Apple format, efficient storage' },
      {
        value: 'jpeg_optimized',
        label: 'JPEG (Optimized)',
        description: 'Enhanced JPEG compression',
      },
      { value: 'png_optimized', label: 'PNG (Optimized)', description: 'Smaller PNG files' },
      { value: 'webp2', label: 'WebP 2', description: 'Experimental next-gen WebP' },
      { value: 'jpeg2000', label: 'JPEG 2000', description: 'Advanced JPEG variant' },
    ]

    this.optimizationModes = [
      { value: null, label: 'None' },
      { value: 'balanced', label: 'Balanced' },
      { value: 'quality', label: 'Quality Priority' },
      { value: 'size', label: 'Size Priority' },
    ]
  }

  /**
   * Initialize the unified settings component
   */
  async init(onChange, onTestConvert, preserveSettings = false) {
    this.onChange = onChange
    this.onTestConvert = onTestConvert

    // Load UI preferences
    const preferences = uiPreferences.init()

    // Apply last used settings only if not preserving current settings
    if (!preserveSettings && preferences.lastUsedSettings) {
      this.settings = { ...this.settings, ...preferences.lastUsedSettings }
    }

    this.element = this.createElement()

    // Initialize sub-components
    await this.initializeComponents(preferences)

    return this.element
  }

  /**
   * Create the main settings element structure
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'unified-settings-panel'
    container.setAttribute('data-mode', this.mode)

    container.innerHTML = `
      <div class="settings-header">
        <h3 class="text-lg font-semibold text-gray-900">
          ${this.mode === 'batch' ? 'Batch Conversion Settings' : 'Conversion Settings'}
        </h3>
        ${
          this.mode === 'batch'
            ? `
          <p class="text-sm text-gray-600 mt-1">Settings will apply to all selected files</p>
        `
            : ''
        }
      </div>
      
      <!-- Preset Selector -->
      <div id="preset-selector-container" class="settings-section"></div>
      
      <!-- Basic Settings -->
      <div class="settings-section">
        <!-- Format Selection -->
        <div class="setting-group">
          <label for="output-format" class="setting-label">
            Output Format
            <span id="format-help" class="ml-2"></span>
          </label>
          <select id="output-format" class="setting-control">
            ${this.outputFormats
              .map(
                (format) => `
              <option value="${format.value}" ${format.value === this.settings.outputFormat ? 'selected' : ''}>
                ${format.label}
              </option>
            `
              )
              .join('')}
          </select>
          <p class="setting-description">${this.getFormatDescription(this.settings.outputFormat)}</p>
        </div>
        
        <!-- Quality Slider -->
        <div id="quality-section" class="setting-group">
          <!-- Will be replaced by QualitySlider component -->
        </div>
        
        <!-- Batch-specific: Optimization Mode -->
        ${
          this.mode === 'batch'
            ? `
          <div class="setting-group">
            <label for="optimization-mode" class="setting-label">
              Optimization Mode
            </label>
            <select id="optimization-mode" class="setting-control">
              ${this.optimizationModes
                .map(
                  (mode) => `
                <option value="${mode.value || ''}" ${mode.value === this.settings.optimizationMode ? 'selected' : ''}>
                  ${mode.label}
                </option>
              `
                )
                .join('')}
            </select>
          </div>
        `
            : ''
        }
        
        <!-- Metadata Options -->
        <div class="setting-group">
          <label class="setting-checkbox">
            <input 
              type="checkbox" 
              id="preserve-metadata"
              ${this.settings.preserveMetadata ? 'checked' : ''}
              class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            >
            <span class="text-sm text-gray-700">Preserve metadata (except GPS)</span>
          </label>
        </div>
        
        <!-- Batch-specific: Apply to All -->
        ${
          this.mode === 'batch'
            ? `
          <div class="setting-group">
            <label class="setting-checkbox">
              <input 
                type="checkbox" 
                id="apply-to-all"
                ${this.settings.applyToAll ? 'checked' : ''}
                class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              >
              <span class="text-sm text-gray-700">Apply settings to all files</span>
            </label>
          </div>
        `
            : ''
        }
      </div>
      
      <!-- Advanced Settings Toggle -->
      <div class="settings-section">
        <button id="advanced-toggle" class="advanced-toggle" aria-expanded="false">
          <svg class="toggle-icon" width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
          </svg>
          <span>Advanced Settings</span>
        </button>
      </div>
      
      <!-- Advanced Settings (Initially Hidden) -->
      <div id="advanced-settings" class="settings-section" style="display: none;">
        <!-- Settings groups will be inserted here -->
      </div>
      
      <!-- Test Conversion (Single mode only) -->
      ${
        this.mode === 'single'
          ? `
        <div id="test-conversion-section" class="settings-section">
          <!-- Test conversion UI will be inserted here -->
        </div>
      `
          : ''
      }
      
      <!-- Settings Summary -->
      <div class="settings-summary">
        <h4 class="text-sm font-medium text-gray-700 mb-2">Current Settings</h4>
        <div id="settings-summary-content" class="text-xs text-gray-600 space-y-1">
          ${this.generateSettingsSummary()}
        </div>
      </div>
    `

    return container
  }

  /**
   * Initialize sub-components
   */
  async initializeComponents(preferences) {
    // Initialize preset selector
    this.presetSelector = new PresetSelector()
    const presetElement = await this.presetSelector.init(
      (preset) => this.handlePresetChange(preset),
      () => this.getCurrentSettings()
    )
    const presetContainer = this.element.querySelector('#preset-selector-container')
    presetContainer.appendChild(presetElement)

    // Initialize quality slider
    this.qualitySlider = new QualitySlider()
    const qualityElement = this.qualitySlider.init(
      (event) => this.handleQualityChange(event),
      this.settings.quality
    )
    const qualitySection = this.element.querySelector('#quality-section')
    qualitySection.appendChild(qualityElement)

    // Initialize progressive UI for advanced settings
    if (preferences.advancedMode) {
      this.initializeAdvancedSettings()
    }

    // Attach event listeners
    this.attachEventListeners()

    // Initialize tooltips
    this.initializeTooltips()
  }

  /**
   * Initialize advanced settings groups
   */
  initializeAdvancedSettings() {
    const advancedContainer = this.element.querySelector('#advanced-settings')

    this.settingsGroups = new SettingsGroups()
    const groupsElement = this.settingsGroups.init((groupId, settings) =>
      this.handleAdvancedSettingsChange(groupId, settings)
    )

    advancedContainer.appendChild(groupsElement)
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    // Format selection
    const formatSelect = this.element.querySelector('#output-format')
    const formatHandler = (e) => {
      this.updateSetting('outputFormat', e.target.value)
      this.updateFormatDescription(e.target.value)
    }
    formatSelect.addEventListener('change', formatHandler)
    this.eventHandlers.set('format-change', {
      element: formatSelect,
      event: 'change',
      handler: formatHandler,
    })

    // Metadata checkbox
    const metadataCheckbox = this.element.querySelector('#preserve-metadata')
    const metadataHandler = (e) => {
      this.updateSetting('preserveMetadata', e.target.checked)
    }
    metadataCheckbox.addEventListener('change', metadataHandler)
    this.eventHandlers.set('metadata-change', {
      element: metadataCheckbox,
      event: 'change',
      handler: metadataHandler,
    })

    // Advanced toggle
    const advancedToggle = this.element.querySelector('#advanced-toggle')
    const toggleHandler = () => this.toggleAdvancedSettings()
    advancedToggle.addEventListener('click', toggleHandler)
    this.eventHandlers.set('advanced-toggle', {
      element: advancedToggle,
      event: 'click',
      handler: toggleHandler,
    })

    // Batch-specific listeners
    if (this.mode === 'batch') {
      const optimizationSelect = this.element.querySelector('#optimization-mode')
      if (optimizationSelect) {
        const optimizationHandler = (e) => {
          this.updateSetting('optimizationMode', e.target.value || null)
        }
        optimizationSelect.addEventListener('change', optimizationHandler)
        this.eventHandlers.set('optimization-change', {
          element: optimizationSelect,
          event: 'change',
          handler: optimizationHandler,
        })
      }

      const applyToAllCheckbox = this.element.querySelector('#apply-to-all')
      if (applyToAllCheckbox) {
        const applyToAllHandler = (e) => {
          this.updateSetting('applyToAll', e.target.checked)
        }
        applyToAllCheckbox.addEventListener('change', applyToAllHandler)
        this.eventHandlers.set('apply-to-all-change', {
          element: applyToAllCheckbox,
          event: 'change',
          handler: applyToAllHandler,
        })
      }
    }
  }

  /**
   * Initialize tooltips
   */
  initializeTooltips() {
    const formatHelp = this.element.querySelector('#format-help')
    if (formatHelp) {
      new Tooltip(formatHelp, {
        content:
          'Choose the output format based on your needs. WebP offers the best balance of quality and file size.',
        position: 'top',
      })
    }
  }

  /**
   * Handle preset change
   */
  handlePresetChange(preset) {
    if (preset) {
      // Apply preset settings
      this.settings = {
        ...this.settings,
        outputFormat: preset.outputFormat || this.settings.outputFormat,
        quality: preset.quality || this.settings.quality,
        preserveMetadata:
          preset.preserveMetadata !== undefined
            ? preset.preserveMetadata
            : this.settings.preserveMetadata,
        presetId: preset.id,
        presetName: preset.name,
      }

      // Update UI to reflect preset values
      this.updateUIFromSettings()

      showNotification('success', `Preset "${preset.name}" applied`)
    } else {
      // Clear preset
      this.settings.presetId = null
      this.settings.presetName = null
    }

    this.notifyChange()
  }

  /**
   * Handle quality change
   */
  handleQualityChange(event) {
    this.updateSetting('quality', event.detail.value)
  }

  /**
   * Handle advanced settings change
   */
  handleAdvancedSettingsChange(groupId, settings) {
    Object.keys(settings).forEach((key) => {
      this.settings[key] = settings[key]
    })
    this.notifyChange()
  }

  /**
   * Toggle advanced settings visibility
   */
  toggleAdvancedSettings() {
    const advancedContainer = this.element.querySelector('#advanced-settings')
    const toggleButton = this.element.querySelector('#advanced-toggle')
    const isExpanded = toggleButton.getAttribute('aria-expanded') === 'true'

    if (isExpanded) {
      advancedContainer.style.display = 'none'
      toggleButton.setAttribute('aria-expanded', 'false')
      toggleButton.querySelector('.toggle-icon').style.transform = 'rotate(0deg)'
    } else {
      advancedContainer.style.display = 'block'
      toggleButton.setAttribute('aria-expanded', 'true')
      toggleButton.querySelector('.toggle-icon').style.transform = 'rotate(180deg)'

      // Initialize advanced settings if not already done
      if (!this.settingsGroups) {
        this.initializeAdvancedSettings()
      }
    }

    // Save preference
    uiPreferences.update('advancedMode', !isExpanded)
  }

  /**
   * Update a specific setting
   */
  updateSetting(key, value) {
    this.settings[key] = value
    this.updateSettingsSummary()
    this.notifyChange()

    // Save to preferences
    uiPreferences.update(`lastUsedSettings.${key}`, value)
  }

  /**
   * Update UI from current settings
   */
  updateUIFromSettings() {
    // Update format select
    const formatSelect = this.element.querySelector('#output-format')
    if (formatSelect) {
      formatSelect.value = this.settings.outputFormat
      this.updateFormatDescription(this.settings.outputFormat)
    }

    // Update quality slider
    if (this.qualitySlider && this.qualitySlider.setValue) {
      this.qualitySlider.setValue(this.settings.quality)
    } else if (this.qualitySlider && this.qualitySlider.updateValue) {
      // Some sliders might use updateValue instead of setValue
      this.qualitySlider.updateValue(this.settings.quality)
    }

    // Update metadata checkbox
    const metadataCheckbox = this.element.querySelector('#preserve-metadata')
    if (metadataCheckbox) {
      metadataCheckbox.checked = this.settings.preserveMetadata
    }

    // Update batch-specific controls
    if (this.mode === 'batch') {
      const optimizationSelect = this.element.querySelector('#optimization-mode')
      if (optimizationSelect) {
        optimizationSelect.value = this.settings.optimizationMode || ''
      }

      const applyToAllCheckbox = this.element.querySelector('#apply-to-all')
      if (applyToAllCheckbox) {
        applyToAllCheckbox.checked = this.settings.applyToAll
      }
    }

    this.updateSettingsSummary()
  }

  /**
   * Update format description
   */
  updateFormatDescription(format) {
    const descriptionElement = this.element.querySelector('.setting-description')
    if (descriptionElement) {
      descriptionElement.textContent = this.getFormatDescription(format)
    }
  }

  /**
   * Get format description
   */
  getFormatDescription(format) {
    const formatInfo = this.outputFormats.find((f) => f.value === format)
    return formatInfo ? formatInfo.description : ''
  }

  /**
   * Generate settings summary
   */
  generateSettingsSummary() {
    const lines = []

    // Format and quality
    lines.push(`Format: ${this.settings.outputFormat.toUpperCase()}`)
    lines.push(`Quality: ${this.settings.quality}%`)

    // Optimization mode (batch only)
    if (this.mode === 'batch' && this.settings.optimizationMode) {
      lines.push(`Optimization: ${this.settings.optimizationMode}`)
    }

    // Metadata
    lines.push(`Metadata: ${this.settings.preserveMetadata ? 'Preserved' : 'Removed'}`)

    // Preset
    if (this.settings.presetName) {
      lines.push(`Preset: ${this.settings.presetName}`)
    }

    // Batch mode
    if (this.mode === 'batch') {
      lines.push(`Apply to: ${this.settings.applyToAll ? 'All files' : 'Individual files'}`)
    }

    return lines.map((line) => `<div>${line}</div>`).join('')
  }

  /**
   * Update settings summary display
   */
  updateSettingsSummary() {
    const summaryContent = this.element.querySelector('#settings-summary-content')
    if (summaryContent) {
      summaryContent.innerHTML = this.generateSettingsSummary()
    }
  }

  /**
   * Switch between single and batch mode
   */
  updateMode(newMode) {
    if (this.mode === newMode) {
      return
    }

    const previousSettings = { ...this.settings }
    this.mode = newMode

    // Preserve applicable settings
    this.settings = this.adaptSettingsForMode(previousSettings, newMode)

    // Re-render the component (only if element has parent for rendering)
    if (this.element && this.element.parentElement) {
      this.render()
      // Notify of change after render (synchronously for testing)
      this.notifyChange()
    } else {
      // If no parent, just update the mode attribute
      this.element?.setAttribute('data-mode', newMode)
      // Notify of change
      this.notifyChange()
    }
  }

  /**
   * Adapt settings when switching modes
   */
  adaptSettingsForMode(settings, targetMode) {
    const adapted = { ...settings }

    if (targetMode === 'batch') {
      // Add batch-specific defaults if not present
      if (adapted.applyToAll === undefined) {
        adapted.applyToAll = true
      }
      if (adapted.optimizationMode === undefined) {
        adapted.optimizationMode = null
      }
    }

    return adapted
  }

  /**
   * Re-render the component
   */
  render() {
    // Store current container
    const container = this.element?.parentElement
    if (!container) {
      // If not attached to DOM, just update the element attribute
      this.element?.setAttribute('data-mode', this.mode)
      return
    }

    // Store current settings before re-initializing
    const currentSettings = { ...this.settings }

    // Clean up existing event listeners
    this.destroy()

    // Re-initialize with preserved settings
    this.settings = currentSettings
    this.init(this.onChange, this.onTestConvert, true).then((newElement) => {
      if (container && this.element && container.contains(this.element)) {
        container.replaceChild(newElement, this.element)
      }
      this.element = newElement
      this.updateUIFromSettings()
    })
  }

  /**
   * Get current settings
   */
  getCurrentSettings() {
    return { ...this.settings }
  }

  /**
   * Set settings programmatically
   */
  setSettings(settings) {
    this.settings = { ...this.settings, ...settings }
    this.updateUIFromSettings()
    this.notifyChange()
  }

  /**
   * Set file info for single mode
   */
  setFileInfo(file) {
    if (this.qualitySlider && this.mode === 'single') {
      this.qualitySlider.setFileInfo(file)
    }
  }

  /**
   * Show test conversion loading state
   */
  showTestLoading() {
    if (this.qualitySlider && this.mode === 'single') {
      this.qualitySlider.showLoading()
    }
  }

  /**
   * Show test conversion results
   */
  showTestResults(convertedSize) {
    if (this.qualitySlider && this.mode === 'single') {
      this.qualitySlider.showTestResults(convertedSize)
    }
  }

  /**
   * Notify change callback
   */
  notifyChange() {
    if (this.onChange) {
      this.onChange(this.getCurrentSettings())
    }
  }

  /**
   * Clean up event listeners
   */
  destroy() {
    // Remove all event listeners
    this.eventHandlers.forEach(({ element, event, handler }) => {
      element?.removeEventListener(event, handler)
    })
    this.eventHandlers.clear()

    // Clean up sub-components
    if (this.presetSelector) {
      this.presetSelector.destroy?.()
    }
    if (this.qualitySlider) {
      this.qualitySlider.destroy?.()
    }
    if (this.settingsGroups) {
      this.settingsGroups.destroy?.()
    }
  }
}
