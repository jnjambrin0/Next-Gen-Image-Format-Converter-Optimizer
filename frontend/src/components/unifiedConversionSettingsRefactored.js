/**
 * Unified conversion settings component for both single and batch modes
 * Refactored version using smaller sub-components for better maintainability
 */

import { PresetSelector } from './presetSelector.js'
import { QualitySlider } from './qualitySlider.js'
import { SettingsGroups } from './settingsGroups.js'
import { showNotification } from '../utils/notifications.js'
import { uiPreferences } from '../services/uiPreferences.js'

// Import new sub-components
import { SettingsHeader } from './settings/SettingsHeader.js'
import { FormatSelector } from './settings/FormatSelector.js'
import { MetadataControls } from './settings/MetadataControls.js'
import { BatchControls } from './settings/BatchControls.js'
import { SettingsSummary } from './settings/SettingsSummary.js'

export class UnifiedConversionSettings {
  constructor(mode = 'single') {
    this.mode = mode // 'single' | 'batch'
    this.element = null
    
    // Sub-components
    this.headerComponent = null
    this.formatSelector = null
    this.metadataControls = null
    this.batchControls = null
    this.settingsSummary = null
    this.presetSelector = null
    this.qualitySlider = null
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

    // Create sections for sub-components
    container.innerHTML = `
      <div id="settings-header-container"></div>
      <div id="preset-selector-container" class="settings-section"></div>
      <div class="settings-section">
        <div id="format-selector-container"></div>
        <div id="quality-section" class="setting-group"></div>
        <div id="batch-controls-container"></div>
        <div id="metadata-controls-container"></div>
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
      
      <div id="settings-summary-container"></div>
    `

    return container
  }

  /**
   * Initialize sub-components
   */
  async initializeComponents(preferences) {
    // Initialize header
    this.headerComponent = new SettingsHeader(this.mode)
    const headerElement = this.headerComponent.init()
    this.element.querySelector('#settings-header-container').appendChild(headerElement)

    // Initialize format selector
    this.formatSelector = new FormatSelector()
    const formatElement = this.formatSelector.init(
      (data) => this.handleFormatChange(data),
      this.settings.outputFormat
    )
    this.element.querySelector('#format-selector-container').appendChild(formatElement)

    // Initialize metadata controls
    this.metadataControls = new MetadataControls()
    const metadataElement = this.metadataControls.init(
      (data) => this.handleMetadataChange(data),
      this.settings.preserveMetadata
    )
    this.element.querySelector('#metadata-controls-container').appendChild(metadataElement)

    // Initialize batch controls (batch mode only)
    if (this.mode === 'batch') {
      this.batchControls = new BatchControls()
      const batchElement = this.batchControls.init(
        (data) => this.handleBatchSettingsChange(data),
        {
          optimizationMode: this.settings.optimizationMode,
          applyToAll: this.settings.applyToAll
        }
      )
      this.element.querySelector('#batch-controls-container').appendChild(batchElement)
    }

    // Initialize settings summary
    this.settingsSummary = new SettingsSummary()
    const summaryElement = this.settingsSummary.init(this.mode)
    this.settingsSummary.updateSettings(this.settings)
    this.element.querySelector('#settings-summary-container').appendChild(summaryElement)

    // Initialize preset selector
    this.presetSelector = new PresetSelector()
    const presetElement = await this.presetSelector.init(
      (preset) => this.handlePresetChange(preset),
      () => this.getCurrentSettings()
    )
    this.element.querySelector('#preset-selector-container').appendChild(presetElement)

    // Initialize quality slider
    this.qualitySlider = new QualitySlider()
    const qualityElement = this.qualitySlider.init(
      (event) => this.handleQualityChange(event),
      this.settings.quality
    )
    this.element.querySelector('#quality-section').appendChild(qualityElement)

    // Initialize progressive UI for advanced settings
    if (preferences.advancedMode) {
      this.initializeAdvancedSettings()
    }

    // Attach event listeners
    this.attachEventListeners()
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
    // Advanced toggle
    const advancedToggle = this.element.querySelector('#advanced-toggle')
    const toggleHandler = () => this.toggleAdvancedSettings()
    advancedToggle.addEventListener('click', toggleHandler)
    this.eventHandlers.set('advanced-toggle', {
      element: advancedToggle,
      event: 'click',
      handler: toggleHandler,
    })
  }

  /**
   * Handle format change from FormatSelector
   */
  handleFormatChange(data) {
    this.updateSetting('outputFormat', data.outputFormat)
  }

  /**
   * Handle metadata change from MetadataControls
   */
  handleMetadataChange(data) {
    this.updateSetting('preserveMetadata', data.preserveMetadata)
  }

  /**
   * Handle batch settings change from BatchControls
   */
  handleBatchSettingsChange(data) {
    if (data.optimizationMode !== undefined) {
      this.updateSetting('optimizationMode', data.optimizationMode)
    }
    if (data.applyToAll !== undefined) {
      this.updateSetting('applyToAll', data.applyToAll)
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
    this.settingsSummary?.updateSettings(this.settings)
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
    this.settingsSummary?.updateSettings(this.settings)
    this.notifyChange()

    // Save to preferences
    uiPreferences.update(`lastUsedSettings.${key}`, value)
  }

  /**
   * Update UI from current settings
   */
  updateUIFromSettings() {
    // Update format selector
    if (this.formatSelector) {
      this.formatSelector.setValue(this.settings.outputFormat)
    }

    // Update quality slider
    if (this.qualitySlider) {
      if (this.qualitySlider.setValue) {
        this.qualitySlider.setValue(this.settings.quality)
      } else if (this.qualitySlider.updateValue) {
        this.qualitySlider.updateValue(this.settings.quality)
      }
    }

    // Update metadata controls
    if (this.metadataControls) {
      this.metadataControls.setValue(this.settings.preserveMetadata)
    }

    // Update batch controls
    if (this.batchControls && this.mode === 'batch') {
      this.batchControls.setSettings({
        optimizationMode: this.settings.optimizationMode,
        applyToAll: this.settings.applyToAll
      })
    }

    // Update settings summary
    if (this.settingsSummary) {
      this.settingsSummary.updateSettings(this.settings)
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

    // Update sub-components
    if (this.headerComponent) {
      this.headerComponent.updateMode(newMode)
    }

    if (this.settingsSummary) {
      this.settingsSummary.updateMode(newMode)
      this.settingsSummary.updateSettings(this.settings)
    }

    // Handle batch controls
    const batchContainer = this.element?.querySelector('#batch-controls-container')
    if (batchContainer) {
      if (newMode === 'batch' && !this.batchControls) {
        // Add batch controls
        this.batchControls = new BatchControls()
        const batchElement = this.batchControls.init(
          (data) => this.handleBatchSettingsChange(data),
          {
            optimizationMode: this.settings.optimizationMode,
            applyToAll: this.settings.applyToAll
          }
        )
        batchContainer.appendChild(batchElement)
      } else if (newMode === 'single' && this.batchControls) {
        // Remove batch controls
        batchContainer.innerHTML = ''
        this.batchControls.destroy()
        this.batchControls = null
      }
    }

    // Update data attribute
    this.element?.setAttribute('data-mode', newMode)
    
    // Notify of change
    this.notifyChange()
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
    const container = this.element?.parentElement
    if (!container) {
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
   * Clean up event listeners and sub-components
   */
  destroy() {
    // Remove all event listeners
    this.eventHandlers.forEach(({ element, event, handler }) => {
      element?.removeEventListener(event, handler)
    })
    this.eventHandlers.clear()

    // Clean up sub-components
    if (this.headerComponent) {
      this.headerComponent.destroy?.()
    }
    if (this.formatSelector) {
      this.formatSelector.destroy?.()
    }
    if (this.metadataControls) {
      this.metadataControls.destroy?.()
    }
    if (this.batchControls) {
      this.batchControls.destroy?.()
    }
    if (this.settingsSummary) {
      this.settingsSummary.destroy?.()
    }
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