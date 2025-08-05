/**
 * Enhanced conversion settings component with progressive disclosure
 * Integrates all new progressive UI features
 */

import { PresetSelector } from './presetSelector.js'
import { QualitySlider } from './qualitySlider.js'
import { presetApi } from '../services/presetApi.js'
import { showNotification } from '../utils/notifications.js'
import { ProgressiveUI } from './progressiveUI.js'
import { SettingsGroups } from './settingsGroups.js'
import { Tooltip } from './tooltip.js'
import { uiPreferences } from '../services/uiPreferences.js'

export class ConversionSettingsProgressive {
  constructor() {
    this.element = null
    this.presetSelector = null
    this.qualitySlider = null
    this.progressiveUI = null
    this.settingsGroups = null
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
    }
    this.onChange = null
    this.onTestConvert = null
  }

  /**
   * Initialize the conversion settings with progressive disclosure
   */
  async init(onChange, onTestConvert) {
    this.onChange = onChange
    this.onTestConvert = onTestConvert

    // Load UI preferences
    const preferences = uiPreferences.init()

    // Apply last used settings
    if (preferences.lastUsedSettings) {
      this.settings = { ...this.settings, ...preferences.lastUsedSettings }
    }

    this.element = this.createElement()

    // Initialize components
    await this.initializeComponents(preferences)

    return this.element
  }

  /**
   * Create the main settings element structure
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'space-y-4'

    container.innerHTML = `
      <!-- Basic Settings (Always Visible) -->
      <div id="basic-settings" class="space-y-4">
        <!-- Preset Selector will be inserted here -->
        <div id="preset-selector-container"></div>
        
        <!-- Format Selection -->
        <div class="flex items-center">
          <label for="output-format" class="block text-sm font-medium text-gray-700 mr-2">
            Output Format
          </label>
          <select id="output-format" class="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="webp" selected>WebP - Best balance</option>
            <option value="avif">AVIF - Smaller files</option>
            <option value="jpeg">JPEG - Compatible</option>
            <option value="png">PNG - Lossless</option>
          </select>
          <span id="format-help" class="ml-2"></span>
        </div>
      </div>
      
      <!-- Advanced Toggle Button -->
      <div class="flex justify-center">
        <button id="advanced-toggle" class="advanced-toggle" aria-expanded="false">
          Show Advanced Settings
        </button>
      </div>
      
      <!-- Advanced Settings (Initially Hidden) -->
      <div id="advanced-settings" style="display: none;">
        <!-- Settings groups will be inserted here -->
      </div>
      
      <!-- Customization Button (Shown in Advanced Mode) -->
      <div id="customization-container" class="flex justify-end" style="display: none;">
        <button id="customize-ui" class="text-sm text-blue-600 hover:text-blue-800">
          Customize UI
        </button>
      </div>
      
      <!-- Conversion Info -->
      <div id="conversion-info" class="text-sm text-gray-600 bg-gray-50 p-3 rounded-md hidden">
        <!-- Dynamic content -->
      </div>
    `

    this.attachBasicEventListeners(container)
    return container
  }

  /**
   * Initialize all components
   */
  async initializeComponents(preferences) {
    // Initialize preset selector
    this.presetSelector = new PresetSelector()
    const presetContainer = this.element.querySelector('#preset-selector-container')
    const presetElement = await this.presetSelector.init(
      (preset) => this.handlePresetChange(preset),
      () => this.getCurrentSettings()
    )
    presetContainer.appendChild(presetElement)

    // Initialize quality slider
    this.qualitySlider = new QualitySlider()
    const qualityElement = this.qualitySlider.init(
      (event) => this.handleQualityChange(event),
      this.settings.quality
    )

    // Create advanced settings groups
    const advancedElements = this.createAdvancedSettings(qualityElement)

    // Initialize settings groups
    this.settingsGroups = new SettingsGroups()
    const groupsElement = this.settingsGroups.init({
      elements: advancedElements,
      onGroupToggle: (groupId, expanded) => {
        uiPreferences.update(`groupStates.${groupId}`, expanded)
      },
    })

    // Apply saved group states
    if (preferences.groupStates) {
      this.settingsGroups.setGroupStates(preferences.groupStates)
    }

    // Add groups to advanced settings
    const advancedContainer = this.element.querySelector('#advanced-settings')
    advancedContainer.appendChild(groupsElement)

    // Initialize progressive UI
    this.progressiveUI = new ProgressiveUI()
    this.progressiveUI.init({
      toggleButton: this.element.querySelector('#advanced-toggle'),
      advancedContainer: advancedContainer,
      basicContainer: this.element.querySelector('#basic-settings'),
      onModeChange: (isAdvanced) => {
        uiPreferences.update('advancedMode', isAdvanced)

        // Show/hide customization button
        const customizationContainer = this.element.querySelector('#customization-container')
        customizationContainer.style.display = isAdvanced ? 'flex' : 'none'
      },
    })

    // Apply saved advanced mode state
    if (preferences.advancedMode) {
      this.progressiveUI.setMode(true)
    }

    // Add tooltips
    this.addTooltips()

    // Setup customization button
    this.setupCustomization()
  }

  /**
   * Create advanced settings elements
   */
  createAdvancedSettings(qualityElement) {
    // Quality settings group
    const qualitySettings = [qualityElement]

    // Optimization settings group
    const optimizationSettings = []

    // Lossless compression option
    const losslessDiv = document.createElement('div')
    losslessDiv.innerHTML = `
      <label class="flex items-center">
        <input 
          type="checkbox" 
          id="lossless-compression" 
          class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          ${this.settings.losslessCompression ? 'checked' : ''}
        >
        <span class="text-sm text-gray-700">Enable lossless compression</span>
        <span id="lossless-help" class="ml-1"></span>
      </label>
    `
    optimizationSettings.push(losslessDiv)

    // Region optimization option
    const regionOptDiv = document.createElement('div')
    regionOptDiv.innerHTML = `
      <label class="flex items-center">
        <input 
          type="checkbox" 
          id="region-optimization" 
          class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          ${this.settings.enableRegionOptimization ? 'checked' : ''}
        >
        <span class="text-sm text-gray-700">Enable smart region optimization</span>
        <span id="region-help" class="ml-1"></span>
      </label>
    `
    optimizationSettings.push(regionOptDiv)

    // Metadata settings group
    const metadataSettings = []

    // Preserve metadata option
    const preserveMetaDiv = document.createElement('div')
    preserveMetaDiv.innerHTML = `
      <label class="flex items-center">
        <input 
          type="checkbox" 
          id="preserve-metadata" 
          class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          ${this.settings.preserveMetadata ? 'checked' : ''}
        >
        <span class="text-sm text-gray-700">Preserve metadata (except GPS)</span>
        <span id="preserve-meta-help" class="ml-1"></span>
      </label>
    `
    metadataSettings.push(preserveMetaDiv)

    // Remove all metadata option
    const removeAllMetaDiv = document.createElement('div')
    removeAllMetaDiv.innerHTML = `
      <label class="flex items-center">
        <input 
          type="checkbox" 
          id="remove-all-metadata" 
          class="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          ${this.settings.removeAllMetadata ? 'checked' : ''}
        >
        <span class="text-sm text-gray-700">Remove all metadata</span>
        <span id="remove-all-help" class="ml-1"></span>
      </label>
    `
    metadataSettings.push(removeAllMetaDiv)

    // Attach event listeners
    this.attachAdvancedEventListeners({
      lossless: losslessDiv,
      regionOpt: regionOptDiv,
      preserveMeta: preserveMetaDiv,
      removeAllMeta: removeAllMetaDiv,
    })

    return {
      quality: qualitySettings,
      optimization: optimizationSettings,
      metadata: metadataSettings,
    }
  }

  /**
   * Add tooltips to help icons
   */
  addTooltips() {
    const tooltips = [
      {
        selector: '#format-help',
        content:
          'Choose the output format based on your needs:<br>• WebP: Best for web, good balance<br>• AVIF: Smaller files, newer format<br>• JPEG: Universal compatibility<br>• PNG: Lossless, supports transparency',
        html: true,
      },
      {
        selector: '#lossless-help',
        content:
          'Apply additional lossless compression after conversion to reduce file size without quality loss',
      },
      {
        selector: '#region-help',
        content:
          'Intelligently optimize different regions of the image based on content (faces, text, etc.)',
      },
      {
        selector: '#preserve-meta-help',
        content:
          'Keep camera settings, color profile, and other metadata. GPS location is always removed for privacy.',
      },
      {
        selector: '#remove-all-help',
        content:
          'Strip all metadata including EXIF, IPTC, XMP, and color profiles for maximum privacy',
      },
    ]

    tooltips.forEach(({ selector, content, html }) => {
      const container = this.element.querySelector(selector)
      if (container) {
        const helpIcon = Tooltip.createHelpIcon(content, { html })
        container.appendChild(helpIcon)
      }
    })
  }

  /**
   * Setup customization modal
   */
  setupCustomization() {
    const customizeBtn = this.element.querySelector('#customize-ui')
    customizeBtn.addEventListener('click', () => {
      this.showCustomizationModal()
    })
  }

  /**
   * Show UI customization modal
   */
  showCustomizationModal() {
    const modal = document.createElement('div')
    modal.className = 'customization-modal'

    const content = document.createElement('div')
    content.className = 'bg-white rounded-lg shadow-xl max-w-md w-full p-6'

    content.innerHTML = `
      <h2 class="text-xl font-semibold mb-4">Customize UI</h2>
      
      <div class="space-y-4">
        <h3 class="text-sm font-semibold text-gray-700">Visible Sections</h3>
        
        <label class="flex items-center">
          <input type="checkbox" id="show-quality" class="mr-2" checked>
          <span class="text-sm">Quality Settings</span>
        </label>
        
        <label class="flex items-center">
          <input type="checkbox" id="show-optimization" class="mr-2" checked>
          <span class="text-sm">Optimization Settings</span>
        </label>
        
        <label class="flex items-center">
          <input type="checkbox" id="show-metadata" class="mr-2" checked>
          <span class="text-sm">Metadata Settings</span>
        </label>
        
        <hr>
        
        <h3 class="text-sm font-semibold text-gray-700">Display Options</h3>
        
        <label class="flex items-center">
          <input type="checkbox" id="show-tooltips" class="mr-2" checked>
          <span class="text-sm">Show help tooltips</span>
        </label>
        
        <label class="flex items-center">
          <input type="checkbox" id="enable-animations" class="mr-2" checked>
          <span class="text-sm">Enable animations</span>
        </label>
        
        <label class="flex items-center">
          <input type="checkbox" id="compact-mode" class="mr-2">
          <span class="text-sm">Compact mode</span>
        </label>
      </div>
      
      <div class="flex justify-end space-x-2 mt-6">
        <button id="cancel-custom" class="px-4 py-2 text-sm text-gray-700 bg-gray-200 rounded hover:bg-gray-300">
          Cancel
        </button>
        <button id="save-custom" class="px-4 py-2 text-sm text-white bg-blue-600 rounded hover:bg-blue-700">
          Save Changes
        </button>
      </div>
    `

    modal.appendChild(content)
    document.body.appendChild(modal)

    // Load current preferences
    const prefs = uiPreferences.load()
    const showQuality = content.querySelector('#show-quality')
    const showOptimization = content.querySelector('#show-optimization')
    const showMetadata = content.querySelector('#show-metadata')
    const showTooltips = content.querySelector('#show-tooltips')
    const enableAnimations = content.querySelector('#enable-animations')
    const compactMode = content.querySelector('#compact-mode')

    showQuality.checked = prefs.visibleSections?.quality ?? true
    showOptimization.checked = prefs.visibleSections?.optimization ?? true
    showMetadata.checked = prefs.visibleSections?.metadata ?? true
    showTooltips.checked = prefs.customization?.showTooltips ?? true
    enableAnimations.checked = prefs.customization?.animationsEnabled ?? true
    compactMode.checked = prefs.customization?.compactMode ?? false

    // Event handlers
    content.querySelector('#cancel-custom').onclick = () => {
      document.body.removeChild(modal)
    }

    content.querySelector('#save-custom').onclick = () => {
      // Save preferences
      uiPreferences.update('visibleSections.quality', showQuality.checked)
      uiPreferences.update('visibleSections.optimization', showOptimization.checked)
      uiPreferences.update('visibleSections.metadata', showMetadata.checked)
      uiPreferences.update('customization.showTooltips', showTooltips.checked)
      uiPreferences.update('customization.animationsEnabled', enableAnimations.checked)
      uiPreferences.update('customization.compactMode', compactMode.checked)

      // Apply changes
      this.applyCustomization()

      // Close modal
      document.body.removeChild(modal)

      showNotification('UI preferences saved', 'success')
    }

    // Close on background click
    modal.onclick = (e) => {
      if (e.target === modal) {
        document.body.removeChild(modal)
      }
    }
  }

  /**
   * Apply UI customization
   */
  applyCustomization() {
    const prefs = uiPreferences.load()

    // Apply compact mode
    if (prefs.customization?.compactMode) {
      document.body.classList.add('compact-mode')
    } else {
      document.body.classList.remove('compact-mode')
    }

    // TODO: Apply other customization options
    // This would require reloading some components
  }

  /**
   * Attach event listeners for basic settings
   */
  attachBasicEventListeners(container) {
    const formatSelect = container.querySelector('#output-format')

    formatSelect.addEventListener('change', (e) => {
      this.settings.outputFormat = e.target.value
      this.updateConversionInfo()

      if (this.qualitySlider) {
        this.qualitySlider.setOutputFormat(e.target.value)
      }

      this.notifyChange()
      this.saveLastUsedSettings()
    })
  }

  /**
   * Attach event listeners for advanced settings
   */
  attachAdvancedEventListeners(elements) {
    const losslessCheckbox = elements.lossless.querySelector('#lossless-compression')
    const regionOptCheckbox = elements.regionOpt.querySelector('#region-optimization')
    const preserveMetaCheckbox = elements.preserveMeta.querySelector('#preserve-metadata')
    const removeAllMetaCheckbox = elements.removeAllMeta.querySelector('#remove-all-metadata')

    losslessCheckbox.addEventListener('change', (e) => {
      this.settings.losslessCompression = e.target.checked
      this.notifyChange()
      this.saveLastUsedSettings()
    })

    regionOptCheckbox.addEventListener('change', (e) => {
      this.settings.enableRegionOptimization = e.target.checked
      this.notifyChange()
      this.saveLastUsedSettings()
    })

    preserveMetaCheckbox.addEventListener('change', (e) => {
      this.settings.preserveMetadata = e.target.checked
      if (e.target.checked) {
        removeAllMetaCheckbox.checked = false
        this.settings.removeAllMetadata = false
      }
      this.notifyChange()
      this.saveLastUsedSettings()
    })

    removeAllMetaCheckbox.addEventListener('change', (e) => {
      this.settings.removeAllMetadata = e.target.checked
      if (e.target.checked) {
        preserveMetaCheckbox.checked = false
        this.settings.preserveMetadata = false
      }
      this.notifyChange()
      this.saveLastUsedSettings()
    })
  }

  /**
   * Save last used settings to preferences
   */
  saveLastUsedSettings() {
    const settingsToSave = {
      outputFormat: this.settings.outputFormat,
      quality: this.settings.quality,
      preserveMetadata: this.settings.preserveMetadata,
    }
    uiPreferences.update('lastUsedSettings', settingsToSave)
  }

  /**
   * Handle quality slider changes
   */
  handleQualityChange(event) {
    if (event.quality !== undefined) {
      this.settings.quality = event.quality
      this.updateConversionInfo()
      this.notifyChange()
      this.saveLastUsedSettings()
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

    // SECURITY FIX: Use DOM manipulation instead of innerHTML
    while (infoElement.firstChild) {
      infoElement.removeChild(infoElement.firstChild)
    }

    let hasInfo = false

    if (presetName) {
      const presetDiv = document.createElement('div')
      presetDiv.className = 'font-medium mb-1'
      presetDiv.textContent = `Using preset: ${presetName}`
      infoElement.appendChild(presetDiv)
      hasInfo = true
    }

    // Format-specific info
    const formatDiv = document.createElement('div')
    switch (outputFormat) {
      case 'webp':
        formatDiv.textContent = `WebP provides excellent compression with ${quality < 95 ? 'lossy' : 'near-lossless'} quality.`
        break
      case 'avif':
        formatDiv.textContent = 'AVIF offers superior compression but may take longer to process.'
        break
      case 'jpeg':
        formatDiv.textContent = "JPEG is widely compatible but doesn't support transparency."
        break
      case 'png':
        formatDiv.textContent = `PNG provides lossless compression${quality < 100 ? ' (quality setting will be ignored)' : ''}.`
        break
    }
    
    if (formatDiv.textContent) {
      infoElement.appendChild(formatDiv)
      hasInfo = true
    }

    infoElement.classList.toggle('hidden', !hasInfo)
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
   * Set file info for the quality slider
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
   */
  showTestResults(actualSize) {
    if (this.qualitySlider) {
      this.qualitySlider.showTestResults(actualSize)
    }
  }

  /**
   * Show test conversion error
   */
  showTestError(errorMessage) {
    if (this.qualitySlider) {
      this.qualitySlider.showTestError(errorMessage)
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
      losslessCompression: false,
      enableRegionOptimization: false,
      removeAllMetadata: false,
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
}
