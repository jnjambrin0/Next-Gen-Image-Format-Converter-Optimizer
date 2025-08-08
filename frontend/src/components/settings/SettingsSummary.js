/**
 * Settings summary component that displays current conversion settings
 * Provides real-time updates and a concise view of all active settings
 */

export class SettingsSummary {
  constructor() {
    this.element = null
    this.mode = 'single'
    this.settings = {
      outputFormat: 'webp',
      quality: 85,
      preserveMetadata: false,
      presetName: null,
      optimizationMode: null,
      applyToAll: true,
    }
  }

  /**
   * Initialize the settings summary
   * @param {string} mode - The current mode ('single' or 'batch')
   * @returns {HTMLElement} The settings summary element
   */
  init(mode = 'single') {
    this.mode = mode
    this.element = this.createElement()
    return this.element
  }

  /**
   * Create the settings summary element
   * @returns {HTMLElement} The settings summary element
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'settings-summary'

    const title = document.createElement('h4')
    title.className = 'text-sm font-medium text-gray-700 mb-2'
    title.textContent = 'Current Settings'

    const content = document.createElement('div')
    content.id = 'settings-summary-content'
    content.className = 'text-xs text-gray-600 space-y-1'
    content.innerHTML = this.generateSummaryHTML()

    container.appendChild(title)
    container.appendChild(content)

    return container
  }

  /**
   * Generate the summary HTML
   * @returns {string} The summary HTML
   */
  generateSummaryHTML() {
    const lines = []

    // Format and quality
    lines.push(`Format: ${this.settings.outputFormat.toUpperCase()}`)
    lines.push(`Quality: ${this.settings.quality}%`)

    // Optimization mode (batch only)
    if (this.mode === 'batch' && this.settings.optimizationMode) {
      const modeLabel = this.getOptimizationModeLabel(this.settings.optimizationMode)
      lines.push(`Optimization: ${modeLabel}`)
    }

    // Metadata
    lines.push(`Metadata: ${this.settings.preserveMetadata ? 'Preserved' : 'Removed'}`)

    // Preset
    if (this.settings.presetName) {
      lines.push(`Preset: ${this.settings.presetName}`)
    }

    // Batch mode specific
    if (this.mode === 'batch') {
      lines.push(`Apply to: ${this.settings.applyToAll ? 'All files' : 'Individual files'}`)
    }

    // Advanced settings if any
    if (this.settings.losslessCompression) {
      lines.push('Lossless: Enabled')
    }
    if (this.settings.enableRegionOptimization) {
      lines.push('Region Optimization: Enabled')
    }
    if (this.settings.removeAllMetadata) {
      lines.push('Remove All Metadata: Yes')
    }

    return lines.map((line) => `<div>${this.escapeHtml(line)}</div>`).join('')
  }

  /**
   * Get optimization mode label
   * @param {string} mode - The optimization mode value
   * @returns {string} The human-readable label
   */
  getOptimizationModeLabel(mode) {
    const modeMap = {
      balanced: 'Balanced',
      quality: 'Quality Priority',
      size: 'Size Priority',
    }
    return modeMap[mode] || 'None'
  }

  /**
   * Update the settings and refresh display
   * @param {Object} newSettings - The new settings to apply
   */
  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings }
    this.refresh()
  }

  /**
   * Update the mode and refresh if needed
   * @param {string} newMode - The new mode ('single' or 'batch')
   */
  updateMode(newMode) {
    if (this.mode === newMode) {
      return
    }

    this.mode = newMode
    this.refresh()
  }

  /**
   * Refresh the summary display
   */
  refresh() {
    const content = this.element?.querySelector('#settings-summary-content')
    if (content) {
      content.innerHTML = this.generateSummaryHTML()
    }
  }

  /**
   * Escape HTML to prevent XSS
   * @param {string} text - The text to escape
   * @returns {string} The escaped text
   */
  escapeHtml(text) {
    const div = document.createElement('div')
    div.textContent = text
    return div.innerHTML
  }

  /**
   * Clean up the component
   */
  destroy() {
    if (this.element && this.element.parentElement) {
      this.element.parentElement.removeChild(this.element)
    }
    this.element = null
  }
}
