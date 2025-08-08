/**
 * Batch controls component for batch-specific conversion settings
 * Handles optimization modes and batch application settings
 */

export class BatchControls {
  constructor() {
    this.element = null
    this.onChange = null
    this.settings = {
      optimizationMode: null,
      applyToAll: true,
    }

    this.optimizationModes = [
      { value: null, label: 'None' },
      { value: 'balanced', label: 'Balanced' },
      { value: 'quality', label: 'Quality Priority' },
      { value: 'size', label: 'Size Priority' },
    ]
  }

  /**
   * Initialize the batch controls
   * @param {Function} onChange - Callback when settings change
   * @param {Object} initialSettings - Initial batch settings
   * @returns {HTMLElement} The batch controls element
   */
  init(onChange, initialSettings = {}) {
    this.onChange = onChange
    this.settings = {
      ...this.settings,
      ...initialSettings,
    }
    this.element = this.createElement()
    this.attachEventListeners()
    return this.element
  }

  /**
   * Create the batch controls element
   * @returns {HTMLElement} The batch controls element
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'batch-controls'

    // Optimization mode selector
    const optimizationGroup = document.createElement('div')
    optimizationGroup.className = 'setting-group'

    const optimizationLabel = document.createElement('label')
    optimizationLabel.htmlFor = 'optimization-mode'
    optimizationLabel.className = 'setting-label'
    optimizationLabel.textContent = 'Optimization Mode'

    const optimizationSelect = document.createElement('select')
    optimizationSelect.id = 'optimization-mode'
    optimizationSelect.className = 'setting-control'

    this.optimizationModes.forEach((mode) => {
      const option = document.createElement('option')
      option.value = mode.value || ''
      option.textContent = mode.label
      if (mode.value === this.settings.optimizationMode) {
        option.selected = true
      }
      optimizationSelect.appendChild(option)
    })

    const optimizationInfo = document.createElement('p')
    optimizationInfo.className = 'text-xs text-gray-500 mt-1'
    optimizationInfo.textContent = 'Choose how to balance quality vs file size for all images'

    optimizationGroup.appendChild(optimizationLabel)
    optimizationGroup.appendChild(optimizationSelect)
    optimizationGroup.appendChild(optimizationInfo)

    // Apply to all checkbox
    const applyGroup = document.createElement('div')
    applyGroup.className = 'setting-group'

    const applyLabel = document.createElement('label')
    applyLabel.className = 'setting-checkbox'

    const applyCheckbox = document.createElement('input')
    applyCheckbox.type = 'checkbox'
    applyCheckbox.id = 'apply-to-all'
    applyCheckbox.checked = this.settings.applyToAll
    applyCheckbox.className =
      'mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded'

    const applyText = document.createElement('span')
    applyText.className = 'text-sm text-gray-700'
    applyText.textContent = 'Apply settings to all files'

    applyLabel.appendChild(applyCheckbox)
    applyLabel.appendChild(applyText)
    applyGroup.appendChild(applyLabel)

    const applyInfo = document.createElement('p')
    applyInfo.className = 'text-xs text-gray-500 mt-1 ml-6'
    applyInfo.textContent = 'Use the same settings for every file in the batch'
    applyGroup.appendChild(applyInfo)

    container.appendChild(optimizationGroup)
    container.appendChild(applyGroup)

    return container
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    const optimizationSelect = this.element.querySelector('#optimization-mode')
    if (optimizationSelect) {
      optimizationSelect.addEventListener('change', (e) => {
        this.handleOptimizationChange(e.target.value || null)
      })
    }

    const applyCheckbox = this.element.querySelector('#apply-to-all')
    if (applyCheckbox) {
      applyCheckbox.addEventListener('change', (e) => {
        this.handleApplyToAllChange(e.target.checked)
      })
    }
  }

  /**
   * Handle optimization mode change
   * @param {string|null} mode - The new optimization mode
   */
  handleOptimizationChange(mode) {
    this.settings.optimizationMode = mode
    this.notifyChange()
  }

  /**
   * Handle apply to all change
   * @param {boolean} applyToAll - Whether to apply to all files
   */
  handleApplyToAllChange(applyToAll) {
    this.settings.applyToAll = applyToAll
    this.notifyChange()
  }

  /**
   * Notify change callback
   */
  notifyChange() {
    if (this.onChange) {
      this.onChange(this.settings)
    }
  }

  /**
   * Set the settings programmatically
   * @param {Object} settings - The settings to set
   */
  setSettings(settings) {
    if (settings.optimizationMode !== undefined) {
      const select = this.element?.querySelector('#optimization-mode')
      if (select) {
        select.value = settings.optimizationMode || ''
        this.settings.optimizationMode = settings.optimizationMode
      }
    }

    if (settings.applyToAll !== undefined) {
      const checkbox = this.element?.querySelector('#apply-to-all')
      if (checkbox) {
        checkbox.checked = settings.applyToAll
        this.settings.applyToAll = settings.applyToAll
      }
    }
  }

  /**
   * Get the current settings
   * @returns {Object} The current batch settings
   */
  getSettings() {
    return { ...this.settings }
  }

  /**
   * Clean up the component
   */
  destroy() {
    const optimizationSelect = this.element?.querySelector('#optimization-mode')
    if (optimizationSelect) {
      optimizationSelect.removeEventListener('change', this.handleOptimizationChange)
    }

    const applyCheckbox = this.element?.querySelector('#apply-to-all')
    if (applyCheckbox) {
      applyCheckbox.removeEventListener('change', this.handleApplyToAllChange)
    }

    this.element = null
    this.onChange = null
  }
}
