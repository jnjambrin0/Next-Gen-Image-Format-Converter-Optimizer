/**
 * Preset selector component for choosing and managing conversion presets
 */

import { presetApi } from '../services/presetApi.js'
import { showNotification } from '../utils/notifications.js'

export class PresetSelector {
  constructor() {
    this.element = null
    this.presets = []
    this.selectedPreset = null
    this.onPresetChange = null
    this.onSaveAsPreset = null
  }

  /**
   * Initialize the preset selector
   * @param {Function} onPresetChange - Callback when preset is selected
   * @param {Function} onSaveAsPreset - Callback to get current settings for saving
   */
  async init(onPresetChange, onSaveAsPreset) {
    this.onPresetChange = onPresetChange
    this.onSaveAsPreset = onSaveAsPreset

    this.element = this.createElement()
    await this.loadPresets()
    return this.element
  }

  /**
   * Create the preset selector element
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'preset-selector bg-white rounded-lg shadow-sm p-4 mb-4'
    container.innerHTML = `
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-lg font-medium text-gray-900">Conversion Presets</h3>
        <button id="preset-menu-button" class="text-gray-500 hover:text-gray-700">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"></path>
          </svg>
        </button>
      </div>
      
      <div class="space-y-3">
        <select id="preset-select" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
          <option value="">Custom Settings</option>
        </select>
        
        <div class="flex gap-2">
          <button id="save-preset-btn" class="flex-1 px-3 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors text-sm">
            Save as Preset
          </button>
          <button id="delete-preset-btn" class="px-3 py-2 border border-red-500 text-red-500 rounded-md hover:bg-red-50 transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed" disabled>
            Delete
          </button>
        </div>
      </div>
      
      <!-- Preset menu dropdown -->
      <div id="preset-menu" class="hidden absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg z-10">
        <div class="py-1">
          <button id="import-presets-btn" class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
            Import Presets
          </button>
          <button id="export-all-btn" class="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
            Export All Presets
          </button>
        </div>
      </div>
      
      <!-- Hidden file input for import -->
      <input type="file" id="import-file-input" accept=".json" class="hidden">
    `

    this.attachEventListeners(container)
    return container
  }

  /**
   * Attach event listeners to the component
   */
  attachEventListeners(container) {
    const presetSelect = container.querySelector('#preset-select')
    const saveButton = container.querySelector('#save-preset-btn')
    const deleteButton = container.querySelector('#delete-preset-btn')
    const menuButton = container.querySelector('#preset-menu-button')
    const presetMenu = container.querySelector('#preset-menu')
    const importButton = container.querySelector('#import-presets-btn')
    const exportButton = container.querySelector('#export-all-btn')
    const fileInput = container.querySelector('#import-file-input')

    // Preset selection
    presetSelect.addEventListener('change', (e) => {
      const presetId = e.target.value
      if (presetId) {
        const preset = this.presets.find((p) => p.id === presetId)
        if (preset) {
          this.selectedPreset = preset
          deleteButton.disabled = preset.is_builtin
          if (this.onPresetChange) {
            this.onPresetChange(preset)
          }
        }
      } else {
        this.selectedPreset = null
        deleteButton.disabled = true
        if (this.onPresetChange) {
          this.onPresetChange(null)
        }
      }
    })

    // Save as preset
    saveButton.addEventListener('click', () => this.handleSaveAsPreset())

    // Delete preset
    deleteButton.addEventListener('click', () => this.handleDeletePreset())

    // Menu toggle
    menuButton.addEventListener('click', (e) => {
      e.stopPropagation()
      presetMenu.classList.toggle('hidden')
    })

    // Close menu when clicking outside
    document.addEventListener('click', () => {
      presetMenu.classList.add('hidden')
    })

    // Import presets
    importButton.addEventListener('click', () => {
      fileInput.click()
      presetMenu.classList.add('hidden')
    })

    fileInput.addEventListener('change', (e) => this.handleImport(e))

    // Export all presets
    exportButton.addEventListener('click', () => {
      this.handleExportAll()
      presetMenu.classList.add('hidden')
    })
  }

  /**
   * Load presets from the API
   */
  async loadPresets() {
    try {
      this.presets = await presetApi.getPresets()
      this.updatePresetList()
    } catch (error) {
      showNotification('Failed to load presets', 'error')
      console.error('Failed to load presets:', error)
    }
  }

  /**
   * Update the preset dropdown list
   */
  updatePresetList() {
    const select = this.element.querySelector('#preset-select')
    const currentValue = select.value

    // Clear existing options except the first one
    select.innerHTML = '<option value="">Custom Settings</option>'

    // Group presets by built-in vs user-created
    const builtInPresets = this.presets.filter((p) => p.is_builtin)
    const userPresets = this.presets.filter((p) => !p.is_builtin)

    // Add built-in presets
    if (builtInPresets.length > 0) {
      const builtInGroup = document.createElement('optgroup')
      builtInGroup.label = 'Built-in Presets'
      builtInPresets.forEach((preset) => {
        const option = document.createElement('option')
        option.value = preset.id
        option.textContent = preset.name
        if (preset.description) {
          option.title = preset.description
        }
        builtInGroup.appendChild(option)
      })
      select.appendChild(builtInGroup)
    }

    // Add user presets
    if (userPresets.length > 0) {
      const userGroup = document.createElement('optgroup')
      userGroup.label = 'My Presets'
      userPresets.forEach((preset) => {
        const option = document.createElement('option')
        option.value = preset.id
        option.textContent = preset.name
        if (preset.description) {
          option.title = preset.description
        }
        userGroup.appendChild(option)
      })
      select.appendChild(userGroup)
    }

    // Restore selection if it still exists
    if (currentValue && this.presets.find((p) => p.id === currentValue)) {
      select.value = currentValue
    }
  }

  /**
   * Handle save as preset
   */
  async handleSaveAsPreset() {
    if (!this.onSaveAsPreset) {
      return
    }

    const currentSettings = this.onSaveAsPreset()
    if (!currentSettings) {
      showNotification('No settings to save', 'error')
      return
    }

    // Prompt for preset name
    const name = prompt('Enter a name for this preset:')
    if (!name || !name.trim()) {
      return
    }

    // Check if name is available
    const isAvailable = await presetApi.isNameAvailable(name.trim())
    if (!isAvailable) {
      showNotification('A preset with this name already exists', 'error')
      return
    }

    // Optional description
    const description = prompt('Enter a description (optional):') || ''

    try {
      const preset = await presetApi.createFromCurrentSettings(
        name.trim(),
        description.trim(),
        currentSettings
      )

      showNotification('Preset saved successfully', 'success')

      // Reload presets and select the new one
      await this.loadPresets()
      const select = this.element.querySelector('#preset-select')
      select.value = preset.id
      select.dispatchEvent(new Event('change'))
    } catch (error) {
      showNotification('Failed to save preset', 'error')
      console.error('Failed to save preset:', error)
    }
  }

  /**
   * Handle delete preset
   */
  async handleDeletePreset() {
    if (!this.selectedPreset || this.selectedPreset.is_builtin) {
      return
    }

    const confirmed = confirm(
      `Are you sure you want to delete the preset "${this.selectedPreset.name}"?`
    )
    if (!confirmed) {
      return
    }

    try {
      await presetApi.deletePreset(this.selectedPreset.id)
      showNotification('Preset deleted successfully', 'success')

      // Reset selection and reload
      const select = this.element.querySelector('#preset-select')
      select.value = ''
      select.dispatchEvent(new Event('change'))
      await this.loadPresets()
    } catch (error) {
      showNotification('Failed to delete preset', 'error')
      console.error('Failed to delete preset:', error)
    }
  }

  /**
   * Handle import presets from file
   */
  async handleImport(event) {
    const file = event.target.files[0]
    if (!file) {
      return
    }

    // Validate file type
    if (!file.name.endsWith('.json') && file.type !== 'application/json') {
      showNotification('Please select a valid JSON preset file', 'error')
      event.target.value = ''
      return
    }

    try {
      const text = await file.text()
      const data = JSON.parse(text)

      // Validate the data structure
      if (!Array.isArray(data.presets)) {
        throw new Error('Invalid preset file format')
      }

      const result = await presetApi.importPresets(data.presets)

      showNotification(
        `Imported ${result.imported} presets successfully` +
          (result.skipped > 0 ? ` (${result.skipped} skipped)` : ''),
        'success'
      )

      // Reload presets
      await this.loadPresets()
    } catch (error) {
      showNotification('Failed to import presets', 'error')
      console.error('Failed to import presets:', error)
    }

    // Reset file input
    event.target.value = ''
  }

  /**
   * Handle export all presets
   */
  async handleExportAll() {
    try {
      const blob = await presetApi.exportAllPresets()

      // Create download link
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `image-converter-presets-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      showNotification('Presets exported successfully', 'success')
    } catch (error) {
      showNotification('Failed to export presets', 'error')
      console.error('Failed to export presets:', error)
    }
  }

  /**
   * Get the currently selected preset
   */
  getSelectedPreset() {
    return this.selectedPreset
  }

  /**
   * Clear the current selection
   */
  clearSelection() {
    const select = this.element.querySelector('#preset-select')
    select.value = ''
    select.dispatchEvent(new Event('change'))
  }
}
