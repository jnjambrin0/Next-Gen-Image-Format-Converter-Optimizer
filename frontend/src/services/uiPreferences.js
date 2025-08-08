/**
 * UI preferences service for managing localStorage state
 * Handles saving and loading UI preferences with error handling
 */

export class UIPreferences {
  constructor() {
    this.storageKey = 'imageConverter_uiPreferences'
    this.version = '1.0'
    this.defaults = {
      version: this.version,
      advancedMode: false,
      groupStates: {
        quality: true,
        optimization: true,
        metadata: true,
      },
      visibleSections: {
        quality: true,
        optimization: true,
        metadata: true,
      },
      lastUsedSettings: {
        outputFormat: 'webp',
        quality: 85,
        preserveMetadata: false,
      },
      customization: {
        showTooltips: true,
        animationsEnabled: true,
        compactMode: false,
      },
    }
  }

  /**
   * Initialize preferences (load from storage or use defaults)
   */
  init() {
    // Check if localStorage is available
    if (!this.isStorageAvailable()) {
      console.warn('localStorage is not available. UI preferences will not persist.')
      return this.defaults
    }

    return this.load()
  }

  /**
   * Check if localStorage is available
   */
  isStorageAvailable() {
    try {
      const test = '__localStorage_test__'
      localStorage.setItem(test, test)
      localStorage.removeItem(test)
      return true
    } catch (e) {
      return false
    }
  }

  /**
   * Load preferences from localStorage
   */
  load() {
    if (!this.isStorageAvailable()) {
      return this.defaults
    }

    try {
      const stored = localStorage.getItem(this.storageKey)

      if (!stored) {
        return this.defaults
      }

      const preferences = JSON.parse(stored)

      // Check version and migrate if needed
      if (preferences.version !== this.version) {
        return this.migrate(preferences)
      }

      // Merge with defaults to ensure all properties exist
      return this.mergeWithDefaults(preferences)
    } catch (error) {
      console.error('Failed to load UI preferences:', error)
      return this.defaults
    }
  }

  /**
   * Save preferences to localStorage
   */
  save(preferences) {
    if (!this.isStorageAvailable()) {
      return false
    }

    try {
      // Ensure version is set
      preferences.version = this.version

      const json = JSON.stringify(preferences)
      localStorage.setItem(this.storageKey, json)

      return true
    } catch (error) {
      // Handle quota exceeded error
      if (error.name === 'QuotaExceededError') {
        console.error('localStorage quota exceeded. Cannot save preferences.')
        this.handleQuotaExceeded()
      } else {
        console.error('Failed to save UI preferences:', error)
      }
      return false
    }
  }

  /**
   * Update a specific preference
   */
  update(path, value) {
    const preferences = this.load()

    // Navigate to nested property
    const parts = path.split('.')
    let current = preferences

    for (let i = 0; i < parts.length - 1; i++) {
      if (!current[parts[i]]) {
        current[parts[i]] = {}
      }
      current = current[parts[i]]
    }

    current[parts[parts.length - 1]] = value

    return this.save(preferences)
  }

  /**
   * Get a specific preference
   */
  get(path, defaultValue = null) {
    const preferences = this.load()

    // Navigate to nested property
    const parts = path.split('.')
    let current = preferences

    for (const part of parts) {
      if (current && typeof current === 'object' && part in current) {
        current = current[part]
      } else {
        return defaultValue
      }
    }

    return current
  }

  /**
   * Reset preferences to defaults
   */
  reset() {
    if (!this.isStorageAvailable()) {
      return false
    }

    try {
      localStorage.removeItem(this.storageKey)
      return true
    } catch (error) {
      console.error('Failed to reset UI preferences:', error)
      return false
    }
  }

  /**
   * Merge preferences with defaults
   */
  mergeWithDefaults(preferences) {
    // Deep merge function
    const merge = (target, source) => {
      for (const key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
          if (
            typeof source[key] === 'object' &&
            source[key] !== null &&
            !Array.isArray(source[key])
          ) {
            if (!target[key]) {
              target[key] = {}
            }
            merge(target[key], source[key])
          } else if (!(key in target)) {
            target[key] = source[key]
          }
        }
      }
      return target
    }

    return merge(JSON.parse(JSON.stringify(preferences)), this.defaults)
  }

  /**
   * Migrate preferences from old version
   */
  migrate(oldPreferences) {
    // Migration from older version - silently handle
    // console.log('Migrating UI preferences from version', oldPreferences.version || 'unknown')

    // For now, just merge with defaults
    // Add specific migration logic here as needed
    return this.mergeWithDefaults(oldPreferences)
  }

  /**
   * Handle quota exceeded error
   */
  handleQuotaExceeded() {
    // Try to clear old data
    try {
      // Clear other app data if any
      const keys = Object.keys(localStorage)
      const appKeys = keys.filter((key) => key.startsWith('imageConverter_'))

      // Remove old entries (except current preferences)
      appKeys.forEach((key) => {
        if (key !== this.storageKey) {
          localStorage.removeItem(key)
        }
      })
    } catch (error) {
      console.error('Failed to clear old data:', error)
    }
  }

  /**
   * Export preferences as JSON
   */
  export() {
    const preferences = this.load()
    return JSON.stringify(preferences, null, 2)
  }

  /**
   * Import preferences from JSON
   */
  import(json) {
    try {
      const preferences = JSON.parse(json)

      // Validate structure
      if (typeof preferences !== 'object' || preferences === null) {
        throw new Error('Invalid preferences format')
      }

      // Merge with defaults and save
      const merged = this.mergeWithDefaults(preferences)
      return this.save(merged)
    } catch (error) {
      console.error('Failed to import UI preferences:', error)
      return false
    }
  }

  /**
   * Get storage usage info
   */
  getStorageInfo() {
    if (!this.isStorageAvailable()) {
      return { available: false }
    }

    try {
      const stored = localStorage.getItem(this.storageKey)
      const size = stored ? new Blob([stored]).size : 0

      return {
        available: true,
        size: size,
        sizeFormatted: this.formatBytes(size),
        itemCount: Object.keys(localStorage).length,
      }
    } catch (error) {
      return { available: true, error: error.message }
    }
  }

  /**
   * Format bytes to human readable
   */
  formatBytes(bytes) {
    if (bytes === 0) {
      return '0 Bytes'
    }

    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  /**
   * Create a preferences manager UI component
   */
  static createManagerUI() {
    const container = document.createElement('div')
    container.className = 'space-y-4'

    const preferences = new UIPreferences()
    const storageInfo = preferences.getStorageInfo()

    container.innerHTML = `
      <div class="bg-gray-50 p-4 rounded-lg">
        <h3 class="text-sm font-semibold text-gray-700 mb-2">UI Preferences Storage</h3>
        ${
          storageInfo.available
            ? `
          <p class="text-xs text-gray-600">Storage used: ${storageInfo.sizeFormatted || '0 Bytes'}</p>
          <p class="text-xs text-gray-600">Total items: ${storageInfo.itemCount || 0}</p>
        `
            : `
          <p class="text-xs text-red-600">localStorage is not available</p>
        `
        }
      </div>
      
      <div class="flex space-x-2">
        <button id="export-prefs" class="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700">
          Export Preferences
        </button>
        <button id="import-prefs" class="px-3 py-1.5 text-sm bg-gray-600 text-white rounded hover:bg-gray-700">
          Import Preferences
        </button>
        <button id="reset-prefs" class="px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700">
          Reset to Defaults
        </button>
      </div>
      
      <input type="file" id="import-file" accept=".json" style="display: none;">
    `

    // Attach event handlers
    const exportBtn = container.querySelector('#export-prefs')
    const importBtn = container.querySelector('#import-prefs')
    const resetBtn = container.querySelector('#reset-prefs')
    const importFile = container.querySelector('#import-file')

    const exportHandler = () => {
      const data = preferences.export()
      const blob = new Blob([data], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'image-converter-ui-preferences.json'
      a.click()
      URL.revokeObjectURL(url)
    }

    const importHandler = () => {
      importFile.click()
    }

    const fileChangeHandler = (e) => {
      const file = e.target.files[0]
      if (file) {
        const reader = new FileReader()
        reader.onload = (e) => {
          if (preferences.import(e.target.result)) {
            alert('Preferences imported successfully. The page will reload.')
            window.location.reload()
          } else {
            alert('Failed to import preferences. Please check the file format.')
          }
        }
        reader.readAsText(file)
      }
    }

    const resetHandler = () => {
      if (confirm('Are you sure you want to reset all UI preferences to defaults?')) {
        if (preferences.reset()) {
          alert('Preferences reset successfully. The page will reload.')
          window.location.reload()
        }
      }
    }

    exportBtn.addEventListener('click', exportHandler)
    importBtn.addEventListener('click', importHandler)
    importFile.addEventListener('change', fileChangeHandler)
    resetBtn.addEventListener('click', resetHandler)

    // Store cleanup function
    container._cleanup = () => {
      exportBtn.removeEventListener('click', exportHandler)
      importBtn.removeEventListener('click', importHandler)
      importFile.removeEventListener('change', fileChangeHandler)
      resetBtn.removeEventListener('click', resetHandler)
    }

    return container
  }
}

// Export singleton instance
export const uiPreferences = new UIPreferences()
