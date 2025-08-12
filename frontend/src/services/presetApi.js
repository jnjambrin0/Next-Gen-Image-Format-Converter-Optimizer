/**
 * Preset API service for managing conversion presets
 */

import { apiClient } from './api.js'

class PresetApi {
  /**
   * Get all presets (built-in and user-created)
   * @returns {Promise<Array>} List of presets
   */
  async getPresets() {
    try {
      const response = await apiClient.get('/presets')
      const data = await response.json()
      return data.presets || []
    } catch (error) {
      console.error('Failed to fetch presets:', error)
      throw error
    }
  }

  /**
   * Get a specific preset by ID
   * @param {string} presetId - UUID of the preset
   * @returns {Promise<Object>} Preset details
   */
  async getPreset(presetId) {
    try {
      const response = await apiClient.get(`/presets/${presetId}`)
      return await response.json()
    } catch (error) {
      console.error('Failed to fetch preset:', error)
      throw error
    }
  }

  /**
   * Create a new preset
   * @param {Object} presetData - Preset data
   * @param {string} presetData.name - Preset name
   * @param {string} presetData.description - Preset description
   * @param {Object} presetData.settings - Preset settings
   * @returns {Promise<Object>} Created preset
   */
  async createPreset(presetData) {
    try {
      const response = await apiClient.post('/presets', presetData)
      return await response.json()
    } catch (error) {
      console.error('Failed to create preset:', error)
      throw error
    }
  }

  /**
   * Update an existing preset
   * @param {string} presetId - UUID of the preset
   * @param {Object} updateData - Updated preset data
   * @returns {Promise<Object>} Updated preset
   */
  async updatePreset(presetId, updateData) {
    try {
      const response = await apiClient.put(`/presets/${presetId}`, updateData)
      return await response.json()
    } catch (error) {
      console.error('Failed to update preset:', error)
      throw error
    }
  }

  /**
   * Delete a preset
   * @param {string} presetId - UUID of the preset
   * @returns {Promise<void>}
   */
  async deletePreset(presetId) {
    try {
      await apiClient.delete(`/presets/${presetId}`)
    } catch (error) {
      console.error('Failed to delete preset:', error)
      throw error
    }
  }

  /**
   * Import presets from JSON
   * @param {Array} presets - Array of preset objects to import
   * @returns {Promise<Object>} Import result
   */
  async importPresets(presets) {
    try {
      const response = await apiClient.post('/presets/import', { presets })
      return await response.json()
    } catch (error) {
      console.error('Failed to import presets:', error)
      throw error
    }
  }

  /**
   * Export a single preset
   * @param {string} presetId - UUID of the preset to export
   * @returns {Promise<Object>} Preset data for export
   */
  async exportPreset(presetId) {
    try {
      const response = await apiClient.get(`/presets/${presetId}/export`)
      return await response.json()
    } catch (error) {
      console.error('Failed to export preset:', error)
      throw error
    }
  }

  /**
   * Export all user presets
   * @returns {Promise<Blob>} JSON file containing all user presets
   */
  async exportAllPresets() {
    try {
      const response = await apiClient.get('/presets/export/all')
      return await response.blob()
    } catch (error) {
      console.error('Failed to export all presets:', error)
      throw error
    }
  }

  /**
   * Create preset from current conversion settings
   * @param {string} name - Preset name
   * @param {string} description - Preset description
   * @param {Object} settings - Current conversion settings
   * @returns {Promise<Object>} Created preset
   */
  createFromCurrentSettings(name, description, settings) {
    // Map frontend optimization mode values to backend expected values
    let optimizationMode = 'balanced'
    if (settings.optimizationMode === 'size') {
      optimizationMode = 'file_size'
    } else if (settings.optimizationMode === 'quality') {
      optimizationMode = 'quality'
    } else if (settings.optimizationMode === 'balanced') {
      optimizationMode = 'balanced'
    }

    const presetData = {
      name,
      description,
      settings: {
        output_format: settings.outputFormat,
        quality: settings.quality,
        optimization_mode: optimizationMode,
        preserve_metadata: settings.preserveMetadata || false,
        resize_options: settings.resizeOptions || null,
        advanced_settings: settings.advancedSettings || null,
      },
    }

    return this.createPreset(presetData)
  }

  /**
   * Apply preset settings to current conversion settings
   * @param {Object} preset - Preset object
   * @returns {Object} Conversion settings object
   */
  applyPresetToSettings(preset) {
    if (!preset || !preset.settings) {
      throw new Error('Invalid preset data')
    }

    const settings = preset.settings

    // Map backend optimization mode values to frontend expected values
    let optimizationMode = null
    if (settings.optimization_mode === 'file_size') {
      optimizationMode = 'size'
    } else if (settings.optimization_mode === 'quality') {
      optimizationMode = 'quality'
    } else if (settings.optimization_mode === 'balanced') {
      optimizationMode = 'balanced'
    }

    return {
      outputFormat: settings.output_format,
      quality: settings.quality,
      optimizationMode: optimizationMode,
      preserveMetadata: settings.preserve_metadata || false,
      resizeOptions: settings.resize_options || null,
      advancedSettings: settings.advanced_settings || null,
      presetId: preset.id,
      presetName: preset.name,
    }
  }

  /**
   * Validate preset name for uniqueness
   * @param {string} name - Preset name to validate
   * @returns {Promise<boolean>} True if name is available
   */
  async isNameAvailable(name) {
    try {
      const presets = await this.getPresets()
      return !presets.some((p) => p.name.toLowerCase() === name.toLowerCase())
    } catch (error) {
      console.error('Failed to validate preset name:', error)
      return false
    }
  }
}

// Export singleton instance
export const presetApi = new PresetApi()
