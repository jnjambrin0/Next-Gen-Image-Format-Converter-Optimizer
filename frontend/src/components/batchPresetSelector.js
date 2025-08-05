/**
 * Batch preset selector component for conversion settings
 */

export class BatchPresetSelector {
  constructor(container) {
    this.container = container
    this.settings = {
      outputFormat: 'webp',
      quality: 85,
      optimizationMode: null,
      presetId: null,
      preserveMetadata: false,
      applyToAll: true
    }
    this.onChangeCallback = null
    
    this.outputFormats = [
      { value: 'webp', label: 'WebP', description: 'Best for web, excellent compression' },
      { value: 'avif', label: 'AVIF', description: 'Next-gen format, smaller files' },
      { value: 'jpeg', label: 'JPEG', description: 'Universal compatibility' },
      { value: 'png', label: 'PNG', description: 'Lossless, supports transparency' },
      { value: 'jxl', label: 'JPEG XL', description: 'Advanced features, good compression' },
      { value: 'heif', label: 'HEIF', description: 'Apple format, efficient storage' },
      { value: 'jpeg_optimized', label: 'JPEG (Optimized)', description: 'Enhanced JPEG compression' },
      { value: 'png_optimized', label: 'PNG (Optimized)', description: 'Smaller PNG files' },
      { value: 'webp2', label: 'WebP 2', description: 'Experimental next-gen WebP' },
      { value: 'jpeg2000', label: 'JPEG 2000', description: 'Advanced JPEG variant' }
    ]
    
    this.optimizationModes = [
      { value: null, label: 'None' },
      { value: 'balanced', label: 'Balanced' },
      { value: 'quality', label: 'Quality Priority' },
      { value: 'size', label: 'Size Priority' }
    ]
    
    this.render()
  }

  getSettings() {
    return { ...this.settings }
  }

  setSettings(settings) {
    this.settings = { ...this.settings, ...settings }
    this.render()
    if (this.onChangeCallback) {
      this.onChangeCallback(this.getSettings())
    }
  }

  onChange(callback) {
    this.onChangeCallback = callback
  }

  updateSetting(key, value) {
    this.settings[key] = value
    if (this.onChangeCallback) {
      this.onChangeCallback(this.getSettings())
    }
  }

  render() {
    this.container.innerHTML = ''
    
    const wrapper = document.createElement('div')
    wrapper.className = 'space-y-6'
    
    // Title
    const title = document.createElement('h3')
    title.className = 'text-lg font-semibold text-gray-900'
    title.textContent = 'Batch Conversion Settings'
    wrapper.appendChild(title)
    
    // Apply to all checkbox
    const applyToAllSection = this.createApplyToAllSection()
    wrapper.appendChild(applyToAllSection)
    
    // Settings container
    const settingsContainer = document.createElement('div')
    settingsContainer.className = 'space-y-4'
    
    // Output format selector
    const formatSection = this.createFormatSection()
    settingsContainer.appendChild(formatSection)
    
    // Quality slider
    const qualitySection = this.createQualitySection()
    settingsContainer.appendChild(qualitySection)
    
    // Optimization mode
    const optimizationSection = this.createOptimizationSection()
    settingsContainer.appendChild(optimizationSection)
    
    // Metadata preservation
    const metadataSection = this.createMetadataSection()
    settingsContainer.appendChild(metadataSection)
    
    wrapper.appendChild(settingsContainer)
    
    // Summary
    const summary = this.createSummary()
    wrapper.appendChild(summary)
    
    this.container.appendChild(wrapper)
  }

  createApplyToAllSection() {
    const section = document.createElement('div')
    section.className = 'bg-blue-50 border border-blue-200 rounded-lg p-4'
    
    const label = document.createElement('label')
    label.className = 'flex items-center space-x-3 cursor-pointer'
    
    const checkbox = document.createElement('input')
    checkbox.type = 'checkbox'
    checkbox.checked = this.settings.applyToAll
    checkbox.className = 'w-4 h-4 text-blue-600 rounded focus:ring-blue-500'
    checkbox.onchange = (e) => this.updateSetting('applyToAll', e.target.checked)
    
    const text = document.createElement('span')
    text.className = 'text-sm font-medium text-gray-900'
    text.textContent = 'Apply these settings to all files in the batch'
    
    label.appendChild(checkbox)
    label.appendChild(text)
    section.appendChild(label)
    
    const note = document.createElement('p')
    note.className = 'text-xs text-gray-600 mt-2 ml-7'
    note.textContent = 'When unchecked, you can set individual settings for each file'
    section.appendChild(note)
    
    return section
  }

  createFormatSection() {
    const section = document.createElement('div')
    
    const label = document.createElement('label')
    label.className = 'block text-sm font-medium text-gray-700 mb-2'
    label.textContent = 'Output Format'
    label.setAttribute('for', 'batch-format-select')
    
    const select = document.createElement('select')
    select.id = 'batch-format-select'
    select.className = 'w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500'
    select.value = this.settings.outputFormat
    select.onchange = (e) => this.updateSetting('outputFormat', e.target.value)
    
    this.outputFormats.forEach(format => {
      const option = document.createElement('option')
      option.value = format.value
      option.textContent = `${format.label} - ${format.description}`
      select.appendChild(option)
    })
    
    section.appendChild(label)
    section.appendChild(select)
    
    return section
  }

  createQualitySection() {
    const section = document.createElement('div')
    
    const labelContainer = document.createElement('div')
    labelContainer.className = 'flex justify-between items-center mb-2'
    
    const label = document.createElement('label')
    label.className = 'text-sm font-medium text-gray-700'
    label.textContent = 'Quality'
    label.setAttribute('for', 'batch-quality-slider')
    
    const value = document.createElement('span')
    value.className = 'text-sm text-gray-600'
    value.textContent = `${this.settings.quality}%`
    value.id = 'batch-quality-value'
    
    labelContainer.appendChild(label)
    labelContainer.appendChild(value)
    
    const sliderContainer = document.createElement('div')
    sliderContainer.className = 'relative'
    
    const slider = document.createElement('input')
    slider.type = 'range'
    slider.id = 'batch-quality-slider'
    slider.min = '1'
    slider.max = '100'
    slider.value = this.settings.quality
    slider.className = 'w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer'
    slider.oninput = (e) => {
      const quality = parseInt(e.target.value)
      this.updateSetting('quality', quality)
      value.textContent = `${quality}%`
    }
    
    // Quality markers
    const markers = document.createElement('div')
    markers.className = 'flex justify-between text-xs text-gray-500 mt-1'
    
    const lowMarker = document.createElement('span')
    lowMarker.textContent = 'Low'
    
    const mediumMarker = document.createElement('span')
    mediumMarker.textContent = 'Medium'
    
    const highMarker = document.createElement('span')
    highMarker.textContent = 'High'
    
    markers.appendChild(lowMarker)
    markers.appendChild(mediumMarker)
    markers.appendChild(highMarker)
    
    section.appendChild(labelContainer)
    sliderContainer.appendChild(slider)
    section.appendChild(sliderContainer)
    section.appendChild(markers)
    
    return section
  }

  createOptimizationSection() {
    const section = document.createElement('div')
    
    const label = document.createElement('label')
    label.className = 'block text-sm font-medium text-gray-700 mb-2'
    label.textContent = 'Optimization Mode'
    
    const radioGroup = document.createElement('div')
    radioGroup.className = 'space-y-2'
    radioGroup.setAttribute('role', 'radiogroup')
    
    this.optimizationModes.forEach(mode => {
      const radioLabel = document.createElement('label')
      radioLabel.className = 'flex items-center space-x-3 cursor-pointer'
      
      const radio = document.createElement('input')
      radio.type = 'radio'
      radio.name = 'batch-optimization-mode'
      radio.value = mode.value || ''
      radio.checked = this.settings.optimizationMode === mode.value
      radio.className = 'w-4 h-4 text-blue-600 focus:ring-blue-500'
      radio.onchange = () => this.updateSetting('optimizationMode', mode.value)
      
      const text = document.createElement('span')
      text.className = 'text-sm text-gray-700'
      text.textContent = mode.label
      
      radioLabel.appendChild(radio)
      radioLabel.appendChild(text)
      radioGroup.appendChild(radioLabel)
    })
    
    section.appendChild(label)
    section.appendChild(radioGroup)
    
    return section
  }

  createMetadataSection() {
    const section = document.createElement('div')
    section.className = 'border-t pt-4'
    
    const label = document.createElement('label')
    label.className = 'flex items-center space-x-3 cursor-pointer'
    
    const checkbox = document.createElement('input')
    checkbox.type = 'checkbox'
    checkbox.checked = this.settings.preserveMetadata
    checkbox.className = 'w-4 h-4 text-blue-600 rounded focus:ring-blue-500'
    checkbox.onchange = (e) => this.updateSetting('preserveMetadata', e.target.checked)
    
    const text = document.createElement('span')
    text.className = 'text-sm text-gray-700'
    text.textContent = 'Preserve metadata (EXIF, etc.)'
    
    label.appendChild(checkbox)
    label.appendChild(text)
    section.appendChild(label)
    
    const warning = document.createElement('p')
    warning.className = 'text-xs text-yellow-600 mt-2 ml-7'
    warning.textContent = 'Warning: Preserving metadata may include location and personal information'
    section.appendChild(warning)
    
    return section
  }

  createSummary() {
    const summary = document.createElement('div')
    summary.className = 'bg-gray-50 rounded-lg p-4 mt-6'
    
    const title = document.createElement('h4')
    title.className = 'text-sm font-medium text-gray-900 mb-2'
    title.textContent = 'Settings Summary'
    
    const list = document.createElement('ul')
    list.className = 'text-sm text-gray-600 space-y-1'
    
    const formatItem = document.createElement('li')
    const selectedFormat = this.outputFormats.find(f => f.value === this.settings.outputFormat)
    formatItem.textContent = `• Format: ${selectedFormat?.label || this.settings.outputFormat}`
    
    const qualityItem = document.createElement('li')
    qualityItem.textContent = `• Quality: ${this.settings.quality}%`
    
    const optimizationItem = document.createElement('li')
    const selectedMode = this.optimizationModes.find(m => m.value === this.settings.optimizationMode)
    optimizationItem.textContent = `• Optimization: ${selectedMode?.label || 'None'}`
    
    const metadataItem = document.createElement('li')
    metadataItem.textContent = `• Metadata: ${this.settings.preserveMetadata ? 'Preserve' : 'Remove'}`
    
    const applyItem = document.createElement('li')
    applyItem.className = 'font-medium text-gray-900'
    applyItem.textContent = `• ${this.settings.applyToAll ? 'Apply to all files' : 'Individual settings per file'}`
    
    list.appendChild(formatItem)
    list.appendChild(qualityItem)
    list.appendChild(optimizationItem)
    list.appendChild(metadataItem)
    list.appendChild(applyItem)
    
    summary.appendChild(title)
    summary.appendChild(list)
    
    return summary
  }

  reset() {
    this.settings = {
      outputFormat: 'webp',
      quality: 85,
      optimizationMode: null,
      presetId: null,
      preserveMetadata: false,
      applyToAll: true
    }
    this.render()
  }
}