/**
 * Format selector component for choosing output image format
 * Provides format selection with descriptions and tooltips
 */

import { Tooltip } from '../tooltip.js'

export class FormatSelector {
  constructor() {
    this.element = null
    this.onChange = null
    this.currentFormat = 'webp'
    this.tooltip = null

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
  }

  /**
   * Initialize the format selector
   * @param {Function} onChange - Callback when format changes
   * @param {string} initialFormat - Initial format selection
   * @returns {HTMLElement} The format selector element
   */
  init(onChange, initialFormat = 'webp') {
    this.onChange = onChange
    this.currentFormat = initialFormat
    this.element = this.createElement()
    this.attachEventListeners()
    this.initializeTooltip()
    return this.element
  }

  /**
   * Create the format selector element
   * @returns {HTMLElement} The format selector element
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'setting-group'

    // Label with help icon
    const labelContainer = document.createElement('div')
    labelContainer.className = 'flex items-center'

    const label = document.createElement('label')
    label.htmlFor = 'output-format'
    label.className = 'setting-label'
    label.textContent = 'Output Format'

    const helpIcon = document.createElement('span')
    helpIcon.id = 'format-help'
    helpIcon.className = 'ml-2'

    labelContainer.appendChild(label)
    labelContainer.appendChild(helpIcon)

    // Select dropdown
    const select = document.createElement('select')
    select.id = 'output-format'
    select.className = 'setting-control'

    this.outputFormats.forEach((format) => {
      const option = document.createElement('option')
      option.value = format.value
      option.textContent = format.label
      if (format.value === this.currentFormat) {
        option.selected = true
      }
      select.appendChild(option)
    })

    // Description
    const description = document.createElement('p')
    description.className = 'setting-description'
    description.textContent = this.getFormatDescription(this.currentFormat)

    container.appendChild(labelContainer)
    container.appendChild(select)
    container.appendChild(description)

    return container
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    const select = this.element.querySelector('#output-format')
    if (select) {
      select.addEventListener('change', (e) => {
        this.handleFormatChange(e.target.value)
      })
    }
  }

  /**
   * Initialize tooltip
   */
  initializeTooltip() {
    const helpIcon = this.element.querySelector('#format-help')
    if (helpIcon) {
      this.tooltip = new Tooltip(helpIcon, {
        content:
          'Choose the output format based on your needs. WebP offers the best balance of quality and file size for web use.',
        position: 'top',
      })
    }
  }

  /**
   * Handle format change
   * @param {string} newFormat - The new format value
   */
  handleFormatChange(newFormat) {
    this.currentFormat = newFormat
    this.updateDescription(newFormat)

    if (this.onChange) {
      this.onChange({
        outputFormat: newFormat,
        description: this.getFormatDescription(newFormat),
      })
    }
  }

  /**
   * Update the format description
   * @param {string} format - The format to get description for
   */
  updateDescription(format) {
    const descriptionElement = this.element.querySelector('.setting-description')
    if (descriptionElement) {
      descriptionElement.textContent = this.getFormatDescription(format)
    }
  }

  /**
   * Get format description
   * @param {string} format - The format to get description for
   * @returns {string} The format description
   */
  getFormatDescription(format) {
    const formatInfo = this.outputFormats.find((f) => f.value === format)
    return formatInfo ? formatInfo.description : ''
  }

  /**
   * Set the current format programmatically
   * @param {string} format - The format to set
   */
  setValue(format) {
    const select = this.element?.querySelector('#output-format')
    if (select && this.outputFormats.find((f) => f.value === format)) {
      select.value = format
      this.handleFormatChange(format)
    }
  }

  /**
   * Get the current format
   * @returns {string} The current format
   */
  getValue() {
    return this.currentFormat
  }

  /**
   * Clean up the component
   */
  destroy() {
    if (this.tooltip) {
      this.tooltip.destroy?.()
    }

    const select = this.element?.querySelector('#output-format')
    if (select) {
      select.removeEventListener('change', this.handleFormatChange)
    }

    this.element = null
    this.onChange = null
  }
}
