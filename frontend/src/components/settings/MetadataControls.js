/**
 * Metadata controls component for managing image metadata settings
 * Handles preservation and removal of EXIF, GPS, and other metadata
 */

export class MetadataControls {
  constructor() {
    this.element = null
    this.onChange = null
    this.preserveMetadata = false
  }

  /**
   * Initialize the metadata controls
   * @param {Function} onChange - Callback when settings change
   * @param {boolean} initialValue - Initial preserve metadata value
   * @returns {HTMLElement} The metadata controls element
   */
  init(onChange, initialValue = false) {
    this.onChange = onChange
    this.preserveMetadata = initialValue
    this.element = this.createElement()
    this.attachEventListeners()
    return this.element
  }

  /**
   * Create the metadata controls element
   * @returns {HTMLElement} The metadata controls element
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'setting-group'

    const label = document.createElement('label')
    label.className = 'setting-checkbox'

    const checkbox = document.createElement('input')
    checkbox.type = 'checkbox'
    checkbox.id = 'preserve-metadata'
    checkbox.checked = this.preserveMetadata
    checkbox.className = 'mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded'

    const text = document.createElement('span')
    text.className = 'text-sm text-gray-700'
    text.textContent = 'Preserve metadata (except GPS)'

    label.appendChild(checkbox)
    label.appendChild(text)
    container.appendChild(label)

    // Add additional info
    const info = document.createElement('p')
    info.className = 'text-xs text-gray-500 mt-1 ml-6'
    info.textContent = 'Keeps EXIF data like camera settings, but removes location for privacy'
    container.appendChild(info)

    return container
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    const checkbox = this.element.querySelector('#preserve-metadata')
    if (checkbox) {
      checkbox.addEventListener('change', (e) => {
        this.handleChange(e.target.checked)
      })
    }
  }

  /**
   * Handle metadata preservation change
   * @param {boolean} preserve - Whether to preserve metadata
   */
  handleChange(preserve) {
    this.preserveMetadata = preserve

    if (this.onChange) {
      this.onChange({
        preserveMetadata: preserve,
      })
    }
  }

  /**
   * Set the preserve metadata value programmatically
   * @param {boolean} preserve - Whether to preserve metadata
   */
  setValue(preserve) {
    const checkbox = this.element?.querySelector('#preserve-metadata')
    if (checkbox) {
      checkbox.checked = preserve
      this.preserveMetadata = preserve
    }
  }

  /**
   * Get the current preserve metadata value
   * @returns {boolean} Whether metadata should be preserved
   */
  getValue() {
    return this.preserveMetadata
  }

  /**
   * Clean up the component
   */
  destroy() {
    const checkbox = this.element?.querySelector('#preserve-metadata')
    if (checkbox) {
      checkbox.removeEventListener('change', this.handleChange)
    }

    this.element = null
    this.onChange = null
  }
}
