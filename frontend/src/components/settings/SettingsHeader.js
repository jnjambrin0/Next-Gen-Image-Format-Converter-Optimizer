/**
 * Settings header component for unified conversion settings
 * Displays the appropriate title and description based on mode
 */

export class SettingsHeader {
  constructor(mode = 'single') {
    this.mode = mode
    this.element = null
  }

  /**
   * Initialize the settings header
   * @returns {HTMLElement} The header element
   */
  init() {
    this.element = this.createElement()
    return this.element
  }

  /**
   * Create the header element
   * @returns {HTMLElement} The header element
   */
  createElement() {
    const header = document.createElement('div')
    header.className = 'settings-header'

    const title = document.createElement('h3')
    title.className = 'text-lg font-semibold text-gray-900'
    title.textContent = this.getTitle()

    header.appendChild(title)

    // Add description for batch mode
    if (this.mode === 'batch') {
      const description = document.createElement('p')
      description.className = 'text-sm text-gray-600 mt-1'
      description.textContent = 'Settings will apply to all selected files'
      header.appendChild(description)
    }

    return header
  }

  /**
   * Get the appropriate title based on mode
   * @returns {string} The title text
   */
  getTitle() {
    return this.mode === 'batch' ? 'Batch Conversion Settings' : 'Conversion Settings'
  }

  /**
   * Update the mode and re-render if needed
   * @param {string} newMode - The new mode ('single' or 'batch')
   */
  updateMode(newMode) {
    if (this.mode === newMode) {
      return
    }

    this.mode = newMode

    if (this.element && this.element.parentElement) {
      const newElement = this.createElement()
      this.element.parentElement.replaceChild(newElement, this.element)
      this.element = newElement
    }
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
