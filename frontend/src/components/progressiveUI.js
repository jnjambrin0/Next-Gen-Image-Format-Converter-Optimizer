/**
 * Progressive disclosure UI controller
 * Manages the display of basic vs advanced settings
 */

export class ProgressiveUI {
  constructor() {
    this.isAdvancedMode = false
    this.animationDuration = 300
    this.onModeChange = null
    this.toggleButton = null
    this.advancedContainer = null
    this.basicContainer = null
  }

  /**
   * Initialize the progressive UI system
   * @param {Object} options - Configuration options
   * @param {HTMLElement} options.toggleButton - Button to toggle advanced mode
   * @param {HTMLElement} options.advancedContainer - Container for advanced settings
   * @param {HTMLElement} options.basicContainer - Container for basic settings
   * @param {Function} options.onModeChange - Callback when mode changes
   */
  init(options) {
    this.toggleButton = options.toggleButton
    this.advancedContainer = options.advancedContainer
    this.basicContainer = options.basicContainer
    this.onModeChange = options.onModeChange

    // Set initial state
    this.setupInitialState()

    // Attach event listeners
    this.attachEventListeners()

    return this
  }

  /**
   * Setup initial UI state
   */
  setupInitialState() {
    // Hide advanced container initially
    if (this.advancedContainer) {
      this.advancedContainer.style.display = 'none'
      this.advancedContainer.style.opacity = '0'
      this.advancedContainer.style.transform = 'translateY(-10px)'
    }

    // Update toggle button text
    this.updateToggleButton()
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    if (this.toggleButton) {
      this.boundToggleMode = () => this.toggleMode()
      this.toggleButton.addEventListener('click', this.boundToggleMode)
    }
  }

  /**
   * Toggle between basic and advanced modes
   */
  async toggleMode() {
    this.isAdvancedMode = !this.isAdvancedMode

    if (this.isAdvancedMode) {
      await this.showAdvancedSettings()
    } else {
      await this.hideAdvancedSettings()
    }

    this.updateToggleButton()

    if (this.onModeChange) {
      this.onModeChange(this.isAdvancedMode)
    }
  }

  /**
   * Show advanced settings with animation
   */
  async showAdvancedSettings() {
    if (!this.advancedContainer) {
      return
    }

    // Update animation duration based on user preferences
    this.updateAnimationDuration()

    // Prepare for animation
    this.advancedContainer.style.display = 'block'
    this.advancedContainer.style.height = 'auto'
    const targetHeight = this.advancedContainer.offsetHeight
    this.advancedContainer.style.height = '0px'

    // Force reflow
    this.advancedContainer.offsetHeight

    // Apply transition
    this.advancedContainer.style.transition = `all ${this.animationDuration}ms ease-out`
    this.advancedContainer.style.height = targetHeight + 'px'
    this.advancedContainer.style.opacity = '1'
    this.advancedContainer.style.transform = 'translateY(0)'

    // Wait for animation to complete
    await this.waitForAnimation()

    // Clean up
    this.advancedContainer.style.height = 'auto'
  }

  /**
   * Hide advanced settings with animation
   */
  async hideAdvancedSettings() {
    if (!this.advancedContainer) {
      return
    }

    // Update animation duration based on user preferences
    this.updateAnimationDuration()

    // Set explicit height for animation
    const currentHeight = this.advancedContainer.offsetHeight
    this.advancedContainer.style.height = currentHeight + 'px'

    // Force reflow
    this.advancedContainer.offsetHeight

    // Apply transition
    this.advancedContainer.style.transition = `all ${this.animationDuration}ms ease-out`
    this.advancedContainer.style.height = '0px'
    this.advancedContainer.style.opacity = '0'
    this.advancedContainer.style.transform = 'translateY(-10px)'

    // Wait for animation to complete
    await this.waitForAnimation()

    // Hide completely
    this.advancedContainer.style.display = 'none'
  }

  /**
   * Wait for animation to complete
   */
  waitForAnimation() {
    return new Promise((resolve) => {
      setTimeout(resolve, this.animationDuration)
    })
  }

  /**
   * Update toggle button text and appearance
   */
  updateToggleButton() {
    if (!this.toggleButton) {
      return
    }

    const icon = this.isAdvancedMode ? this.createChevronUpIcon() : this.createChevronDownIcon()
    const text = this.isAdvancedMode ? 'Hide Advanced Settings' : 'Show Advanced Settings'

    // SECURITY FIX: Use DOM manipulation instead of innerHTML
    while (this.toggleButton.firstChild) {
      this.toggleButton.removeChild(this.toggleButton.firstChild)
    }
    this.toggleButton.appendChild(icon)

    const textSpan = document.createElement('span')
    textSpan.textContent = text
    this.toggleButton.appendChild(textSpan)

    // Update ARIA attributes
    this.toggleButton.setAttribute('aria-expanded', String(this.isAdvancedMode))
    this.toggleButton.setAttribute('aria-label', text)
  }

  /**
   * Create chevron down icon
   */
  createChevronDownIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-4 h-4 mr-2')
    svg.setAttribute('fill', 'none')
    svg.setAttribute('stroke', 'currentColor')
    svg.setAttribute('viewBox', '0 0 24 24')

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('stroke-linecap', 'round')
    path.setAttribute('stroke-linejoin', 'round')
    path.setAttribute('stroke-width', '2')
    path.setAttribute('d', 'M19 9l-7 7-7-7')

    svg.appendChild(path)
    return svg
  }

  /**
   * Create chevron up icon
   */
  createChevronUpIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-4 h-4 mr-2')
    svg.setAttribute('fill', 'none')
    svg.setAttribute('stroke', 'currentColor')
    svg.setAttribute('viewBox', '0 0 24 24')

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('stroke-linecap', 'round')
    path.setAttribute('stroke-linejoin', 'round')
    path.setAttribute('stroke-width', '2')
    path.setAttribute('d', 'M5 15l7-7 7 7')

    svg.appendChild(path)
    return svg
  }

  /**
   * Set advanced mode programmatically
   * @param {boolean} isAdvanced - Whether to show advanced mode
   */
  async setMode(isAdvanced) {
    if (this.isAdvancedMode !== isAdvanced) {
      await this.toggleMode()
    }
  }

  /**
   * Get current mode
   * @returns {boolean} Whether advanced mode is active
   */
  getMode() {
    return this.isAdvancedMode
  }

  /**
   * Check if prefers reduced motion
   */
  prefersReducedMotion() {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  }

  /**
   * Set animation duration based on user preferences
   */
  updateAnimationDuration() {
    if (this.prefersReducedMotion()) {
      this.animationDuration = 0
    } else {
      this.animationDuration = 300
    }
  }

  /**
   * Cleanup and destroy
   */
  destroy() {
    if (this.toggleButton && this.boundToggleMode) {
      this.toggleButton.removeEventListener('click', this.boundToggleMode)
    }
  }
}
