/**
 * Reusable tooltip component for providing contextual help
 */

export class Tooltip {
  constructor() {
    this.activeTooltips = new Map()
    this.tooltipZIndex = 1000
  }

  /**
   * Create a tooltip for an element
   * @param {HTMLElement} element - Element to attach tooltip to
   * @param {Object} options - Tooltip configuration
   * @param {string} options.content - Tooltip content (text only for security)
   * @param {string} options.position - Preferred position (top, bottom, left, right)
   * @param {number} options.delay - Delay before showing (ms)
   */
  create(element, options = {}) {
    const config = {
      content: options.content || '',
      position: options.position || 'top',
      delay: options.delay || 300,
      ...options,
    }

    // Create tooltip instance
    const tooltipData = {
      element,
      config,
      tooltip: null,
      showTimeout: null,
      isVisible: false,
    }

    // Store reference
    this.activeTooltips.set(element, tooltipData)

    // Attach event listeners
    this.attachEventListeners(element, tooltipData)

    return this
  }

  /**
   * Attach event listeners for tooltip triggers
   */
  attachEventListeners(element, tooltipData) {
    // Create bound event handlers for proper cleanup
    tooltipData.boundHandlers = {
      mouseenter: () => this.handleMouseEnter(tooltipData),
      mouseleave: () => this.handleMouseLeave(tooltipData),
      focus: () => this.handleFocus(tooltipData),
      blur: () => this.handleBlur(tooltipData),
      touchstart: (e) => this.handleTouch(e, tooltipData),
    }

    // Mouse events
    element.addEventListener('mouseenter', tooltipData.boundHandlers.mouseenter)
    element.addEventListener('mouseleave', tooltipData.boundHandlers.mouseleave)

    // Keyboard events for accessibility
    element.addEventListener('focus', tooltipData.boundHandlers.focus)
    element.addEventListener('blur', tooltipData.boundHandlers.blur)

    // Touch events for mobile
    element.addEventListener('touchstart', tooltipData.boundHandlers.touchstart)
  }

  /**
   * Handle mouse enter event
   */
  handleMouseEnter(tooltipData) {
    if (tooltipData.showTimeout) {
      clearTimeout(tooltipData.showTimeout)
    }

    tooltipData.showTimeout = setTimeout(() => {
      this.show(tooltipData)
    }, tooltipData.config.delay)
  }

  /**
   * Handle mouse leave event
   */
  handleMouseLeave(tooltipData) {
    if (tooltipData.showTimeout) {
      clearTimeout(tooltipData.showTimeout)
    }
    this.hide(tooltipData)
  }

  /**
   * Handle focus event
   */
  handleFocus(tooltipData) {
    this.show(tooltipData)
  }

  /**
   * Handle blur event
   */
  handleBlur(tooltipData) {
    this.hide(tooltipData)
  }

  /**
   * Handle touch event
   */
  handleTouch(event, tooltipData) {
    event.preventDefault()
    if (tooltipData.isVisible) {
      this.hide(tooltipData)
    } else {
      this.show(tooltipData)
    }
  }

  /**
   * Show tooltip
   */
  show(tooltipData) {
    if (tooltipData.isVisible) {
      return
    }

    // Create tooltip element
    const tooltip = this.createTooltipElement(tooltipData.config)
    tooltipData.tooltip = tooltip
    document.body.appendChild(tooltip)

    // Position tooltip
    this.positionTooltip(tooltipData.element, tooltip, tooltipData.config.position)

    // Animate in
    requestAnimationFrame(() => {
      tooltip.classList.add('tooltip-visible')
    })

    tooltipData.isVisible = true

    // Set ARIA attributes
    tooltipData.element.setAttribute('aria-describedby', tooltip.id)
  }

  /**
   * Hide tooltip
   */
  hide(tooltipData) {
    if (!tooltipData.isVisible || !tooltipData.tooltip) {
      return
    }

    const tooltip = tooltipData.tooltip

    // Animate out
    tooltip.classList.remove('tooltip-visible')

    // Remove after animation
    setTimeout(() => {
      if (tooltip.parentNode) {
        tooltip.parentNode.removeChild(tooltip)
      }
    }, 200)

    tooltipData.isVisible = false
    tooltipData.tooltip = null

    // Remove ARIA attributes
    tooltipData.element.removeAttribute('aria-describedby')
  }

  /**
   * Create tooltip element
   */
  createTooltipElement(config) {
    const tooltip = document.createElement('div')
    tooltip.className = 'tooltip'
    tooltip.id = `tooltip-${Date.now()}`
    tooltip.setAttribute('role', 'tooltip')

    // Add content - SECURITY FIX: Remove HTML support to prevent XSS
    // Always use textContent for safety, never innerHTML
    tooltip.textContent = config.content

    // Add styles
    tooltip.style.cssText = `
      position: fixed;
      z-index: ${this.tooltipZIndex};
      padding: 8px 12px;
      background-color: rgba(31, 41, 55, 0.95);
      color: white;
      font-size: 14px;
      line-height: 1.4;
      border-radius: 6px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
      pointer-events: none;
      opacity: 0;
      transform: scale(0.9);
      transition: opacity 200ms ease-out, transform 200ms ease-out;
      max-width: 300px;
      word-wrap: break-word;
    `

    // Arrow
    const arrow = document.createElement('div')
    arrow.className = 'tooltip-arrow'
    arrow.style.cssText = `
      position: absolute;
      width: 8px;
      height: 8px;
      background-color: rgba(31, 41, 55, 0.95);
      transform: rotate(45deg);
    `
    tooltip.appendChild(arrow)

    return tooltip
  }

  /**
   * Position tooltip relative to element
   */
  positionTooltip(element, tooltip, preferredPosition) {
    const rect = element.getBoundingClientRect()
    const tooltipRect = tooltip.getBoundingClientRect()
    const arrow = tooltip.querySelector('.tooltip-arrow')

    const spacing = 8
    const positions = {
      top: () => {
        const left = rect.left + (rect.width - tooltipRect.width) / 2
        const top = rect.top - tooltipRect.height - spacing
        arrow.style.bottom = '-4px'
        arrow.style.left = '50%'
        arrow.style.transform = 'translateX(-50%) rotate(45deg)'
        return { left, top }
      },
      bottom: () => {
        const left = rect.left + (rect.width - tooltipRect.width) / 2
        const top = rect.bottom + spacing
        arrow.style.top = '-4px'
        arrow.style.left = '50%'
        arrow.style.transform = 'translateX(-50%) rotate(45deg)'
        return { left, top }
      },
      left: () => {
        const left = rect.left - tooltipRect.width - spacing
        const top = rect.top + (rect.height - tooltipRect.height) / 2
        arrow.style.right = '-4px'
        arrow.style.top = '50%'
        arrow.style.transform = 'translateY(-50%) rotate(45deg)'
        return { left, top }
      },
      right: () => {
        const left = rect.right + spacing
        const top = rect.top + (rect.height - tooltipRect.height) / 2
        arrow.style.left = '-4px'
        arrow.style.top = '50%'
        arrow.style.transform = 'translateY(-50%) rotate(45deg)'
        return { left, top }
      },
    }

    // Try preferred position first
    let position = positions[preferredPosition]()

    // Check if tooltip fits in viewport
    if (
      position.left < 0 ||
      position.left + tooltipRect.width > window.innerWidth ||
      position.top < 0 ||
      position.top + tooltipRect.height > window.innerHeight
    ) {
      // Try other positions
      const fallbackOrder = ['top', 'bottom', 'left', 'right'].filter(
        (p) => p !== preferredPosition
      )

      for (const fallback of fallbackOrder) {
        position = positions[fallback]()
        if (
          position.left >= 0 &&
          position.left + tooltipRect.width <= window.innerWidth &&
          position.top >= 0 &&
          position.top + tooltipRect.height <= window.innerHeight
        ) {
          break
        }
      }
    }

    // Apply position
    tooltip.style.left = `${Math.max(0, Math.min(position.left, window.innerWidth - tooltipRect.width))}px`
    tooltip.style.top = `${Math.max(0, Math.min(position.top, window.innerHeight - tooltipRect.height))}px`
  }

  /**
   * Add tooltip styles to page (call once)
   */
  static addStyles() {
    if (document.getElementById('tooltip-styles')) {
      return
    }

    const style = document.createElement('style')
    style.id = 'tooltip-styles'
    style.textContent = `
      .tooltip-visible {
        opacity: 1 !important;
        transform: scale(1) !important;
      }
      
      @media (prefers-reduced-motion: reduce) {
        .tooltip {
          transition: none !important;
        }
      }
    `
    document.head.appendChild(style)
  }

  /**
   * Create help icon with tooltip
   */
  static createHelpIcon(tooltipContent, options = {}) {
    const container = document.createElement('span')
    container.className = 'inline-flex items-center ml-1'
    container.setAttribute('tabindex', '0')
    container.setAttribute('role', 'button')
    container.setAttribute('aria-label', 'Help')

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-4 h-4 text-gray-400 hover:text-gray-600 cursor-help')
    svg.setAttribute('fill', 'none')
    svg.setAttribute('stroke', 'currentColor')
    svg.setAttribute('viewBox', '0 0 24 24')

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('stroke-linecap', 'round')
    path.setAttribute('stroke-linejoin', 'round')
    path.setAttribute('stroke-width', '2')
    path.setAttribute(
      'd',
      'M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z'
    )

    svg.appendChild(path)
    container.appendChild(svg)

    // Create tooltip instance
    const tooltip = new Tooltip()
    tooltip.create(container, {
      content: tooltipContent,
      position: options.position || 'top',
      ...options,
    })

    return container
  }

  /**
   * Remove tooltip from element
   */
  remove(element) {
    const tooltipData = this.activeTooltips.get(element)
    if (tooltipData) {
      // Hide tooltip if visible
      this.hide(tooltipData)

      // Clean up event listeners
      if (tooltipData.boundHandlers) {
        element.removeEventListener('mouseenter', tooltipData.boundHandlers.mouseenter)
        element.removeEventListener('mouseleave', tooltipData.boundHandlers.mouseleave)
        element.removeEventListener('focus', tooltipData.boundHandlers.focus)
        element.removeEventListener('blur', tooltipData.boundHandlers.blur)
        element.removeEventListener('touchstart', tooltipData.boundHandlers.touchstart)
      }

      // Clear any pending timeouts
      if (tooltipData.showTimeout) {
        clearTimeout(tooltipData.showTimeout)
      }

      this.activeTooltips.delete(element)
    }
  }

  /**
   * Remove all tooltips
   */
  removeAll() {
    this.activeTooltips.forEach((tooltipData) => {
      this.hide(tooltipData)
    })
    this.activeTooltips.clear()
  }
}

// Add styles on load
Tooltip.addStyles()
