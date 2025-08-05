/**
 * Global keyboard shortcut handler
 * Manages keyboard shortcuts throughout the application
 */

export class KeyboardShortcuts {
  constructor() {
    this.shortcuts = new Map()
    this.enabled = true
    this.isListening = false
    this.modalOpen = false
  }

  /**
   * Initialize keyboard shortcuts
   */
  init() {
    if (this.isListening) {
      return
    }

    // Store bound handler for proper cleanup
    this.boundHandleKeyDown = this.handleKeyDown.bind(this)
    document.addEventListener('keydown', this.boundHandleKeyDown)
    this.isListening = true

    return this
  }

  /**
   * Register a keyboard shortcut
   * @param {Object} options - Shortcut configuration
   * @param {string} options.key - Key to listen for
   * @param {boolean} options.ctrl - Require Ctrl/Cmd key
   * @param {boolean} options.shift - Require Shift key
   * @param {boolean} options.alt - Require Alt key
   * @param {Function} options.handler - Function to call when triggered
   * @param {string} options.description - Description for help
   * @param {string} options.category - Category for grouping
   */
  register(options) {
    const shortcutKey = this.generateShortcutKey(options)

    this.shortcuts.set(shortcutKey, {
      ...options,
      shortcutKey,
    })

    return this
  }

  /**
   * Unregister a keyboard shortcut
   */
  unregister(options) {
    const shortcutKey = this.generateShortcutKey(options)
    this.shortcuts.delete(shortcutKey)

    return this
  }

  /**
   * Generate unique key for shortcut
   */
  generateShortcutKey(options) {
    const parts = []

    if (options.ctrl) {
      parts.push('ctrl')
    }
    if (options.alt) {
      parts.push('alt')
    }
    if (options.shift) {
      parts.push('shift')
    }
    parts.push(options.key.toLowerCase())

    return parts.join('+')
  }

  /**
   * Handle keydown events
   */
  handleKeyDown(event) {
    if (!this.enabled || this.modalOpen) {
      return
    }

    // Ignore if in input field (unless explicitly allowed)
    const target = event.target
    const isInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)
    if (isInput && !event.ctrlKey && !event.metaKey) {
      return
    }

    // Build shortcut key
    const parts = []
    if (event.ctrlKey || event.metaKey) {
      parts.push('ctrl')
    }
    if (event.altKey) {
      parts.push('alt')
    }
    if (event.shiftKey) {
      parts.push('shift')
    }

    // Normalize key
    let key = event.key.toLowerCase()
    if (key === ' ') {
      key = 'space'
    }
    if (key === 'escape') {
      key = 'esc'
    }
    if (key === 'arrowup') {
      key = 'up'
    }
    if (key === 'arrowdown') {
      key = 'down'
    }
    if (key === 'arrowleft') {
      key = 'left'
    }
    if (key === 'arrowright') {
      key = 'right'
    }

    parts.push(key)
    const shortcutKey = parts.join('+')

    // Check if shortcut exists
    const shortcut = this.shortcuts.get(shortcutKey)
    if (shortcut && shortcut.handler) {
      event.preventDefault()
      event.stopPropagation()
      shortcut.handler(event)
    }
  }

  /**
   * Enable/disable shortcuts
   */
  setEnabled(enabled) {
    this.enabled = enabled
    return this
  }

  /**
   * Set modal state (disables shortcuts when modal is open)
   */
  setModalOpen(open) {
    this.modalOpen = open
    return this
  }

  /**
   * Get all registered shortcuts
   */
  getShortcuts() {
    const shortcuts = []

    this.shortcuts.forEach((shortcut) => {
      shortcuts.push({
        key: shortcut.key,
        ctrl: shortcut.ctrl || false,
        shift: shortcut.shift || false,
        alt: shortcut.alt || false,
        description: shortcut.description || '',
        category: shortcut.category || 'General',
        displayKey: this.getDisplayKey(shortcut),
      })
    })

    return shortcuts
  }

  /**
   * Get display-friendly key combination
   */
  getDisplayKey(shortcut) {
    const parts = []
    const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0

    if (shortcut.ctrl) {
      parts.push(isMac ? '⌘' : 'Ctrl')
    }
    if (shortcut.alt) {
      parts.push(isMac ? '⌥' : 'Alt')
    }
    if (shortcut.shift) {
      parts.push('⇧')
    }

    // Format key
    let key = shortcut.key
    if (key.length === 1) {
      key = key.toUpperCase()
    } else {
      key = key.charAt(0).toUpperCase() + key.slice(1)
    }

    parts.push(key)

    return parts.join(isMac ? '' : '+')
  }

  /**
   * Show help modal with all shortcuts
   */
  showHelp() {
    // Group shortcuts by category
    const shortcutsByCategory = new Map()

    this.shortcuts.forEach((shortcut) => {
      const category = shortcut.category || 'General'
      if (!shortcutsByCategory.has(category)) {
        shortcutsByCategory.set(category, [])
      }
      shortcutsByCategory.get(category).push(shortcut)
    })

    // Create modal
    const modal = document.createElement('div')
    modal.className =
      'fixed inset-0 z-50 flex items-center justify-center p-4 bg-black bg-opacity-50'
    modal.onclick = (e) => {
      if (e.target === modal) {
        this.hideHelp()
      }
    }

    const content = document.createElement('div')
    content.className =
      'bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] overflow-hidden'

    // Header
    const header = document.createElement('div')
    header.className = 'px-6 py-4 border-b border-gray-200'
    
    // SECURITY FIX: Use DOM manipulation instead of innerHTML
    const title = document.createElement('h2')
    title.className = 'text-xl font-semibold text-gray-900'
    title.textContent = 'Keyboard Shortcuts'
    header.appendChild(title)

    // Body
    const body = document.createElement('div')
    body.className = 'px-6 py-4 overflow-y-auto max-h-[60vh]'

    shortcutsByCategory.forEach((shortcuts, category) => {
      const section = document.createElement('div')
      section.className = 'mb-6'

      const categoryTitle = document.createElement('h3')
      categoryTitle.className = 'text-sm font-semibold text-gray-700 mb-2'
      categoryTitle.textContent = category

      section.appendChild(categoryTitle)

      const list = document.createElement('div')
      list.className = 'space-y-2'

      shortcuts.forEach((shortcut) => {
        const item = document.createElement('div')
        item.className = 'flex items-center justify-between'

        const description = document.createElement('span')
        description.className = 'text-sm text-gray-600'
        description.textContent = shortcut.description

        const key = document.createElement('kbd')
        key.className =
          'px-2 py-1 text-xs font-semibold text-gray-800 bg-gray-100 border border-gray-200 rounded'
        key.textContent = this.getDisplayKey(shortcut)

        item.appendChild(description)
        item.appendChild(key)
        list.appendChild(item)
      })

      section.appendChild(list)
      body.appendChild(section)
    })

    // Footer
    const footer = document.createElement('div')
    footer.className = 'px-6 py-3 bg-gray-50 border-t border-gray-200 flex justify-end'

    const closeButton = document.createElement('button')
    closeButton.className =
      'px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'
    closeButton.textContent = 'Close'
    closeButton.onclick = () => this.hideHelp()

    footer.appendChild(closeButton)

    content.appendChild(header)
    content.appendChild(body)
    content.appendChild(footer)
    modal.appendChild(content)

    document.body.appendChild(modal)
    this.helpModal = modal
    this.setModalOpen(true)

    // Focus close button
    closeButton.focus()
  }

  /**
   * Hide help modal
   */
  hideHelp() {
    if (this.helpModal) {
      document.body.removeChild(this.helpModal)
      this.helpModal = null
      this.setModalOpen(false)
    }
  }

  /**
   * Register default shortcuts
   */
  static registerDefaults(shortcuts) {
    // Toggle advanced settings
    shortcuts.register({
      key: 'k',
      ctrl: true,
      handler: () => {
        const event = new CustomEvent('shortcut:toggleAdvanced')
        window.dispatchEvent(event)
      },
      description: 'Toggle advanced settings',
      category: 'Interface',
    })

    // Start conversion
    shortcuts.register({
      key: 'enter',
      ctrl: true,
      handler: () => {
        const event = new CustomEvent('shortcut:startConversion')
        window.dispatchEvent(event)
      },
      description: 'Start conversion',
      category: 'Actions',
    })

    // Format selection shortcuts
    const formats = ['webp', 'avif', 'jpeg', 'png']
    formats.forEach((format, index) => {
      shortcuts.register({
        key: String(index + 1),
        handler: () => {
          const event = new CustomEvent('shortcut:selectFormat', {
            detail: { format },
          })
          window.dispatchEvent(event)
        },
        description: `Select ${format.toUpperCase()} format`,
        category: 'Format Selection',
      })
    })

    // Show help
    shortcuts.register({
      key: '?',
      shift: true,
      handler: () => shortcuts.showHelp(),
      description: 'Show keyboard shortcuts',
      category: 'Help',
    })

    // Escape key
    shortcuts.register({
      key: 'esc',
      handler: () => {
        const event = new CustomEvent('shortcut:escape')
        window.dispatchEvent(event)
      },
      description: 'Close dialogs/Cancel operation',
      category: 'General',
    })
  }

  /**
   * Cleanup
   */
  destroy() {
    if (this.isListening && this.boundHandleKeyDown) {
      document.removeEventListener('keydown', this.boundHandleKeyDown)
      this.isListening = false
    }

    this.shortcuts.clear()
    this.hideHelp()
  }
}
