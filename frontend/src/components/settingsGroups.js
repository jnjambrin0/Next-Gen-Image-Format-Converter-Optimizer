/**
 * Settings groups component for organizing conversion settings
 * Groups settings into logical categories with expand/collapse functionality
 */

export class SettingsGroups {
  constructor() {
    this.groups = {
      quality: {
        name: 'Quality Settings',
        description: 'Adjust quality and optimization',
        expanded: true,
        elements: [],
      },
      optimization: {
        name: 'Optimization',
        description: 'Advanced optimization options',
        expanded: true,
        elements: [],
      },
      metadata: {
        name: 'Metadata',
        description: 'Control metadata handling',
        expanded: true,
        elements: [],
      },
    }
    this.onGroupToggle = null
    this.container = null
    this.eventHandlers = new Map()
  }

  /**
   * Initialize settings groups
   * @param {Object} options - Configuration options
   * @param {Object} options.elements - Map of setting elements by group
   * @param {Function} options.onGroupToggle - Callback when group is toggled
   * @returns {HTMLElement} Container element
   */
  init(options) {
    this.onGroupToggle = options.onGroupToggle

    // Assign elements to groups
    if (options.elements) {
      Object.keys(options.elements).forEach((groupId) => {
        if (this.groups[groupId]) {
          this.groups[groupId].elements = options.elements[groupId]
        }
      })
    }

    this.container = this.createElement()
    return this.container
  }

  /**
   * Create the groups container element
   */
  createElement() {
    const container = document.createElement('div')
    container.className = 'space-y-4'

    Object.entries(this.groups).forEach(([groupId, group]) => {
      const groupElement = this.createGroupElement(groupId, group)
      container.appendChild(groupElement)
    })

    return container
  }

  /**
   * Create a single group element
   */
  createGroupElement(groupId, group) {
    const groupContainer = document.createElement('div')
    groupContainer.className = 'border border-gray-200 rounded-lg overflow-hidden'
    groupContainer.setAttribute('data-group-id', groupId)

    // Group header
    const header = this.createGroupHeader(groupId, group)
    groupContainer.appendChild(header)

    // Group content
    const content = this.createGroupContent(groupId, group)
    groupContainer.appendChild(content)

    return groupContainer
  }

  /**
   * Create group header with toggle functionality
   */
  createGroupHeader(groupId, group) {
    const header = document.createElement('button')
    header.className =
      'w-full px-4 py-3 bg-gray-50 hover:bg-gray-100 transition-colors flex items-center justify-between text-left'
    header.setAttribute('aria-expanded', String(group.expanded))
    header.setAttribute('aria-controls', `group-content-${groupId}`)

    // Title and description
    const titleContainer = document.createElement('div')
    titleContainer.className = 'flex-1'

    const title = document.createElement('h3')
    title.className = 'text-sm font-semibold text-gray-900'
    title.textContent = group.name

    const description = document.createElement('p')
    description.className = 'text-xs text-gray-500 mt-0.5'
    description.textContent = group.description

    titleContainer.appendChild(title)
    titleContainer.appendChild(description)

    // Toggle icon
    const icon = this.createToggleIcon(group.expanded)
    icon.setAttribute('data-toggle-icon', groupId)

    header.appendChild(titleContainer)
    header.appendChild(icon)

    // Click handler - store reference for cleanup
    const clickHandler = () => this.toggleGroup(groupId)
    header.addEventListener('click', clickHandler)
    this.eventHandlers.set(`header-${groupId}`, { element: header, event: 'click', handler: clickHandler })

    return header
  }

  /**
   * Create group content container
   */
  createGroupContent(groupId, group) {
    const content = document.createElement('div')
    content.id = `group-content-${groupId}`
    content.className = 'px-4 py-3 space-y-3'
    content.style.display = group.expanded ? 'block' : 'none'

    // Add elements to content
    group.elements.forEach((element) => {
      if (element) {
        content.appendChild(element)
      }
    })

    return content
  }

  /**
   * Create toggle icon
   */
  createToggleIcon(expanded) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-5 h-5 text-gray-400 transition-transform duration-200')
    svg.setAttribute('fill', 'none')
    svg.setAttribute('stroke', 'currentColor')
    svg.setAttribute('viewBox', '0 0 24 24')

    if (!expanded) {
      svg.style.transform = 'rotate(-90deg)'
    }

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('stroke-linecap', 'round')
    path.setAttribute('stroke-linejoin', 'round')
    path.setAttribute('stroke-width', '2')
    path.setAttribute('d', 'M19 9l-7 7-7-7')

    svg.appendChild(path)
    return svg
  }

  /**
   * Toggle group expanded state
   */
  toggleGroup(groupId) {
    const group = this.groups[groupId]
    if (!group) {
      return
    }

    group.expanded = !group.expanded

    // Update UI
    const groupElement = this.container.querySelector(`[data-group-id="${groupId}"]`)
    if (groupElement) {
      const header = groupElement.querySelector('button')
      const content = groupElement.querySelector(`#group-content-${groupId}`)
      const icon = groupElement.querySelector('[data-toggle-icon]')

      if (header) {
        header.setAttribute('aria-expanded', String(group.expanded))
      }

      if (content) {
        if (group.expanded) {
          this.expandContent(content)
          if (icon) {
            icon.style.transform = 'rotate(0deg)'
          }
        } else {
          this.collapseContent(content)
          if (icon) {
            icon.style.transform = 'rotate(-90deg)'
          }
        }
      }
    }

    if (this.onGroupToggle) {
      this.onGroupToggle(groupId, group.expanded)
    }
  }

  /**
   * Expand content with animation
   */
  expandContent(content) {
    content.style.display = 'block'
    const height = content.scrollHeight
    content.style.height = '0px'
    content.offsetHeight // Force reflow
    content.style.transition = 'height 200ms ease-out'
    content.style.height = height + 'px'

    setTimeout(() => {
      content.style.height = 'auto'
      content.style.transition = ''
    }, 200)
  }

  /**
   * Collapse content with animation
   */
  collapseContent(content) {
    const height = content.scrollHeight
    content.style.height = height + 'px'
    content.offsetHeight // Force reflow
    content.style.transition = 'height 200ms ease-out'
    content.style.height = '0px'

    setTimeout(() => {
      content.style.display = 'none'
      content.style.transition = ''
    }, 200)
  }

  /**
   * Set group expanded state
   */
  setGroupExpanded(groupId, expanded) {
    const group = this.groups[groupId]
    if (group && group.expanded !== expanded) {
      this.toggleGroup(groupId)
    }
  }

  /**
   * Get group states
   */
  getGroupStates() {
    const states = {}
    Object.keys(this.groups).forEach((groupId) => {
      states[groupId] = this.groups[groupId].expanded
    })
    return states
  }

  /**
   * Set all group states
   */
  setGroupStates(states) {
    Object.entries(states).forEach(([groupId, expanded]) => {
      this.setGroupExpanded(groupId, expanded)
    })
  }

  /**
   * Expand all groups
   */
  expandAll() {
    Object.keys(this.groups).forEach((groupId) => {
      this.setGroupExpanded(groupId, true)
    })
  }

  /**
   * Collapse all groups
   */
  collapseAll() {
    Object.keys(this.groups).forEach((groupId) => {
      this.setGroupExpanded(groupId, false)
    })
  }

  /**
   * Cleanup event listeners and references
   */
  destroy() {
    // Remove all event listeners
    this.eventHandlers.forEach(({ element, event, handler }) => {
      if (element) {
        element.removeEventListener(event, handler)
      }
    })
    this.eventHandlers.clear()

    // Clear references
    this.container = null
    this.onGroupToggle = null
  }
}
