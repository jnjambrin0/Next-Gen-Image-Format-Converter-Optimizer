import { UIStates } from '../utils/uiState.js'
import { throttle } from '../utils/debounce.js'

export class DropZone {
  constructor(element, uiStateManager = null) {
    this.element = element
    this.fileInput = element.querySelector('#fileInput')
    this.isDragging = false
    this.onFileSelectCallback = null
    this.uiStateManager = uiStateManager

    // Store bound event handlers for cleanup
    this.boundHandlers = {
      dragEnter: this.handleDragEnter.bind(this),
      dragOver: throttle(this.handleDragOver.bind(this), 100),
      dragLeave: this.handleDragLeave.bind(this),
      drop: this.handleDrop.bind(this),
      click: this.handleClick.bind(this),
      keyDown: this.handleKeyDown.bind(this),
      fileInputChange: this.handleFileInputChange.bind(this),
    }

    this.bindEvents()
  }

  bindEvents() {
    // Drag and drop events
    this.element.addEventListener('dragenter', this.boundHandlers.dragEnter)
    this.element.addEventListener('dragover', this.boundHandlers.dragOver)
    this.element.addEventListener('dragleave', this.boundHandlers.dragLeave)
    this.element.addEventListener('drop', this.boundHandlers.drop)

    // Click to select file
    this.element.addEventListener('click', this.boundHandlers.click)

    // Keyboard accessibility
    this.element.addEventListener('keydown', this.boundHandlers.keyDown)

    // File input change
    this.fileInput.addEventListener('change', this.boundHandlers.fileInputChange)
  }

  handleDragEnter(e) {
    e.preventDefault()
    e.stopPropagation()
    this.isDragging = true
    this.element.classList.add('dropzone-active')

    if (this.uiStateManager) {
      this.uiStateManager.setState('dragging')
    }
  }

  handleDragOver(e) {
    e.preventDefault()
    e.stopPropagation()
  }

  handleDragLeave(e) {
    e.preventDefault()
    e.stopPropagation()

    // Check if we're leaving the dropzone completely
    const rect = this.element.getBoundingClientRect()
    const x = e.clientX
    const y = e.clientY

    if (x <= rect.left || x >= rect.right || y <= rect.top || y >= rect.bottom) {
      this.isDragging = false
      this.element.classList.remove('dropzone-active')

      if (this.uiStateManager) {
        this.uiStateManager.setState('idle')
      }
    }
  }

  handleDrop(e) {
    e.preventDefault()
    e.stopPropagation()

    this.isDragging = false
    this.element.classList.remove('dropzone-active')

    if (this.uiStateManager) {
      this.uiStateManager.setState('idle')
    }

    const files = e.dataTransfer.files
    this.processFiles(files)
  }

  handleClick(e) {
    // Prevent clicking on the file input from triggering this
    if (e.target === this.fileInput) {
      return
    }
    this.fileInput.click()
  }

  handleKeyDown(e) {
    // Enter or Space key
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      this.fileInput.click()
    }
  }

  handleFileInputChange(e) {
    const files = e.target.files
    this.processFiles(files)
  }

  processFiles(files) {
    if (files.length === 0) {
      return
    }

    // For now, we only handle single file
    const file = files[0]

    if (this.onFileSelectCallback) {
      try {
        this.onFileSelectCallback(file)
      } catch (error) {
        console.error('Error processing file:', error)
        this.uiStateManager.setState(UIStates.ERROR)
      }
    }
  }

  onFileSelect(callback) {
    this.onFileSelectCallback = callback
  }

  reset() {
    this.fileInput.value = ''
    this.element.classList.remove('dropzone-active')
  }

  destroy() {
    // Remove all event listeners
    this.element.removeEventListener('dragenter', this.boundHandlers.dragEnter)
    this.element.removeEventListener('dragover', this.boundHandlers.dragOver)
    this.element.removeEventListener('dragleave', this.boundHandlers.dragLeave)
    this.element.removeEventListener('drop', this.boundHandlers.drop)
    this.element.removeEventListener('click', this.boundHandlers.click)
    this.element.removeEventListener('keydown', this.boundHandlers.keyDown)
    this.fileInput.removeEventListener('change', this.boundHandlers.fileInputChange)

    // Clear references
    this.element = null
    this.fileInput = null
    this.onFileSelectCallback = null
    this.uiStateManager = null
  }
}
