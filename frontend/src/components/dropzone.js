import { UIStates } from '../utils/uiState.js'
import { throttle } from '../utils/debounce.js'

export class DropZone {
  constructor(element, uiStateManager = null) {
    this.element = element
    this.fileInput = element.querySelector('#fileInput')
    this.isDragging = false
    this.onFileSelectCallback = null
    this.onMultipleFilesSelectCallback = null
    this.uiStateManager = uiStateManager
    this.supportedFormats = [
      '.jpg',
      '.jpeg',
      '.png',
      '.webp',
      '.heif',
      '.heic',
      '.bmp',
      '.tiff',
      '.gif',
      '.avif',
    ]
    this.maxFileSize = 50 * 1024 * 1024 // 50MB
    this.maxFileCount = 100

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

    // Handle both files and items (for folder support)
    const items = e.dataTransfer.items
    if (items && items.length > 0) {
      this.processFiles(items)
    } else {
      // Fallback to files
      const files = e.dataTransfer.files
      this.processFiles(files)
    }
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

  async processFiles(files) {
    if (files.length === 0) {
      return
    }

    // Extract files from FileList and handle folders
    const allFiles = await this.extractAllFiles(files)

    // Filter and validate files
    const validFiles = this.filterValidImageFiles(allFiles)

    if (validFiles.length === 0) {
      if (this.uiStateManager) {
        this.uiStateManager.setState(UIStates.ERROR)
      }
      this.showError('No valid image files found')
      return
    }

    // Check file count limit
    if (validFiles.length > this.maxFileCount) {
      if (this.uiStateManager) {
        this.uiStateManager.setState(UIStates.ERROR)
      }
      this.showError(
        `Maximum ${this.maxFileCount} files allowed. You selected ${validFiles.length} files.`
      )
      return
    }

    // Check if we should handle multiple files or single file
    if (validFiles.length === 1 && this.onFileSelectCallback) {
      // Single file - use existing callback for backward compatibility
      try {
        this.onFileSelectCallback(validFiles[0])
      } catch (error) {
        console.error('Error processing file:', error)
        if (this.uiStateManager) {
          this.uiStateManager.setState(UIStates.ERROR)
        }
      }
    } else if (validFiles.length > 1 && this.onMultipleFilesSelectCallback) {
      // Multiple files - use new callback
      try {
        this.onMultipleFilesSelectCallback(validFiles)
      } catch (error) {
        console.error('Error processing files:', error)
        if (this.uiStateManager) {
          this.uiStateManager.setState(UIStates.ERROR)
        }
      }
    } else if (validFiles.length > 1 && !this.onMultipleFilesSelectCallback) {
      // Multiple files but no handler - show error
      this.showError('Multiple file handling not configured')
    }
  }

  async extractAllFiles(fileList) {
    const files = []
    const items = []

    // Convert FileList to array of items
    if (fileList instanceof DataTransferItemList) {
      for (let i = 0; i < fileList.length; i++) {
        items.push(fileList[i])
      }
    } else {
      // Regular FileList
      for (let i = 0; i < fileList.length; i++) {
        files.push(fileList[i])
      }
      return files
    }

    // Process each item (could be file or directory)
    for (const item of items) {
      if (item.kind === 'file') {
        const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : item.getAsEntry?.()
        if (entry) {
          const extractedFiles = await this.traverseFileTree(entry)
          files.push(...extractedFiles)
        } else {
          // Fallback to getAsFile
          const file = item.getAsFile()
          if (file) {
            files.push(file)
          }
        }
      }
    }

    return files
  }

  async traverseFileTree(entry, path = '') {
    const files = []

    if (entry.isFile) {
      // Get file
      const file = await new Promise((resolve, reject) => {
        entry.file(resolve, reject)
      })
      files.push(file)
    } else if (entry.isDirectory) {
      // Read directory
      const reader = entry.createReader()
      const entries = await new Promise((resolve, reject) => {
        const allEntries = []
        const readEntries = () => {
          reader.readEntries((entries) => {
            if (entries.length === 0) {
              resolve(allEntries)
            } else {
              allEntries.push(...entries)
              readEntries() // Continue reading
            }
          }, reject)
        }
        readEntries()
      })

      // Process each entry in directory
      for (const childEntry of entries) {
        const childFiles = await this.traverseFileTree(childEntry, path + entry.name + '/')
        files.push(...childFiles)
      }
    }

    return files
  }

  filterValidImageFiles(files) {
    return files.filter((file) => {
      // Check file extension
      const ext = file.name.toLowerCase().match(/\.[^.]+$/)?.[0]
      if (!ext || !this.supportedFormats.includes(ext)) {
        console.warn(`Skipping unsupported file type: ${file.name}`)
        return false
      }

      // Check file size
      if (file.size > this.maxFileSize) {
        console.warn(
          `Skipping file too large: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)}MB)`
        )
        return false
      }

      return true
    })
  }

  showError(message) {
    // Find or create error message element
    const errorEl = document.getElementById('errorMessage')
    if (errorEl) {
      errorEl.textContent = message
      errorEl.classList.remove('hidden')
      setTimeout(() => {
        errorEl.classList.add('hidden')
      }, 5000)
    }
  }

  onFileSelect(callback) {
    this.onFileSelectCallback = callback
  }

  onMultipleFilesSelect(callback) {
    this.onMultipleFilesSelectCallback = callback
  }

  reset() {
    this.fileInput.value = ''
    this.element.classList.remove('dropzone-active')
  }

  destroy() {
    // Remove all event listeners if elements exist
    if (this.element && this.boundHandlers) {
      this.element.removeEventListener('dragenter', this.boundHandlers.dragEnter)
      this.element.removeEventListener('dragover', this.boundHandlers.dragOver)
      this.element.removeEventListener('dragleave', this.boundHandlers.dragLeave)
      this.element.removeEventListener('drop', this.boundHandlers.drop)
      this.element.removeEventListener('click', this.boundHandlers.click)
      this.element.removeEventListener('keydown', this.boundHandlers.keyDown)
    }
    
    if (this.fileInput && this.boundHandlers) {
      this.fileInput.removeEventListener('change', this.boundHandlers.fileInputChange)
    }

    // Clear references
    this.element = null
    this.fileInput = null
    this.onFileSelectCallback = null
    this.uiStateManager = null
    this.boundHandlers = null
  }
}
