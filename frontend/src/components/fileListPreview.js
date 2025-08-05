/**
 * File list preview component for batch processing
 */

export class FileListPreview {
  constructor(container) {
    this.container = container
    this.files = []
    this.onRemoveCallback = null
    this.onClearAllCallback = null
    
    this.render()
  }

  setFiles(files) {
    this.files = Array.from(files)
    this.render()
  }

  addFiles(newFiles) {
    this.files.push(...Array.from(newFiles))
    this.render()
  }

  removeFile(index) {
    if (index >= 0 && index < this.files.length) {
      const removedFile = this.files.splice(index, 1)[0]
      this.render()
      
      if (this.onRemoveCallback) {
        this.onRemoveCallback(removedFile, index)
      }
    }
  }

  clearAll() {
    this.files = []
    this.render()
    
    if (this.onClearAllCallback) {
      this.onClearAllCallback()
    }
  }

  onRemove(callback) {
    this.onRemoveCallback = callback
  }

  onClearAll(callback) {
    this.onClearAllCallback = callback
  }

  render() {
    this.container.innerHTML = ''
    
    if (this.files.length === 0) {
      this.container.classList.add('hidden')
      return
    }
    
    this.container.classList.remove('hidden')
    
    // Header
    const header = this.createHeader()
    this.container.appendChild(header)
    
    // File list
    const fileList = this.createFileList()
    this.container.appendChild(fileList)
  }

  createHeader() {
    const header = document.createElement('div')
    header.className = 'flex justify-between items-center mb-4'
    
    const title = document.createElement('h3')
    title.className = 'text-lg font-semibold'
    title.textContent = `Selected Files (${this.files.length})`
    
    const clearButton = document.createElement('button')
    clearButton.className = 'text-sm text-red-600 hover:text-red-800 transition-colors'
    clearButton.textContent = 'Clear All'
    clearButton.onclick = () => this.clearAll()
    
    header.appendChild(title)
    header.appendChild(clearButton)
    
    return header
  }

  createFileList() {
    const list = document.createElement('div')
    list.className = 'space-y-2 max-h-64 overflow-y-auto'
    
    this.files.forEach((file, index) => {
      const fileItem = this.createFileItem(file, index)
      list.appendChild(fileItem)
    })
    
    return list
  }

  createFileItem(file, index) {
    const item = document.createElement('div')
    item.className = 'flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors'
    
    // File info
    const fileInfo = document.createElement('div')
    fileInfo.className = 'flex items-center space-x-3 flex-1 min-w-0'
    
    // File icon
    const icon = this.createFileIcon()
    fileInfo.appendChild(icon)
    
    // File details
    const details = document.createElement('div')
    details.className = 'flex-1 min-w-0'
    
    const fileName = document.createElement('p')
    fileName.className = 'text-sm font-medium text-gray-900 truncate'
    fileName.textContent = file.name
    fileName.title = file.name
    
    const fileSize = document.createElement('p')
    fileSize.className = 'text-xs text-gray-500'
    fileSize.textContent = this.formatFileSize(file.size)
    
    details.appendChild(fileName)
    details.appendChild(fileSize)
    fileInfo.appendChild(details)
    
    // Remove button
    const removeButton = document.createElement('button')
    removeButton.className = 'p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors'
    removeButton.setAttribute('aria-label', `Remove ${file.name}`)
    removeButton.onclick = () => this.removeFile(index)
    
    const removeIcon = this.createRemoveIcon()
    removeButton.appendChild(removeIcon)
    
    item.appendChild(fileInfo)
    item.appendChild(removeButton)
    
    return item
  }

  createFileIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-8 h-8 text-gray-400')
    svg.setAttribute('fill', 'none')
    svg.setAttribute('stroke', 'currentColor')
    svg.setAttribute('viewBox', '0 0 24 24')
    
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('stroke-linecap', 'round')
    path.setAttribute('stroke-linejoin', 'round')
    path.setAttribute('stroke-width', '2')
    path.setAttribute('d', 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z')
    
    svg.appendChild(path)
    return svg
  }

  createRemoveIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-5 h-5')
    svg.setAttribute('fill', 'none')
    svg.setAttribute('stroke', 'currentColor')
    svg.setAttribute('viewBox', '0 0 24 24')
    
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
    path.setAttribute('stroke-linecap', 'round')
    path.setAttribute('stroke-linejoin', 'round')
    path.setAttribute('stroke-width', '2')
    path.setAttribute('d', 'M6 18L18 6M6 6l12 12')
    
    svg.appendChild(path)
    return svg
  }

  formatFileSize(bytes) {
    if (bytes === 0) {
      return '0 Bytes'
    }
    
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  getFiles() {
    return this.files
  }

  getFileCount() {
    return this.files.length
  }

  getTotalSize() {
    return this.files.reduce((total, file) => total + file.size, 0)
  }
}