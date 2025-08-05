/**
 * Batch queue visualization component
 */

export class BatchQueueComponent {
  constructor(container) {
    this.container = container
    this.items = []
    this.jobId = null
    this.onCancelItemCallback = null
    this.onCancelAllCallback = null
    this.sortBy = 'index' // index, name, status
    this.filterBy = 'all' // all, pending, processing, completed, failed
    
    this.render()
  }

  setJobId(jobId) {
    this.jobId = jobId
  }

  setItems(items) {
    this.items = items.map((item, index) => ({
      ...item,
      index: item.index !== undefined ? item.index : index
    }))
    this.render()
  }

  updateItem(index, updates) {
    const item = this.items.find(item => item.index === index)
    if (item) {
      Object.assign(item, updates)
      this.renderItem(item)
    }
  }

  updateProgress(index, progress) {
    this.updateItem(index, { progress })
  }

  updateStatus(index, status, error = null) {
    const updates = { status }
    if (error) {
      updates.error = error
      updates.error_message = error  // Add for backward compatibility
    }
    this.updateItem(index, updates)
  }

  onCancelItem(callback) {
    this.onCancelItemCallback = callback
  }

  onCancelAll(callback) {
    this.onCancelAllCallback = callback
  }

  setSortBy(sortBy) {
    this.sortBy = sortBy
    this.render()
  }

  setFilterBy(filterBy) {
    this.filterBy = filterBy
    this.render()
  }

  getFilteredAndSortedItems() {
    let items = [...this.items]
    
    // Filter
    if (this.filterBy !== 'all') {
      items = items.filter(item => item.status === this.filterBy)
    }
    
    // Sort
    switch (this.sortBy) {
      case 'name':
        items.sort((a, b) => a.filename.localeCompare(b.filename))
        break
      case 'status':
        items.sort((a, b) => a.status.localeCompare(b.status))
        break
      case 'index':
      default:
        items.sort((a, b) => a.index - b.index)
        break
    }
    
    return items
  }

  render() {
    this.container.innerHTML = ''
    
    if (this.items.length === 0) {
      this.container.classList.add('hidden')
      return
    }
    
    this.container.classList.remove('hidden')
    
    // Header with controls
    const header = this.createHeader()
    this.container.appendChild(header)
    
    // Queue items container
    const queueContainer = document.createElement('div')
    queueContainer.className = 'space-y-3 max-h-96 overflow-y-auto'
    queueContainer.id = 'batch-queue-items'
    
    const items = this.getFilteredAndSortedItems()
    items.forEach(item => {
      const itemEl = this.createQueueItem(item)
      queueContainer.appendChild(itemEl)
    })
    
    this.container.appendChild(queueContainer)
  }

  renderItem(item) {
    const itemEl = document.getElementById(`queue-item-${item.index}`)
    if (itemEl) {
      const newItemEl = this.createQueueItem(item)
      itemEl.replaceWith(newItemEl)
    }
  }

  createHeader() {
    const header = document.createElement('div')
    header.className = 'flex flex-col space-y-4 mb-4'
    
    // Title and cancel all button
    const titleRow = document.createElement('div')
    titleRow.className = 'flex justify-between items-center'
    
    const title = document.createElement('h3')
    title.className = 'text-lg font-semibold'
    title.textContent = 'Conversion Queue'
    
    const cancelAllBtn = document.createElement('button')
    cancelAllBtn.className = 'text-sm text-red-600 hover:text-red-800 transition-colors font-medium'
    cancelAllBtn.textContent = 'Cancel All'
    cancelAllBtn.onclick = () => {
      if (this.onCancelAllCallback) {
        this.onCancelAllCallback()
      }
    }
    
    titleRow.appendChild(title)
    titleRow.appendChild(cancelAllBtn)
    
    // Controls row
    const controlsRow = document.createElement('div')
    controlsRow.className = 'flex space-x-4'
    
    // Sort dropdown
    const sortContainer = document.createElement('div')
    sortContainer.className = 'flex items-center space-x-2'
    
    const sortLabel = document.createElement('label')
    sortLabel.className = 'text-sm text-gray-600'
    sortLabel.textContent = 'Sort by:'
    sortLabel.setAttribute('for', 'queue-sort')
    
    const sortSelect = document.createElement('select')
    sortSelect.id = 'queue-sort'
    sortSelect.className = 'text-sm border border-gray-300 rounded px-2 py-1'
    sortSelect.innerHTML = `
      <option value="index">Order</option>
      <option value="name">Name</option>
      <option value="status">Status</option>
    `
    sortSelect.value = this.sortBy
    sortSelect.onchange = (e) => this.setSortBy(e.target.value)
    
    sortContainer.appendChild(sortLabel)
    sortContainer.appendChild(sortSelect)
    
    // Filter dropdown
    const filterContainer = document.createElement('div')
    filterContainer.className = 'flex items-center space-x-2'
    
    const filterLabel = document.createElement('label')
    filterLabel.className = 'text-sm text-gray-600'
    filterLabel.textContent = 'Filter:'
    filterLabel.setAttribute('for', 'queue-filter')
    
    const filterSelect = document.createElement('select')
    filterSelect.id = 'queue-filter'
    filterSelect.className = 'text-sm border border-gray-300 rounded px-2 py-1'
    filterSelect.innerHTML = `
      <option value="all">All</option>
      <option value="pending">Pending</option>
      <option value="processing">Processing</option>
      <option value="completed">Completed</option>
      <option value="failed">Failed</option>
    `
    filterSelect.value = this.filterBy
    filterSelect.onchange = (e) => this.setFilterBy(e.target.value)
    
    filterContainer.appendChild(filterLabel)
    filterContainer.appendChild(filterSelect)
    
    controlsRow.appendChild(sortContainer)
    controlsRow.appendChild(filterContainer)
    
    header.appendChild(titleRow)
    header.appendChild(controlsRow)
    
    // Summary stats
    const stats = this.createStats()
    header.appendChild(stats)
    
    return header
  }

  createStats() {
    const stats = document.createElement('div')
    stats.className = 'flex space-x-4 text-sm'
    
    const total = this.items.length
    const completed = this.items.filter(item => item.status === 'completed').length
    const failed = this.items.filter(item => item.status === 'failed').length
    const processing = this.items.filter(item => item.status === 'processing').length
    const pending = this.items.filter(item => item.status === 'pending').length
    
    const statItems = [
      { label: 'Total', value: total, color: 'text-gray-600' },
      { label: 'Pending', value: pending, color: 'text-gray-500' },
      { label: 'Processing', value: processing, color: 'text-blue-600' },
      { label: 'Completed', value: completed, color: 'text-green-600' },
      { label: 'Failed', value: failed, color: 'text-red-600' }
    ]
    
    statItems.forEach(stat => {
      const statEl = document.createElement('span')
      statEl.className = stat.color
      statEl.textContent = `${stat.label}: ${stat.value}`
      stats.appendChild(statEl)
    })
    
    return stats
  }

  createQueueItem(item) {
    const itemEl = document.createElement('div')
    itemEl.id = `queue-item-${item.index}`
    itemEl.className = 'bg-white border border-gray-200 rounded-lg p-4 transition-all'
    
    // Add status-specific styling
    if (item.status === 'failed') {
      itemEl.className += ' border-red-200 bg-red-50'
    } else if (item.status === 'completed') {
      itemEl.className += ' border-green-200 bg-green-50'
    } else if (item.status === 'processing') {
      itemEl.className += ' border-blue-200 bg-blue-50'
    }
    
    // Top row - filename and cancel button
    const topRow = document.createElement('div')
    topRow.className = 'flex justify-between items-start mb-2'
    
    const fileInfo = document.createElement('div')
    fileInfo.className = 'flex-1 min-w-0'
    
    const filename = document.createElement('p')
    filename.className = 'text-sm font-medium text-gray-900 truncate'
    filename.textContent = item.filename
    filename.title = item.filename
    
    const status = document.createElement('p')
    status.className = 'text-xs mt-1'
    status.className += this.getStatusColor(item.status)
    status.textContent = this.getStatusText(item.status)
    
    fileInfo.appendChild(filename)
    fileInfo.appendChild(status)
    
    // Cancel button (only for pending/processing items)
    if (item.status === 'pending' || item.status === 'processing') {
      const cancelBtn = document.createElement('button')
      cancelBtn.className = 'p-1 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors'
      cancelBtn.setAttribute('aria-label', `Cancel ${item.filename}`)
      cancelBtn.onclick = () => {
        if (this.onCancelItemCallback) {
          this.onCancelItemCallback(item.index)
        }
      }
      
      const cancelIcon = this.createCancelIcon()
      cancelBtn.appendChild(cancelIcon)
      topRow.appendChild(fileInfo)
      topRow.appendChild(cancelBtn)
    } else {
      topRow.appendChild(fileInfo)
    }
    
    itemEl.appendChild(topRow)
    
    // Progress bar (for pending/processing items)
    if (item.status === 'pending' || item.status === 'processing') {
      const progressBar = this.createProgressBar(item.progress || 0)
      itemEl.appendChild(progressBar)
    }
    
    // Error message (for failed items)
    if (item.status === 'failed' && (item.error || item.error_message)) {
      const errorMsg = document.createElement('p')
      errorMsg.className = 'text-xs text-red-600 mt-2'
      errorMsg.textContent = item.error || item.error_message
      itemEl.appendChild(errorMsg)
    }
    
    return itemEl
  }

  createProgressBar(progress) {
    const progressContainer = document.createElement('div')
    progressContainer.className = 'w-full bg-gray-200 rounded-full h-2 mt-2'
    
    const progressBar = document.createElement('div')
    progressBar.className = 'bg-blue-600 h-2 rounded-full transition-all duration-300'
    progressBar.style.width = `${progress}%`
    
    progressContainer.appendChild(progressBar)
    return progressContainer
  }

  createCancelIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-4 h-4')
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

  getStatusColor(status) {
    switch (status) {
      case 'pending':
        return ' text-gray-500'
      case 'processing':
        return ' text-blue-600'
      case 'completed':
        return ' text-green-600'
      case 'failed':
        return ' text-red-600'
      default:
        return ' text-gray-500'
    }
  }

  getStatusText(status) {
    switch (status) {
      case 'pending':
        return 'Waiting...'
      case 'processing':
        return 'Converting...'
      case 'completed':
        return 'Completed'
      case 'failed':
        return 'Failed'
      default:
        return status
    }
  }

  reset() {
    this.items = []
    this.jobId = null
    this.render()
  }
}