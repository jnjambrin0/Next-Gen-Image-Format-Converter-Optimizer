/**
 * Batch summary report display component
 */

export class BatchSummaryModal {
  constructor() {
    this.modal = null
    this.jobId = null
    this.results = null
    this.onRetryCallback = null
    this.onCloseCallback = null
    this.onDownloadCallback = null
  }

  show(jobId, results) {
    this.jobId = jobId
    this.results = results
    this.render()
    document.body.appendChild(this.modal)

    // Focus management for accessibility
    const firstButton = this.modal.querySelector('button')
    if (firstButton) {
      firstButton.focus()
    }
  }

  hide() {
    if (this.modal && this.modal.parentNode) {
      this.modal.parentNode.removeChild(this.modal)
      this.modal = null
    }

    if (this.onCloseCallback) {
      this.onCloseCallback()
    }
  }

  onRetry(callback) {
    this.onRetryCallback = callback
  }

  onClose(callback) {
    this.onCloseCallback = callback
  }

  onDownload(callback) {
    this.onDownloadCallback = callback
  }

  render() {
    // Create modal container
    this.modal = document.createElement('div')
    this.modal.className = 'fixed inset-0 z-50 overflow-y-auto'
    this.modal.setAttribute('role', 'dialog')
    this.modal.setAttribute('aria-modal', 'true')
    this.modal.setAttribute('aria-labelledby', 'summary-modal-title')

    // Backdrop
    const backdrop = document.createElement('div')
    backdrop.className = 'fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity'
    backdrop.onclick = () => this.hide()

    // Modal content container
    const container = document.createElement('div')
    container.className = 'flex min-h-full items-center justify-center p-4'

    // Modal panel
    const panel = document.createElement('div')
    panel.className =
      'relative bg-white rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-hidden'
    panel.onclick = (e) => e.stopPropagation()

    // Header
    const header = this.createHeader()
    panel.appendChild(header)

    // Content
    const content = document.createElement('div')
    content.className = 'p-6 overflow-y-auto max-h-[calc(90vh-200px)]'

    // Statistics
    const stats = this.createStatistics()
    content.appendChild(stats)

    // Results table
    const resultsSection = this.createResultsTable()
    content.appendChild(resultsSection)

    // Charts (if data available)
    if (this.results.processing_time_seconds) {
      const charts = this.createCharts()
      content.appendChild(charts)
    }

    panel.appendChild(content)

    // Footer with actions
    const footer = this.createFooter()
    panel.appendChild(footer)

    container.appendChild(panel)
    this.modal.appendChild(backdrop)
    this.modal.appendChild(container)
  }

  createHeader() {
    const header = document.createElement('div')
    header.className = 'bg-gray-50 px-6 py-4 border-b border-gray-200'

    const flexContainer = document.createElement('div')
    flexContainer.className = 'flex items-center justify-between'

    const title = document.createElement('h2')
    title.id = 'summary-modal-title'
    title.className = 'text-xl font-semibold text-gray-900'
    title.textContent = 'Batch Conversion Summary'

    const closeButton = document.createElement('button')
    closeButton.className = 'text-gray-400 hover:text-gray-600 transition-colors'
    closeButton.setAttribute('aria-label', 'Close summary')
    closeButton.onclick = () => this.hide()

    const closeIcon = this.createCloseIcon()
    closeButton.appendChild(closeIcon)

    flexContainer.appendChild(title)
    flexContainer.appendChild(closeButton)
    header.appendChild(flexContainer)

    return header
  }

  createStatistics() {
    const statsContainer = document.createElement('div')
    statsContainer.className = 'mb-6'

    const title = document.createElement('h3')
    title.className = 'text-lg font-medium text-gray-900 mb-4'
    title.textContent = 'Processing Statistics'

    const statsGrid = document.createElement('div')
    statsGrid.className = 'grid grid-cols-2 md:grid-cols-4 gap-4'

    const totalFiles = this.results.total_files || 0
    const successfulFiles = this.results.successful_files?.length || 0
    const failedFiles = this.results.failed_files?.length || 0
    const successRate = totalFiles > 0 ? Math.round((successfulFiles / totalFiles) * 100) : 0
    const processingTime = this.formatTime(this.results.processing_time_seconds || 0)

    const stats = [
      { label: 'Total Files', value: totalFiles, color: 'text-gray-900' },
      { label: 'Successful', value: successfulFiles, color: 'text-green-600' },
      { label: 'Failed', value: failedFiles, color: 'text-red-600' },
      { label: 'Success Rate', value: `${successRate}%`, color: 'text-blue-600' },
    ]

    stats.forEach((stat) => {
      const statCard = this.createStatCard(stat.label, stat.value, stat.color)
      statsGrid.appendChild(statCard)
    })

    statsContainer.appendChild(title)
    statsContainer.appendChild(statsGrid)

    // Processing time
    const timeContainer = document.createElement('div')
    timeContainer.className = 'mt-4 text-sm text-gray-600'
    timeContainer.textContent = `Total processing time: ${processingTime}`
    statsContainer.appendChild(timeContainer)

    return statsContainer
  }

  createStatCard(label, value, colorClass) {
    const card = document.createElement('div')
    card.className = 'bg-gray-50 rounded-lg p-4 text-center'

    const valueEl = document.createElement('div')
    valueEl.className = `text-2xl font-bold ${colorClass}`
    valueEl.textContent = value

    const labelEl = document.createElement('div')
    labelEl.className = 'text-sm text-gray-600 mt-1'
    labelEl.textContent = label

    card.appendChild(valueEl)
    card.appendChild(labelEl)

    return card
  }

  createResultsTable() {
    const section = document.createElement('div')
    section.className = 'mb-6'

    const title = document.createElement('h3')
    title.className = 'text-lg font-medium text-gray-900 mb-4'
    title.textContent = 'Detailed Results'

    // Successful files
    if (this.results.successful_files?.length > 0) {
      const successSection = document.createElement('div')
      successSection.className = 'mb-4'

      const successTitle = document.createElement('h4')
      successTitle.className = 'text-sm font-medium text-green-700 mb-2'
      successTitle.textContent = 'Successfully Converted'

      const successTable = this.createSuccessTable()

      successSection.appendChild(successTitle)
      successSection.appendChild(successTable)
      section.appendChild(successSection)
    }

    // Failed files
    if (this.results.failed_files?.length > 0) {
      const failedSection = document.createElement('div')

      const failedTitle = document.createElement('h4')
      failedTitle.className = 'text-sm font-medium text-red-700 mb-2'
      failedTitle.textContent = 'Failed Conversions'

      const failedTable = this.createFailedTable()

      failedSection.appendChild(failedTitle)
      failedSection.appendChild(failedTable)
      section.appendChild(failedSection)
    }

    section.appendChild(title)

    return section
  }

  createSuccessTable() {
    const tableContainer = document.createElement('div')
    tableContainer.className = 'overflow-x-auto'

    const table = document.createElement('table')
    table.className = 'min-w-full divide-y divide-gray-200'

    // Header
    const thead = document.createElement('thead')
    thead.className = 'bg-gray-50'

    const headerRow = document.createElement('tr')
    const headers = ['File Name', 'Original Size', 'Output Size', 'Reduction']

    headers.forEach((headerText) => {
      const th = document.createElement('th')
      th.className =
        'px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider'
      th.textContent = headerText
      headerRow.appendChild(th)
    })

    thead.appendChild(headerRow)
    table.appendChild(thead)

    // Body
    const tbody = document.createElement('tbody')
    tbody.className = 'bg-white divide-y divide-gray-200'

    this.results.successful_files.forEach((file) => {
      const row = document.createElement('tr')
      row.className = 'hover:bg-gray-50'

      // Filename
      const filenameCell = document.createElement('td')
      filenameCell.className = 'px-4 py-2 text-sm text-gray-900 truncate max-w-xs'
      filenameCell.textContent = file.filename
      filenameCell.title = file.filename

      // Original size (estimate)
      const originalCell = document.createElement('td')
      originalCell.className = 'px-4 py-2 text-sm text-gray-600'
      originalCell.textContent = '-'

      // Output size
      const outputCell = document.createElement('td')
      outputCell.className = 'px-4 py-2 text-sm text-gray-600'
      outputCell.textContent = this.formatFileSize(file.output_size || 0)

      // Reduction
      const reductionCell = document.createElement('td')
      reductionCell.className = 'px-4 py-2 text-sm text-green-600'
      reductionCell.textContent = '-'

      row.appendChild(filenameCell)
      row.appendChild(originalCell)
      row.appendChild(outputCell)
      row.appendChild(reductionCell)

      tbody.appendChild(row)
    })

    table.appendChild(tbody)
    tableContainer.appendChild(table)

    return tableContainer
  }

  createFailedTable() {
    const tableContainer = document.createElement('div')
    tableContainer.className = 'overflow-x-auto'

    const table = document.createElement('table')
    table.className = 'min-w-full divide-y divide-gray-200'

    // Header
    const thead = document.createElement('thead')
    thead.className = 'bg-gray-50'

    const headerRow = document.createElement('tr')
    const headers = ['File Name', 'Error']

    headers.forEach((headerText) => {
      const th = document.createElement('th')
      th.className =
        'px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider'
      th.textContent = headerText
      headerRow.appendChild(th)
    })

    thead.appendChild(headerRow)
    table.appendChild(thead)

    // Body
    const tbody = document.createElement('tbody')
    tbody.className = 'bg-white divide-y divide-gray-200'

    this.results.failed_files.forEach((file) => {
      const row = document.createElement('tr')
      row.className = 'hover:bg-gray-50'

      // Filename
      const filenameCell = document.createElement('td')
      filenameCell.className = 'px-4 py-2 text-sm text-gray-900 truncate max-w-xs'
      filenameCell.textContent = file.filename
      filenameCell.title = file.filename

      // Error
      const errorCell = document.createElement('td')
      errorCell.className = 'px-4 py-2 text-sm text-red-600'
      errorCell.textContent = file.error || 'Unknown error'

      row.appendChild(filenameCell)
      row.appendChild(errorCell)

      tbody.appendChild(row)
    })

    table.appendChild(tbody)
    tableContainer.appendChild(table)

    return tableContainer
  }

  createCharts() {
    const chartsContainer = document.createElement('div')
    chartsContainer.className = 'mb-6'

    const title = document.createElement('h3')
    title.className = 'text-lg font-medium text-gray-900 mb-4'
    title.textContent = 'Visual Summary'

    // Simple bar chart for success/fail ratio
    const chartContainer = document.createElement('div')
    chartContainer.className = 'bg-gray-50 rounded-lg p-4'

    const successCount = this.results.successful_files?.length || 0
    const failedCount = this.results.failed_files?.length || 0
    const total = successCount + failedCount

    if (total > 0) {
      const successPercent = (successCount / total) * 100
      const failedPercent = (failedCount / total) * 100

      const barContainer = document.createElement('div')
      barContainer.className = 'relative h-8 bg-gray-200 rounded-full overflow-hidden'

      const successBar = document.createElement('div')
      successBar.className = 'absolute left-0 top-0 h-full bg-green-500'
      successBar.style.width = `${successPercent}%`

      const failedBar = document.createElement('div')
      failedBar.className = 'absolute right-0 top-0 h-full bg-red-500'
      failedBar.style.width = `${failedPercent}%`

      barContainer.appendChild(successBar)
      barContainer.appendChild(failedBar)

      chartContainer.appendChild(barContainer)

      // Legend
      const legend = document.createElement('div')
      legend.className = 'flex justify-center space-x-6 mt-4 text-sm'

      const successLegend = document.createElement('div')
      successLegend.className = 'flex items-center'
      successLegend.innerHTML = `
        <span class="w-3 h-3 bg-green-500 rounded-full mr-2"></span>
        <span>Successful (${successCount})</span>
      `

      const failedLegend = document.createElement('div')
      failedLegend.className = 'flex items-center'
      failedLegend.innerHTML = `
        <span class="w-3 h-3 bg-red-500 rounded-full mr-2"></span>
        <span>Failed (${failedCount})</span>
      `

      legend.appendChild(successLegend)
      legend.appendChild(failedLegend)
      chartContainer.appendChild(legend)
    }

    chartsContainer.appendChild(title)
    chartsContainer.appendChild(chartContainer)

    return chartsContainer
  }

  createFooter() {
    const footer = document.createElement('div')
    footer.className = 'bg-gray-50 px-6 py-4 border-t border-gray-200'

    const buttonContainer = document.createElement('div')
    buttonContainer.className = 'flex justify-between'

    // Left side - retry button
    const leftContainer = document.createElement('div')

    if (this.results.failed_files?.length > 0) {
      const retryButton = document.createElement('button')
      retryButton.className =
        'px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500'
      retryButton.textContent = `Retry Failed Files (${this.results.failed_files.length})`
      retryButton.onclick = () => {
        if (this.onRetryCallback) {
          this.onRetryCallback(this.results.failed_files)
        }
        this.hide()
      }
      leftContainer.appendChild(retryButton)
    }

    // Right side - download and close buttons
    const rightContainer = document.createElement('div')
    rightContainer.className = 'flex space-x-3'

    // Download button
    const downloadButton = document.createElement('button')
    downloadButton.className =
      'px-4 py-2 text-sm font-medium text-white bg-green-600 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500'
    downloadButton.innerHTML = `
      <span class="flex items-center">
        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"></path>
        </svg>
        Download Results
      </span>
    `
    downloadButton.onclick = () => {
      if (this.onDownloadCallback) {
        this.onDownloadCallback(this.jobId)
      }
    }

    // Close button
    const closeButton = document.createElement('button')
    closeButton.className =
      'px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500'
    closeButton.textContent = 'Close'
    closeButton.onclick = () => this.hide()

    rightContainer.appendChild(downloadButton)
    rightContainer.appendChild(closeButton)

    buttonContainer.appendChild(leftContainer)
    buttonContainer.appendChild(rightContainer)
    footer.appendChild(buttonContainer)

    return footer
  }

  createCloseIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('class', 'w-6 h-6')
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

  formatTime(seconds) {
    if (seconds < 60) {
      return `${seconds.toFixed(1)} seconds`
    }

    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60

    if (minutes < 60) {
      return `${minutes}m ${remainingSeconds.toFixed(0)}s`
    }

    const hours = Math.floor(minutes / 60)
    const remainingMinutes = minutes % 60
    return `${hours}h ${remainingMinutes}m`
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
}
