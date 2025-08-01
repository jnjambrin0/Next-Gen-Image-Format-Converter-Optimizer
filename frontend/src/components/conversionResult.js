/**
 * Creates a conversion result component with file details and Convert Another button
 * @param {Object} options - Configuration options
 * @param {string} options.originalFilename - Original file name
 * @param {string} options.convertedFilename - Converted file name
 * @param {string} options.outputFormat - Output format (webp, avif, etc.)
 * @param {number} options.originalSize - Original file size in bytes
 * @param {number} options.convertedSize - Converted file size in bytes
 * @param {string} options.conversionTime - Conversion time in seconds
 * @param {Function} options.onConvertAnother - Callback when Convert Another is clicked
 * @returns {HTMLElement} The conversion result element
 */
export function createConversionResult(options) {
  const {
    originalFilename,
    convertedFilename,
    outputFormat,
    originalSize,
    convertedSize,
    conversionTime,
    onConvertAnother,
  } = options

  // Main container
  const container = document.createElement('div')
  container.className = 'bg-green-50 border border-green-200 rounded-lg p-6 mt-4'

  // Success header with icon
  const header = document.createElement('div')
  header.className = 'flex items-center mb-4'

  const successIcon = createSuccessIcon()
  const title = document.createElement('h3')
  title.className = 'text-lg font-semibold text-green-800 ml-3'
  title.textContent = 'Conversion Successful!'

  header.appendChild(successIcon)
  header.appendChild(title)

  // File details grid
  const detailsGrid = document.createElement('div')
  detailsGrid.className = 'grid grid-cols-2 gap-4 mb-6 text-sm'

  const details = [
    { label: 'Original File', value: originalFilename },
    { label: 'Converted File', value: convertedFilename },
    { label: 'Output Format', value: outputFormat.toUpperCase() },
    { label: 'Conversion Time', value: `${conversionTime}s` },
    { label: 'Original Size', value: formatFileSize(originalSize) },
    { label: 'Converted Size', value: formatFileSize(convertedSize) },
  ]

  details.forEach(({ label, value }) => {
    const detailItem = createDetailItem(label, value)
    detailsGrid.appendChild(detailItem)
  })

  // Size reduction percentage
  const reduction = calculateSizeReduction(originalSize, convertedSize)
  if (reduction > 0) {
    const reductionBadge = document.createElement('div')
    reductionBadge.className =
      'inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 mb-4'
    reductionBadge.textContent = `${reduction}% size reduction`
    detailsGrid.appendChild(reductionBadge)
  }

  // Convert Another button
  const buttonContainer = document.createElement('div')
  buttonContainer.className = 'flex justify-center'

  const convertAnotherBtn = document.createElement('button')
  convertAnotherBtn.className =
    'px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors'
  convertAnotherBtn.textContent = 'Convert Another Image'
  convertAnotherBtn.onclick = onConvertAnother

  buttonContainer.appendChild(convertAnotherBtn)

  // Assemble component
  container.appendChild(header)
  container.appendChild(detailsGrid)
  container.appendChild(buttonContainer)

  return container
}

/**
 * Creates a detail item for the grid
 * @param {string} label - The label text
 * @param {string} value - The value text
 * @returns {HTMLElement} The detail item element
 */
function createDetailItem(label, value) {
  const item = document.createElement('div')

  const labelEl = document.createElement('span')
  labelEl.className = 'text-gray-600'
  labelEl.textContent = label + ':'

  const valueEl = document.createElement('span')
  valueEl.className = 'font-medium text-gray-900 ml-2'
  valueEl.textContent = value

  item.appendChild(labelEl)
  item.appendChild(valueEl)

  return item
}

/**
 * Creates the success checkmark icon
 * @returns {SVGElement} The success icon
 */
function createSuccessIcon() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  svg.setAttribute('class', 'w-8 h-8 text-green-600')
  svg.setAttribute('fill', 'currentColor')
  svg.setAttribute('viewBox', '0 0 20 20')

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
  path.setAttribute('fill-rule', 'evenodd')
  path.setAttribute(
    'd',
    'M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z'
  )
  path.setAttribute('clip-rule', 'evenodd')

  svg.appendChild(path)
  return svg
}

/**
 * Formats file size in human-readable format
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
function formatFileSize(bytes) {
  if (bytes === 0) {
    return '0 Bytes'
  }

  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

/**
 * Calculates size reduction percentage
 * @param {number} originalSize - Original file size
 * @param {number} convertedSize - Converted file size
 * @returns {number} Size reduction percentage
 */
function calculateSizeReduction(originalSize, convertedSize) {
  if (originalSize === 0) {
    return 0
  }
  const reduction = ((originalSize - convertedSize) / originalSize) * 100
  return Math.max(0, Math.round(reduction))
}
