import { formatFileSize, calculateSizeReduction } from '../utils/validators.js'

// CSS class constants for better performance and maintainability
const CLASSES = {
  sideBySide: 'grid grid-cols-1 md:grid-cols-2 gap-4 max-w-full',
  single: 'flex justify-center',
  hidden: 'hidden',
}

/**
 * Creates a comparison viewer component for side-by-side image comparison
 * @param {Object} options - Configuration options
 * @param {string} options.originalUrl - Object URL for original image
 * @param {string} options.convertedUrl - Object URL for converted image
 * @param {number} options.originalSize - Original file size in bytes
 * @param {number} options.convertedSize - Converted file size in bytes
 * @param {string} options.originalFilename - Original filename
 * @param {string} options.convertedFilename - Converted filename
 * @param {Function} options.onClose - Callback when viewer is closed
 * @returns {HTMLElement} The comparison viewer element
 */
export function createComparisonViewer(options) {
  const {
    originalUrl,
    convertedUrl,
    originalSize,
    convertedSize,
    originalFilename,
    convertedFilename,
    onClose,
  } = options

  // Track current view mode
  let viewMode = 'side-by-side' // 'side-by-side' or 'single'
  let currentImage = 'converted' // which image to show in single view

  // Main container
  const container = document.createElement('div')
  container.className =
    'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4'
  container.setAttribute('role', 'dialog')
  container.setAttribute('aria-modal', 'true')
  container.setAttribute('aria-labelledby', 'comparison-viewer-title')

  // Modal content
  const modal = document.createElement('div')
  modal.className = 'bg-white rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] flex flex-col'

  // Header
  const header = createHeader(onClose)
  modal.appendChild(header)

  // Controls
  const controls = createControls()
  modal.appendChild(controls)

  // Image container
  const imageContainer = document.createElement('div')
  imageContainer.className = 'flex-1 overflow-auto p-6 bg-gray-50'

  const imagesWrapper = document.createElement('div')
  imagesWrapper.className = CLASSES.sideBySide

  // Original image
  const originalWrapper = createImageWrapper('Original', originalUrl, originalFilename)
  imagesWrapper.appendChild(originalWrapper)

  // Converted image
  const convertedWrapper = createImageWrapper('Converted', convertedUrl, convertedFilename)
  imagesWrapper.appendChild(convertedWrapper)

  imageContainer.appendChild(imagesWrapper)
  modal.appendChild(imageContainer)

  // File size metrics
  const metrics = createMetrics(originalSize, convertedSize)
  modal.appendChild(metrics)

  // Event handlers
  function updateView() {
    // Use className assignment for better performance
    imagesWrapper.className = viewMode === 'side-by-side' ? CLASSES.sideBySide : CLASSES.single

    if (viewMode === 'side-by-side') {
      // Show both images
      originalWrapper.classList.remove(CLASSES.hidden)
      convertedWrapper.classList.remove(CLASSES.hidden)
    } else {
      // Toggle visibility based on selected image
      const showOriginal = currentImage === 'original'
      originalWrapper.classList.toggle(CLASSES.hidden, !showOriginal)
      convertedWrapper.classList.toggle(CLASSES.hidden, showOriginal)
    }
  }

  // Toggle button handler
  const toggleBtn = controls.querySelector('[data-toggle-view]')
  toggleBtn.addEventListener('click', () => {
    viewMode = viewMode === 'side-by-side' ? 'single' : 'side-by-side'
    toggleBtn.textContent = viewMode === 'side-by-side' ? 'Single View' : 'Side-by-Side'
    toggleBtn.setAttribute('aria-pressed', viewMode === 'single' ? 'true' : 'false')

    // Show/hide image selector
    const selector = controls.querySelector('[data-image-selector]')
    selector.classList.toggle('hidden', viewMode === 'side-by-side')

    updateView()
  })

  // Image selector handler
  const imageSelector = controls.querySelector('[data-image-selector]')
  imageSelector.addEventListener('change', (e) => {
    currentImage = e.target.value
    updateView()
  })

  // Close on backdrop click
  container.addEventListener('click', (e) => {
    if (e.target === container) {
      onClose()
    }
  })

  // Close on Escape key
  const handleEscape = (e) => {
    if (e.key === 'Escape') {
      onClose()
      document.removeEventListener('keydown', handleEscape)
    }
  }
  document.addEventListener('keydown', handleEscape)

  container.appendChild(modal)

  // Focus management - focus the close button when modal opens
  setTimeout(() => {
    const closeBtn = container.querySelector('button[aria-label="Close comparison viewer"]')
    if (closeBtn) {
      closeBtn.focus()
    }
  }, 100)

  return container
}

/**
 * Creates the header section
 */
function createHeader(onClose) {
  const header = document.createElement('div')
  header.className = 'flex items-center justify-between p-6 border-b'

  const title = document.createElement('h2')
  title.className = 'text-xl font-semibold text-gray-900'
  title.textContent = 'Image Comparison'
  title.id = 'comparison-viewer-title'

  const closeBtn = document.createElement('button')
  closeBtn.className = 'p-2 hover:bg-gray-100 rounded-lg transition-colors'
  closeBtn.setAttribute('aria-label', 'Close comparison viewer')
  closeBtn.innerHTML = `
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
    </svg>
  `
  closeBtn.addEventListener('click', onClose)

  header.appendChild(title)
  header.appendChild(closeBtn)

  return header
}

/**
 * Creates the controls section
 */
function createControls() {
  const controls = document.createElement('div')
  controls.className = 'flex items-center justify-center gap-4 p-4 border-b bg-gray-50'

  // Toggle view button
  const toggleBtn = document.createElement('button')
  toggleBtn.className =
    'px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors'
  toggleBtn.textContent = 'Single View'
  toggleBtn.setAttribute('data-toggle-view', '')
  toggleBtn.setAttribute('aria-label', 'Toggle between side-by-side and single view')
  toggleBtn.setAttribute('aria-pressed', 'false')

  // Image selector (hidden by default)
  const selector = document.createElement('select')
  selector.className =
    'hidden px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500'
  selector.setAttribute('data-image-selector', '')
  selector.setAttribute('aria-label', 'Select image to view')
  selector.innerHTML = `
    <option value="converted">Converted Image</option>
    <option value="original">Original Image</option>
  `

  controls.appendChild(toggleBtn)
  controls.appendChild(selector)

  return controls
}

/**
 * Creates an image wrapper with label
 */
function createImageWrapper(label, imageUrl, filename) {
  const wrapper = document.createElement('div')
  wrapper.className = 'bg-white rounded-lg shadow-sm overflow-hidden'

  const labelDiv = document.createElement('div')
  labelDiv.className = 'px-4 py-3 bg-gray-100 border-b'

  const labelText = document.createElement('h3')
  labelText.className = 'font-medium text-gray-900'
  labelText.textContent = label

  const filenameText = document.createElement('p')
  filenameText.className = 'text-sm text-gray-600 truncate'
  filenameText.textContent = filename
  filenameText.title = filename

  labelDiv.appendChild(labelText)
  labelDiv.appendChild(filenameText)

  const imageContainer = document.createElement('div')
  imageContainer.className = 'p-4 flex items-center justify-center min-h-[200px] bg-gray-50'

  const img = document.createElement('img')
  img.src = imageUrl
  img.alt = `${label} image`
  img.className = 'max-w-full max-h-[60vh] object-contain'

  imageContainer.appendChild(img)
  wrapper.appendChild(labelDiv)
  wrapper.appendChild(imageContainer)

  return wrapper
}

/**
 * Creates the metrics section
 */
function createMetrics(originalSize, convertedSize) {
  const metrics = document.createElement('div')
  metrics.className = 'p-6 border-t bg-gray-50'

  const grid = document.createElement('div')
  grid.className = 'grid grid-cols-1 sm:grid-cols-3 gap-4 text-center'

  // Original size
  const originalMetric = createMetricItem('Original Size', formatFileSize(originalSize))
  grid.appendChild(originalMetric)

  // Converted size
  const convertedMetric = createMetricItem('Converted Size', formatFileSize(convertedSize))
  grid.appendChild(convertedMetric)

  // Size reduction
  const reduction = calculateSizeReduction(originalSize, convertedSize)
  const reductionMetric = createMetricItem(
    'Size Reduction',
    reduction > 0 ? `${reduction}% saved` : 'No reduction',
    reduction > 0 ? 'text-green-600' : 'text-gray-600'
  )
  grid.appendChild(reductionMetric)

  metrics.appendChild(grid)
  return metrics
}

/**
 * Creates a metric item
 */
function createMetricItem(label, value, valueClass = 'text-gray-900') {
  const item = document.createElement('div')

  const labelEl = document.createElement('p')
  labelEl.className = 'text-sm text-gray-600 mb-1'
  labelEl.textContent = label

  const valueEl = document.createElement('p')
  valueEl.className = `text-lg font-semibold ${valueClass}`
  valueEl.textContent = value

  item.appendChild(labelEl)
  item.appendChild(valueEl)

  return item
}
