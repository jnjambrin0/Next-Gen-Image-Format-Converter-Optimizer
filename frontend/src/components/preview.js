import { formatFileSize } from '../utils/validators.js'

/**
 * Simple preview component for before/after image comparison
 * Based on patterns from comparisonViewer.js but simplified
 */
export function createPreview(options) {
  const { originalUrl, convertedUrl, originalSize, convertedSize, originalFilename, onClose } =
    options

  // Main container
  const container = document.createElement('div')
  container.className = 'preview-container bg-white rounded-lg shadow-lg p-6 mb-4'
  container.setAttribute('role', 'region')
  container.setAttribute('aria-label', 'Image preview comparison')

  // Header
  const header = document.createElement('div')
  header.className = 'flex items-center justify-between mb-4'

  const title = document.createElement('h3')
  title.className = 'text-lg font-semibold text-gray-900'
  title.textContent = 'Preview Results'

  const closeBtn = document.createElement('button')
  closeBtn.className = 'p-2 hover:bg-gray-100 rounded-lg transition-colors'
  closeBtn.setAttribute('aria-label', 'Close preview')
  closeBtn.innerHTML = `
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
    </svg>
  `
  closeBtn.addEventListener('click', onClose)

  header.appendChild(title)
  header.appendChild(closeBtn)

  // Images container
  const imagesContainer = document.createElement('div')
  imagesContainer.className = 'grid grid-cols-1 md:grid-cols-2 gap-4 mb-4'

  // Original image
  const originalWrapper = createImageSection(
    'Original',
    originalUrl,
    originalFilename,
    originalSize
  )
  imagesContainer.appendChild(originalWrapper)

  // Converted image
  const convertedWrapper = createImageSection(
    'Test Conversion',
    convertedUrl,
    originalFilename, // Use same filename for now
    convertedSize
  )
  imagesContainer.appendChild(convertedWrapper)

  // Size comparison
  const sizeComparison = createSizeComparison(originalSize, convertedSize)

  // Assemble container
  container.appendChild(header)
  container.appendChild(imagesContainer)
  container.appendChild(sizeComparison)

  return container
}

/**
 * Create an image section with label and size
 */
function createImageSection(label, imageUrl, filename, fileSize) {
  const wrapper = document.createElement('div')
  wrapper.className = 'bg-gray-50 rounded-lg overflow-hidden'

  const labelDiv = document.createElement('div')
  labelDiv.className = 'px-4 py-2 bg-gray-100 border-b'

  const labelText = document.createElement('h4')
  labelText.className = 'font-medium text-gray-900 text-sm'
  labelText.textContent = label

  labelDiv.appendChild(labelText)

  const imageContainer = document.createElement('div')
  imageContainer.className = 'p-4 flex items-center justify-center min-h-[200px]'

  const img = document.createElement('img')
  img.src = imageUrl
  img.alt = `${label} image`
  img.className = 'max-w-full max-h-[300px] object-contain'

  imageContainer.appendChild(img)

  // File size info
  const sizeInfo = document.createElement('div')
  sizeInfo.className = 'px-4 py-2 bg-gray-100 border-t text-sm text-gray-600 text-center'
  sizeInfo.textContent = formatFileSize(fileSize)

  wrapper.appendChild(labelDiv)
  wrapper.appendChild(imageContainer)
  wrapper.appendChild(sizeInfo)

  return wrapper
}

/**
 * Create size comparison section
 */
function createSizeComparison(originalSize, convertedSize) {
  const container = document.createElement('div')
  container.className = 'bg-blue-50 border border-blue-200 rounded-md p-4'

  const reduction = Math.round((1 - convertedSize / originalSize) * 100)
  const increased = reduction < 0

  const text = document.createElement('p')
  text.className = 'text-sm text-center'

  if (increased) {
    text.innerHTML = `
      <span class="text-gray-700">Size increased by </span>
      <span class="font-semibold text-orange-600">${Math.abs(reduction)}%</span>
      <span class="text-gray-700"> with current settings</span>
    `
  } else if (reduction > 0) {
    text.innerHTML = `
      <span class="text-gray-700">Size reduced by </span>
      <span class="font-semibold text-green-600">${reduction}%</span>
      <span class="text-gray-700"> with current settings</span>
    `
  } else {
    text.innerHTML = `<span class="text-gray-700">No size change with current settings</span>`
  }

  container.appendChild(text)
  return container
}
