/**
 * Creates the main application layout structure
 * @returns {HTMLElement} The complete app layout
 */
export function createAppLayout() {
  // Main container
  const container = document.createElement('div')
  container.className = 'min-h-screen bg-gray-50'

  // Header
  const header = createHeader()
  container.appendChild(header)

  // Main content
  const main = createMainContent()
  container.appendChild(main)

  return container
}

function createHeader() {
  const header = document.createElement('header')
  header.className = 'bg-white shadow-sm border-b border-gray-200'

  const headerInner = document.createElement('div')
  headerInner.className = 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6'

  const flexContainer = document.createElement('div')
  flexContainer.className = 'flex items-center justify-between'

  // Left side - Title
  const titleContainer = document.createElement('div')

  const h1 = document.createElement('h1')
  h1.className = 'text-3xl font-bold text-gray-900'
  h1.textContent = 'Image Converter'

  const subtitle = document.createElement('p')
  subtitle.className = 'text-sm text-gray-600 mt-1'
  subtitle.textContent = 'Privacy-first local image processing'

  titleContainer.appendChild(h1)
  titleContainer.appendChild(subtitle)

  // Right side - Status badge and API management
  const badgeContainer = document.createElement('div')
  badgeContainer.className = 'flex items-center space-x-3'

  // API management button
  const apiButton = document.createElement('button')
  apiButton.id = 'apiManagementBtn'
  apiButton.className =
    'inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500'
  apiButton.innerHTML = `
    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
    </svg>
    API Keys
  `
  apiButton.title = 'Manage API Keys'
  badgeContainer.appendChild(apiButton)

  const badge = document.createElement('span')
  badge.className =
    'inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800'

  const badgeDot = document.createElement('span')
  badgeDot.className = 'w-2 h-2 bg-green-400 rounded-full mr-2'

  const badgeText = document.createTextNode('100% Local')

  badge.appendChild(badgeDot)
  badge.appendChild(badgeText)
  badgeContainer.appendChild(badge)

  flexContainer.appendChild(titleContainer)
  flexContainer.appendChild(badgeContainer)
  headerInner.appendChild(flexContainer)
  header.appendChild(headerInner)

  return header
}

function createMainContent() {
  const main = document.createElement('main')
  main.className = 'unified-layout-container'

  // Create the flex container for consistent layout
  const layoutWrapper = document.createElement('div')
  layoutWrapper.className = 'unified-layout-wrapper'

  // Main content area (left side) - for dropzone/file list
  const contentArea = document.createElement('div')
  contentArea.className = 'unified-content-area'
  contentArea.id = 'mainContentArea'

  const uploadCard = createUploadCard()
  contentArea.appendChild(uploadCard)

  // Settings panel (right side) - fixed position
  const settingsPanel = document.createElement('aside')
  settingsPanel.className = 'unified-settings-sidebar'
  settingsPanel.id = 'settingsSidebar'

  // Settings card placeholder
  const settingsCard = document.createElement('div')
  settingsCard.id = 'conversionSettings'
  settingsCard.className = 'unified-settings-container'

  const featuresCard = createFeaturesCard()

  settingsPanel.appendChild(settingsCard)
  settingsPanel.appendChild(featuresCard)

  // Append both areas to the layout wrapper
  layoutWrapper.appendChild(contentArea)
  layoutWrapper.appendChild(settingsPanel)
  main.appendChild(layoutWrapper)

  return main
}

function createUploadCard() {
  const card = document.createElement('div')
  card.className = 'card'

  const h2 = document.createElement('h2')
  h2.className = 'text-xl font-semibold mb-6'
  h2.textContent = 'Upload Image'

  // Dropzone
  const dropzone = createDropzone()

  // Error message container
  const errorMessage = document.createElement('div')
  errorMessage.id = 'errorMessage'
  errorMessage.className = 'mt-4 hidden'
  errorMessage.setAttribute('role', 'alert')

  // File info container
  const fileInfo = document.createElement('div')
  fileInfo.id = 'fileInfo'
  fileInfo.className = 'mt-4 hidden'

  // File list preview container
  const fileListContainer = document.createElement('div')
  fileListContainer.id = 'fileListPreview'
  fileListContainer.className = 'mt-4 hidden'

  card.appendChild(h2)
  card.appendChild(dropzone)
  card.appendChild(errorMessage)
  card.appendChild(fileInfo)
  card.appendChild(fileListContainer)

  return card
}

function createDropzone() {
  const dropzone = document.createElement('div')
  dropzone.className = 'dropzone min-h-[200px] flex flex-col items-center justify-center'
  dropzone.id = 'dropzone'
  dropzone.setAttribute('role', 'button')
  dropzone.setAttribute('tabindex', '0')
  dropzone.setAttribute(
    'aria-label',
    'Image upload area. Drag and drop images here or press Enter to select files'
  )

  // Hidden file input
  const fileInput = document.createElement('input')
  fileInput.type = 'file'
  fileInput.id = 'fileInput'
  fileInput.className = 'sr-only'
  fileInput.accept = 'image/*'
  fileInput.multiple = true
  fileInput.setAttribute('aria-label', 'File input for image selection')

  // Upload icon
  const icon = createUploadIcon()

  // Instructions
  const instructions = document.createElement('p')
  instructions.className = 'text-gray-600 pointer-events-none'
  instructions.textContent = 'Drag and drop images or folders here, or click to select'

  const formats = document.createElement('p')
  formats.className = 'text-sm text-gray-500 mt-2 pointer-events-none'
  formats.textContent = 'Supported formats: JPEG, PNG, WebP, HEIF/HEIC, BMP, TIFF, GIF, AVIF'

  const limits = document.createElement('p')
  limits.className = 'text-xs text-gray-400 mt-1 pointer-events-none'
  limits.textContent = 'Maximum: 100 files, 50MB per file'

  dropzone.appendChild(fileInput)
  dropzone.appendChild(icon)
  dropzone.appendChild(instructions)
  dropzone.appendChild(formats)
  dropzone.appendChild(limits)

  return dropzone
}

function createUploadIcon() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  svg.setAttribute('class', 'w-12 h-12 text-gray-400 mb-4 pointer-events-none')
  svg.setAttribute('fill', 'none')
  svg.setAttribute('stroke', 'currentColor')
  svg.setAttribute('viewBox', '0 0 24 24')

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
  path.setAttribute('stroke-linecap', 'round')
  path.setAttribute('stroke-linejoin', 'round')
  path.setAttribute('stroke-width', '2')
  path.setAttribute(
    'd',
    'M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12'
  )

  svg.appendChild(path)
  return svg
}

function createFeaturesCard() {
  const card = document.createElement('div')
  card.className = 'card'

  const h3 = document.createElement('h3')
  h3.className = 'text-lg font-semibold mb-4'
  h3.textContent = 'Features'

  const featuresList = document.createElement('ul')
  featuresList.className = 'space-y-3 text-sm'

  const features = [
    '100% local processing - no uploads',
    'Privacy-first design',
    'Support for modern formats',
    'Automatic EXIF removal',
  ]

  features.forEach((feature) => {
    const li = createFeatureItem(feature)
    featuresList.appendChild(li)
  })

  card.appendChild(h3)
  card.appendChild(featuresList)

  return card
}

function createFeatureItem(text) {
  const li = document.createElement('li')
  li.className = 'flex items-start'

  // Check icon
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  svg.setAttribute('class', 'w-5 h-5 text-green-500 mr-2 flex-shrink-0')
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

  const span = document.createElement('span')
  span.textContent = text

  li.appendChild(svg)
  li.appendChild(span)

  return li
}
