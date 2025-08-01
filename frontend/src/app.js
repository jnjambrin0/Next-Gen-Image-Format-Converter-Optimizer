import { DropZone } from './components/dropzone.js'
import { validateImageFile, formatFileSize } from './utils/validators.js'
import { UIStateManager, UIStates } from './utils/uiState.js'
import { createLoadingSpinner } from './components/loadingSpinner.js'
import { createErrorMessage, createSuccessMessage } from './components/uiMessages.js'
import { createAppLayout } from './components/appLayout.js'
import { UI_TIMING } from './config/constants.js'
import { convertImage, APIError, mapErrorCodeToMessage } from './services/api.js'
import { createConversionResult } from './components/conversionResult.js'

export function initializeApp() {
  const app = document.getElementById('app')

  // Clear existing content and append the new layout
  app.innerHTML = ''
  app.appendChild(createAppLayout())

  // Initialize UI state manager
  const uiStateManager = new UIStateManager()

  // Initialize dropzone
  const dropzoneElement = document.getElementById('dropzone')
  const dropzone = new DropZone(dropzoneElement, uiStateManager)

  // Track conversion time and last file for retry
  let conversionStartTime = null
  let lastFileForRetry = null
  let lastOutputFormat = 'webp'
  let lastQuality = 85

  // Handle file selection
  dropzone.onFileSelect(async (file) => {
    // File selected - log details for debugging
    // console.log('File selected:', file.name, file.type, file.size)

    // Clear previous messages
    const errorElement = document.getElementById('errorMessage')
    const fileInfoElement = document.getElementById('fileInfo')
    errorElement.classList.add('hidden')
    fileInfoElement.classList.add('hidden')

    // Validate file
    const validation = validateImageFile(file)

    if (!validation.valid) {
      // Show error message
      errorElement.innerHTML = ''
      errorElement.appendChild(createErrorMessage(validation.errors))
      errorElement.classList.remove('hidden')
      return
    }

    // Show file info
    fileInfoElement.innerHTML = ''
    fileInfoElement.appendChild(createSuccessMessage(file.name, formatFileSize(file.size)))
    fileInfoElement.classList.remove('hidden')

    // Start conversion process
    conversionStartTime = Date.now()
    uiStateManager.setState(UIStates.UPLOADING)

    // TODO: Add output format selection UI in future story
    // For now, default to WebP with quality 85
    const outputFormat = lastOutputFormat
    const quality = lastQuality

    try {
      // Update state to converting
      uiStateManager.setState(UIStates.CONVERTING)

      // Call API to convert image
      const { blob, filename } = await convertImage(file, outputFormat, quality)

      // Calculate conversion time
      const conversionTime = ((Date.now() - conversionStartTime) / 1000).toFixed(1)

      // Trigger download
      uiStateManager.setState(UIStates.DOWNLOADING)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      // Show success with conversion result component
      uiStateManager.setState(UIStates.SUCCESS)

      // Create and display conversion result
      const conversionResult = createConversionResult({
        originalFilename: file.name,
        convertedFilename: filename,
        outputFormat: outputFormat,
        originalSize: file.size,
        convertedSize: blob.size,
        conversionTime: conversionTime,
        onConvertAnother: () => {
          // Reset UI for another conversion
          uiStateManager.setState(UIStates.IDLE)
          fileInfoElement.innerHTML = ''
          fileInfoElement.classList.add('hidden')
          errorElement.classList.add('hidden')
          // Reset dropzone
          dropzone.reset()
        },
      })

      fileInfoElement.innerHTML = ''
      fileInfoElement.appendChild(conversionResult)
      fileInfoElement.classList.remove('hidden')
    } catch (error) {
      // Handle API errors
      uiStateManager.setState(UIStates.ERROR)

      // Store file for retry
      lastFileForRetry = file
      lastOutputFormat = outputFormat
      lastQuality = quality

      let errorMessage = 'Failed to convert image. '
      if (error instanceof APIError) {
        if (error.errorCode) {
          errorMessage += mapErrorCodeToMessage(error.errorCode)
        } else {
          errorMessage += error.message
        }
      } else {
        errorMessage += 'Please try again.'
        console.error('Conversion error:', error)
      }

      // Create error with retry button
      const errorContainer = document.createElement('div')
      errorContainer.appendChild(createErrorMessage([errorMessage]))

      // Add retry button
      const retryButton = document.createElement('button')
      retryButton.className =
        'mt-3 px-4 py-2 bg-red-600 text-white font-medium rounded hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2'
      retryButton.textContent = 'Retry Conversion'
      retryButton.onclick = () => {
        if (lastFileForRetry) {
          // Clear error and retry
          errorElement.classList.add('hidden')
          dropzone.onFileSelect()(lastFileForRetry)
        }
      }
      errorContainer.appendChild(retryButton)

      errorElement.innerHTML = ''
      errorElement.appendChild(errorContainer)
      errorElement.classList.remove('hidden')

      // Reset to idle after error
      setTimeout(() => {
        uiStateManager.setState(UIStates.IDLE)
      }, UI_TIMING.ERROR_MESSAGE_DURATION)
    }
  })

  // Handle UI state changes
  uiStateManager.onStateChange((newState, _oldState) => {
    const dropzoneContent = dropzoneElement.querySelector('p')

    switch (newState) {
      case UIStates.IDLE:
        dropzoneContent.textContent = 'Drag and drop images here, or click to select'
        dropzoneElement.classList.remove('opacity-50', 'pointer-events-none')
        break

      case UIStates.DRAGGING:
        dropzoneContent.textContent = 'Drop your image here'
        break

      case UIStates.PROCESSING:
      case UIStates.UPLOADING: {
        dropzoneContent.textContent = ''
        dropzoneElement.classList.add('opacity-50', 'pointer-events-none')
        // Remove any existing spinner
        const existingSpinner =
          dropzoneElement.querySelector('.animate-spin')?.parentElement?.parentElement
        if (existingSpinner) {
          existingSpinner.remove()
        }
        // Add loading spinner with status text
        const spinner = createLoadingSpinner('Uploading image...')
        dropzoneElement.appendChild(spinner)
        break
      }

      case UIStates.CONVERTING: {
        dropzoneContent.textContent = ''
        // Update spinner text
        const existingSpinner =
          dropzoneElement.querySelector('.animate-spin')?.parentElement?.parentElement
        if (existingSpinner) {
          const textElement = existingSpinner.querySelector('p')
          if (textElement) {
            textElement.textContent = 'Converting image...'
          }
        }
        break
      }

      case UIStates.DOWNLOADING: {
        dropzoneContent.textContent = ''
        // Update spinner text
        const existingSpinner =
          dropzoneElement.querySelector('.animate-spin')?.parentElement?.parentElement
        if (existingSpinner) {
          const textElement = existingSpinner.querySelector('p')
          if (textElement) {
            textElement.textContent = 'Preparing download...'
          }
        }
        break
      }

      case UIStates.SUCCESS: {
        // Remove spinner if exists
        const existingSpinner =
          dropzoneElement.querySelector('.animate-spin')?.parentElement?.parentElement
        if (existingSpinner) {
          existingSpinner.remove()
        }
        dropzoneContent.textContent = 'Image processed successfully!'
        dropzoneElement.classList.remove('opacity-50', 'pointer-events-none')
        break
      }

      case UIStates.ERROR: {
        // Remove spinner if exists
        const existingSpinner =
          dropzoneElement.querySelector('.animate-spin')?.parentElement?.parentElement
        if (existingSpinner) {
          existingSpinner.remove()
        }
        dropzoneContent.textContent = 'Error processing image. Please try again.'
        dropzoneElement.classList.remove('opacity-50', 'pointer-events-none')
        break
      }
    }
  })

  // App initialized successfully
  // console.log('Image Converter app initialized')
}
