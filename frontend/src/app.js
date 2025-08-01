import { DropZone } from './components/dropzone.js'
import { validateImageFile, formatFileSize } from './utils/validators.js'
import { UIStateManager, UIStates } from './utils/uiState.js'
import { createLoadingSpinner } from './components/loadingSpinner.js'
import { createErrorMessage, createSuccessMessage } from './components/uiMessages.js'
import { createAppLayout } from './components/appLayout.js'
import { UI_TIMING } from './config/constants.js'

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

  // Handle file selection
  dropzone.onFileSelect((file) => {
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

    // Set processing state
    uiStateManager.setState(UIStates.PROCESSING)

    // Simulate processing for now (will be replaced with actual API call)
    setTimeout(() => {
      uiStateManager.setState(UIStates.SUCCESS)

      // Reset to idle after showing success
      setTimeout(() => {
        uiStateManager.setState(UIStates.IDLE)
      }, UI_TIMING.SUCCESS_MESSAGE_DURATION)
    }, UI_TIMING.PROCESSING_SIMULATION)
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

      case UIStates.PROCESSING: {
        dropzoneContent.textContent = 'Processing image...'
        dropzoneElement.classList.add('opacity-50', 'pointer-events-none')
        // Add loading spinner
        const spinner = createLoadingSpinner()
        dropzoneElement.appendChild(spinner)
        break
      }

      case UIStates.SUCCESS: {
        // Remove spinner if exists
        const existingSpinner = dropzoneElement.querySelector('.animate-spin')?.parentElement
        if (existingSpinner) {
          existingSpinner.remove()
        }
        dropzoneContent.textContent = 'Image processed successfully!'
        break
      }

      case UIStates.ERROR:
        dropzoneContent.textContent = 'Error processing image. Please try again.'
        dropzoneElement.classList.remove('opacity-50', 'pointer-events-none')
        break
    }
  })

  // App initialized successfully
  // console.log('Image Converter app initialized')
}
