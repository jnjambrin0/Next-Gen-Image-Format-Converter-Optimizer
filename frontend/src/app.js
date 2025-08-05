import { DropZone } from './components/dropzone.js'
import { validateImageFile, formatFileSize } from './utils/validators.js'
import { UIStateManager, UIStates } from './utils/uiState.js'
import { createLoadingSpinner } from './components/loadingSpinner.js'
import { createErrorMessage, createSuccessMessage } from './components/uiMessages.js'
import { createAppLayout } from './components/appLayout.js'
import { UI_TIMING } from './config/constants.js'
import { convertImage, APIError, mapErrorCodeToMessage } from './services/api.js'
import { createConversionResult } from './components/conversionResult.js'

// Batch processing components
import { FileListPreview } from './components/fileListPreview.js'
import { BatchQueueComponent } from './components/batchQueue.js'
import { BatchPresetSelector } from './components/batchPresetSelector.js'
import { WebSocketService } from './services/websocket.js'
import { createBatchJob, getBatchStatus, downloadBatchResults } from './services/batchApi.js'

// Conversion settings
import { ConversionSettings } from './components/conversionSettings.js'

export function initializeApp() {
  const app = document.getElementById('app')

  // Clear existing content and append the new layout
  app.innerHTML = ''
  app.appendChild(createAppLayout())

  // Initialize UI state manager
  const uiStateManager = new UIStateManager()

  // Initialize conversion settings
  const conversionSettings = new ConversionSettings()
  const settingsContainer = document.getElementById('conversionSettings')
  conversionSettings.init((settings) => {
    // Update last settings when changed
    lastOutputFormat = settings.outputFormat
    lastQuality = settings.quality
  }).then(settingsElement => {
    settingsContainer.appendChild(settingsElement)
  })

  // Initialize dropzone
  const dropzoneElement = document.getElementById('dropzone')
  const dropzone = new DropZone(dropzoneElement, uiStateManager)

  // Track conversion time and last file for retry
  let conversionStartTime = null
  let lastFileForRetry = null
  let lastOutputFormat = 'webp'
  let lastQuality = 85

  // Batch processing components
  let fileListPreview = null
  let batchQueue = null
  let batchPresetSelector = null
  let websocketService = null
  let currentBatchJobId = null

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

    // Get current settings from conversion settings component
    const currentSettings = conversionSettings.getCurrentSettings()
    const outputFormat = currentSettings.outputFormat
    const quality = currentSettings.quality
    const preserveMetadata = currentSettings.preserveMetadata
    const presetId = currentSettings.presetId

    try {
      // Update state to converting
      uiStateManager.setState(UIStates.CONVERTING)

      // Call API to convert image with all settings
      const { blob, filename } = await convertImage(file, outputFormat, quality, preserveMetadata, presetId)

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

  // Handle multiple files selection for batch processing
  dropzone.onMultipleFilesSelect(async (files) => {
    console.log(`Multiple files selected: ${files.length} files`)

    // Clear previous messages
    const errorElement = document.getElementById('errorMessage')
    const fileInfoElement = document.getElementById('fileInfo')
    errorElement.classList.add('hidden')
    fileInfoElement.classList.add('hidden')

    // Initialize file list preview if not exists
    const fileListContainer = document.getElementById('fileListPreview')
    if (!fileListPreview) {
      fileListPreview = new FileListPreview(fileListContainer)
    }

    // Show file list
    fileListPreview.setFiles(files)
    fileListContainer.classList.remove('hidden')

    // Initialize batch preset selector
    const presetContainer = document.createElement('div')
    presetContainer.className = 'mt-4'
    fileListContainer.parentElement.appendChild(presetContainer)
    
    if (!batchPresetSelector) {
      batchPresetSelector = new BatchPresetSelector(presetContainer)
      batchPresetSelector.onChange((settings) => {
        console.log('Batch settings changed:', settings)
      })
    }

    // Add start batch button
    const startButton = document.createElement('button')
    startButton.className = 'mt-4 w-full px-4 py-2 bg-blue-600 text-white font-medium rounded hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'
    startButton.textContent = `Start Batch Conversion (${files.length} files)`
    startButton.onclick = async () => {
      await startBatchConversion(files)
    }
    presetContainer.appendChild(startButton)
  })

  // Function to start batch conversion
  async function startBatchConversion(files) {
    try {
      // Get settings from preset selector
      const settings = batchPresetSelector.getSettings()
      
      // Hide file list and preset selector
      const fileListContainer = document.getElementById('fileListPreview')
      fileListContainer.classList.add('hidden')
      
      // Remove preset selector container
      const presetContainer = batchPresetSelector.container.parentElement
      if (presetContainer) {
        presetContainer.remove()
      }
      
      // Initialize batch queue component
      const queueContainer = document.createElement('div')
      queueContainer.id = 'batchQueueContainer'
      queueContainer.className = 'mt-4'
      fileListContainer.parentElement.appendChild(queueContainer)
      
      if (!batchQueue) {
        batchQueue = new BatchQueueComponent(queueContainer)
      }
      
      // Create batch job via API
      const response = await createBatchJob(files, settings)
      currentBatchJobId = response.job_id
      
      // Set up batch queue
      batchQueue.setJobId(currentBatchJobId)
      const queueItems = files.map((file, index) => ({
        index,
        filename: file.name,
        status: 'pending',
        progress: 0
      }))
      batchQueue.setItems(queueItems)
      
      // Initialize WebSocket connection
      if (!websocketService) {
        websocketService = new WebSocketService()
      }
      
      // Connect to WebSocket for progress updates
      await websocketService.connect(currentBatchJobId, response.websocket_url)
      
      // Handle progress updates
      websocketService.on('progress', (data) => {
        if (data.file_index >= 0) {
          batchQueue.updateProgress(data.file_index, data.progress)
          batchQueue.updateStatus(data.file_index, data.status, data.message)
        }
      })
      
      // Handle job status updates
      websocketService.on('job_status', async (data) => {
        if (data.status === 'completed') {
          console.log('Batch job completed successfully')
          // Auto-download the results
          await autoDownloadBatchResults()
        } else if (data.status === 'failed') {
          console.log('Batch job failed')
          showBatchError('Batch processing failed. Some files could not be converted.')
        }
      })
      
      // Poll for status as backup (in case WebSocket messages are missed)
      const statusInterval = setInterval(async () => {
        try {
          const status = await getBatchStatus(currentBatchJobId)
          if (status.status === 'completed') {
            clearInterval(statusInterval)
            await autoDownloadBatchResults()
          } else if (status.status === 'failed' || status.status === 'cancelled') {
            clearInterval(statusInterval)
            showBatchError(`Batch processing ${status.status}. Some files could not be converted.`)
          }
        } catch (error) {
          console.error('Failed to get batch status:', error)
        }
      }, 2000) // Check every 2 seconds
      
      // Handle cancel callbacks
      batchQueue.onCancelItem(async (index) => {
        // TODO: Implement cancel item API call
        console.log('Cancel item:', index)
      })
      
      batchQueue.onCancelAll(async () => {
        // TODO: Implement cancel all API call
        console.log('Cancel all')
      })
      
    } catch (error) {
      console.error('Failed to start batch conversion:', error)
      const errorElement = document.getElementById('errorMessage')
      if (errorElement) {
        errorElement.innerHTML = ''
        errorElement.appendChild(createErrorMessage(['Failed to start batch conversion. Please try again.']))
        errorElement.classList.remove('hidden')
      }
    }
  }

  // Function to auto-download batch results
  async function autoDownloadBatchResults() {
    try {
      // Download the ZIP file
      const blob = await downloadBatchResults(currentBatchJobId)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `batch_${currentBatchJobId.substring(0, 8)}_results.zip`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      
      // Show success message
      showBatchSuccess('Batch conversion completed! Your files are downloading.')
      
      // Clean up after a short delay
      setTimeout(() => {
        if (websocketService) {
          websocketService.disconnect()
        }
        resetBatchUI()
      }, 3000)
      
    } catch (error) {
      console.error('Failed to download results:', error)
      showBatchError('Failed to download batch results. Please try again.')
    }
  }
  
  // Function to show batch success message
  function showBatchSuccess(message) {
    const fileInfoElement = document.getElementById('fileInfo')
    if (fileInfoElement) {
      fileInfoElement.innerHTML = ''
      fileInfoElement.appendChild(createSuccessMessage(message, ''))
      fileInfoElement.classList.remove('hidden')
    }
  }
  
  // Function to show batch error message
  function showBatchError(message) {
    const errorElement = document.getElementById('errorMessage')
    if (errorElement) {
      errorElement.innerHTML = ''
      errorElement.appendChild(createErrorMessage([message]))
      errorElement.classList.remove('hidden')
    }
  }

  // Function to reset batch UI
  function resetBatchUI() {
    // Remove batch queue container
    const queueContainer = document.getElementById('batchQueueContainer')
    if (queueContainer) {
      queueContainer.remove()
    }
    
    // Reset components
    fileListPreview = null
    batchQueue = null
    batchPresetSelector = null
    currentBatchJobId = null
    
    // Reset dropzone
    dropzone.reset()
    uiStateManager.setState(UIStates.IDLE)
  }

  // Handle UI state changes
  uiStateManager.onStateChange((newState, _oldState) => {
    const dropzoneContent = dropzoneElement.querySelector('p')

    switch (newState) {
      case UIStates.IDLE:
        dropzoneContent.textContent = 'Drag and drop images or folders here, or click to select'
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
