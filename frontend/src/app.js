import { DropZone } from './components/dropzone.js'
import { validateImageFile, formatFileSize } from './utils/validators.js'
import { UIStateManager, UIStates } from './utils/uiState.js'
import { createLoadingSpinner } from './components/loadingSpinner.js'
import { createErrorMessage, createSuccessMessage } from './components/uiMessages.js'
import { createAppLayout } from './components/appLayout.js'
import { UI_TIMING } from './config/constants.js'
import { convertImage, APIError, mapErrorCodeToMessage } from './services/api.js'
import { createConversionResult } from './components/conversionResult.js'
import { createComparisonViewer } from './components/comparisonViewer.js'
import { createPreview } from './components/preview.js'
import { BlobUrlManager } from './utils/blobUrlManager.js'

// Batch processing components
import { FileListPreview } from './components/fileListPreview.js'
import { BatchQueueComponent } from './components/batchQueue.js'
import { BatchPresetSelector } from './components/batchPresetSelector.js'
import { WebSocketService } from './services/websocket.js'
import { createBatchJob, getBatchStatus, downloadBatchResults } from './services/batchApi.js'

// Conversion settings
import { ConversionSettingsProgressive } from './components/conversionSettingsProgressive.js'
import { KeyboardShortcuts } from './components/keyboardShortcuts.js'

// API key management
import { apiKeyManager } from './components/apiKeyManager.js'

export function initializeApp() {
  const app = document.getElementById('app')

  // Clear existing content and append the new layout
  app.innerHTML = ''
  app.appendChild(createAppLayout())

  // Initialize UI state manager
  const uiStateManager = new UIStateManager()

  // Initialize conversion settings with progressive disclosure
  const conversionSettings = new ConversionSettingsProgressive()
  const settingsContainer = document.getElementById('conversionSettings')

  // Initialize keyboard shortcuts
  const keyboardShortcuts = new KeyboardShortcuts()
  keyboardShortcuts.init()
  KeyboardShortcuts.registerDefaults(keyboardShortcuts)

  // Store current file for test conversions
  let currentFile = null
  let testPreviewElement = null
  const testBlobUrls = { original: null, converted: null }

  conversionSettings
    .init(
      (settings) => {
        // Settings updated - callback for future use
        console.log('Settings updated:', settings)
      },
      async () => {
        // Handle test conversion
        if (!currentFile) {
          return
        }

        try {
          conversionSettings.showTestLoading()

          const currentSettings = conversionSettings.getCurrentSettings()
          const testBlob = await convertImage(
            currentFile,
            currentSettings.outputFormat,
            currentSettings.quality,
            currentSettings.preserveMetadata,
            currentSettings.presetId
          )

          // Show test results in quality slider
          conversionSettings.showTestResults(testBlob.blob.size)

          // Clean up previous blob URLs
          if (testBlobUrls.original) {
            blobUrlManager.revokeUrl(testBlobUrls.original)
            testBlobUrls.original = null
          }
          if (testBlobUrls.converted) {
            blobUrlManager.revokeUrl(testBlobUrls.converted)
            testBlobUrls.converted = null
          }

          // Create preview
          const originalUrl = blobUrlManager.createUrl(currentFile)
          const convertedUrl = blobUrlManager.createUrl(testBlob.blob)

          // Store URLs for cleanup
          testBlobUrls.original = originalUrl
          testBlobUrls.converted = convertedUrl

          // Remove existing preview if any
          if (testPreviewElement) {
            testPreviewElement.remove()
            testPreviewElement = null
          }

          // Create new preview
          testPreviewElement = createPreview({
            originalUrl,
            convertedUrl,
            originalSize: currentFile.size,
            convertedSize: testBlob.blob.size,
            originalFilename: currentFile.name,
            onClose: () => {
              if (testPreviewElement) {
                testPreviewElement.remove()
                testPreviewElement = null
              }
              // Clean up blob URLs on close
              if (testBlobUrls.original) {
                blobUrlManager.revokeUrl(testBlobUrls.original)
                testBlobUrls.original = null
              }
              if (testBlobUrls.converted) {
                blobUrlManager.revokeUrl(testBlobUrls.converted)
                testBlobUrls.converted = null
              }
            },
          })

          // Insert preview after settings
          const resultsContainer = document.getElementById('conversionResults')
          resultsContainer.parentNode.insertBefore(testPreviewElement, resultsContainer)
        } catch (error) {
          console.error('Test conversion failed:', error)

          // Hide loading state
          conversionSettings.showTestResults(null)

          let errorMessage = 'Test conversion failed'

          if (error instanceof APIError) {
            // Map specific error codes to user-friendly messages
            switch (error.code) {
              case 'TIMEOUT':
                errorMessage =
                  'Test conversion timed out. Please try again with a smaller image or lower quality.'
                break
              case 'FILE_TOO_LARGE':
                errorMessage =
                  'The file is too large for test conversion. Please try a smaller file.'
                break
              case 'INVALID_FORMAT':
                errorMessage = 'The selected output format is not supported for this image.'
                break
              case 'CONVERSION_FAILED':
                errorMessage =
                  'Unable to convert the image. Please try a different format or quality setting.'
                break
              default:
                errorMessage = mapErrorCodeToMessage(error.code)
            }
          } else if (error.name === 'AbortError') {
            errorMessage = 'Test conversion was cancelled or timed out. Please try again.'
          }

          const errorElement = document.getElementById('errorMessage')
          errorElement.innerHTML = ''
          errorElement.appendChild(createErrorMessage(errorMessage))
          errorElement.classList.remove('hidden')

          // Also show error in quality slider
          if (conversionSettings.showTestError) {
            conversionSettings.showTestError(errorMessage)
          }
        }
      }
    )
    .then((settingsElement) => {
      settingsContainer.appendChild(settingsElement)
    })

  // Initialize dropzone
  const dropzoneElement = document.getElementById('dropzone')
  const dropzone = new DropZone(dropzoneElement, uiStateManager)

  // Track conversion time and last file for retry
  let conversionStartTime = null
  let lastFileForRetry = null

  // Store for comparison
  const blobUrlManager = new BlobUrlManager()
  let lastConversionData = null

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

    // Clear previous test preview and blob URLs
    if (testPreviewElement) {
      testPreviewElement.remove()
      testPreviewElement = null
    }
    if (testBlobUrls.original) {
      blobUrlManager.revokeUrl(testBlobUrls.original)
      testBlobUrls.original = null
    }
    if (testBlobUrls.converted) {
      blobUrlManager.revokeUrl(testBlobUrls.converted)
      testBlobUrls.converted = null
    }

    // Validate file
    const validation = validateImageFile(file)

    if (!validation.valid) {
      // Show error message
      errorElement.innerHTML = ''
      errorElement.appendChild(createErrorMessage(validation.errors))
      errorElement.classList.remove('hidden')
      return
    }

    // Store current file
    currentFile = file

    // Update quality slider with file info
    conversionSettings.setFileInfo(file)

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
      const { blob, filename } = await convertImage(
        file,
        outputFormat,
        quality,
        preserveMetadata,
        presetId
      )

      // Calculate conversion time
      const conversionTime = ((Date.now() - conversionStartTime) / 1000).toFixed(1)

      // Create object URLs for comparison using BlobUrlManager
      const originalUrl = blobUrlManager.createUrl(file, 'original')
      const convertedUrl = blobUrlManager.createUrl(blob, 'converted')

      // Store conversion data for comparison
      lastConversionData = {
        originalUrl: originalUrl,
        convertedUrl: convertedUrl,
        originalSize: file.size,
        convertedSize: blob.size,
        originalFilename: file.name,
        convertedFilename: filename,
      }

      // Trigger download
      uiStateManager.setState(UIStates.DOWNLOADING)
      const a = document.createElement('a')
      a.href = convertedUrl
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)

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
          // Clean up all blob URLs
          blobUrlManager.revokeAll()
          lastConversionData = null
          // Reset dropzone
          dropzone.reset()
        },
        onCompare: () => {
          if (lastConversionData) {
            // Create and show comparison viewer
            const comparisonViewer = createComparisonViewer({
              ...lastConversionData,
              onClose: () => {
                // Remove viewer from DOM
                document.body.removeChild(comparisonViewer)
              },
            })
            document.body.appendChild(comparisonViewer)
          }
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
  dropzone.onMultipleFilesSelect((files) => {
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
    startButton.className =
      'mt-4 w-full px-4 py-2 bg-blue-600 text-white font-medium rounded hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'
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
        progress: 0,
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
      batchQueue.onCancelItem((index) => {
        // TODO: Implement cancel item API call
        console.log('Cancel item:', index)
      })

      batchQueue.onCancelAll(() => {
        // TODO: Implement cancel all API call
        console.log('Cancel all')
      })
    } catch (error) {
      console.error('Failed to start batch conversion:', error)
      const errorElement = document.getElementById('errorMessage')
      if (errorElement) {
        errorElement.innerHTML = ''
        errorElement.appendChild(
          createErrorMessage(['Failed to start batch conversion. Please try again.'])
        )
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

  // Setup keyboard shortcut event listeners
  setupKeyboardShortcutListeners()

  // Setup API key manager
  setupApiKeyManager()

  function setupApiKeyManager() {
    // Initialize the API key manager UI
    apiKeyManager.render()
    
    // Add event listener to the API management button
    const apiButton = document.getElementById('apiManagementBtn')
    if (apiButton) {
      apiButton.addEventListener('click', () => {
        apiKeyManager.show()
      })
    }
    
    // Handle escape key to close API key manager
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && apiKeyManager.isVisible) {
        apiKeyManager.hide()
      }
    })
  }

  function setupKeyboardShortcutListeners() {
    // Toggle advanced settings
    window.addEventListener('shortcut:toggleAdvanced', () => {
      const toggleBtn = document.querySelector('#advanced-toggle')
      if (toggleBtn) {
        toggleBtn.click()
      }
    })

    // Start conversion
    window.addEventListener('shortcut:startConversion', () => {
      // Trigger file selection if no file selected
      if (!currentFile) {
        const fileInput = dropzoneElement.querySelector('input[type="file"]')
        if (fileInput) {
          fileInput.click()
        }
      }
    })

    // Format selection
    window.addEventListener('shortcut:selectFormat', (event) => {
      const formatSelect = document.querySelector('#output-format')
      if (formatSelect && event.detail.format) {
        formatSelect.value = event.detail.format
        formatSelect.dispatchEvent(new Event('change'))
      }
    })

    // Escape key handling
    window.addEventListener('shortcut:escape', () => {
      // Close any open modals or dialogs
      const modals = document.querySelectorAll('.customization-modal')
      modals.forEach((modal) => modal.remove())
    })
  }
}
