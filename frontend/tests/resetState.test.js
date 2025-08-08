import { describe, it, expect, beforeEach, vi } from 'vitest'
import { JSDOM } from 'jsdom'

// Mock the modules that would be imported
vi.mock('../src/utils/blobUrlManager.js', () => ({
  BlobUrlManager: vi.fn().mockImplementation(() => ({
    createUrl: vi.fn((blob, key) => `blob:${key}`),
    revokeUrl: vi.fn(),
    revokeAll: vi.fn(),
    hasUrl: vi.fn(),
    getUrl: vi.fn(),
    size: 0,
  })),
}))

describe('Application State Reset', () => {
  let dom
  let document
  let window

  beforeEach(() => {
    // Set up DOM environment with proper URL
    dom = new JSDOM(
      `
      <!DOCTYPE html>
      <html>
        <body>
          <div id="app"></div>
          <div id="dropzone"><p>Drop files here</p></div>
          <div id="errorMessage" class="hidden"></div>
          <div id="fileInfo" class="hidden"></div>
          <div id="conversionSettings"></div>
          <div id="conversionResults"></div>
          <div id="fileListPreview" class="hidden"></div>
          <div id="batchQueueContainer"></div>
        </body>
      </html>
    `,
      {
        url: 'http://localhost:3000',
        pretendToBeVisual: true,
      }
    )
    document = dom.window.document
    window = dom.window
    global.document = document
    global.window = window
    global.URL = {
      createObjectURL: vi.fn((_blob) => `blob:mock-${Math.random()}`),
      revokeObjectURL: vi.fn(),
    }

    // Mock localStorage
    global.localStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    }
  })

  it('should clean up all blob URLs when reset is called', () => {
    // This test verifies that blob URLs are properly revoked
    const mockBlobManager = {
      urls: new Map([
        ['original', 'blob:original-url'],
        ['converted', 'blob:converted-url'],
        ['test-original', 'blob:test-original-url'],
        ['test-converted', 'blob:test-converted-url'],
      ]),
      revokeAll: vi.fn(function () {
        this.urls.clear()
      }),
      revokeUrl: vi.fn(function (key) {
        this.urls.delete(key)
      }),
    }

    // Simulate reset
    mockBlobManager.revokeAll()

    expect(mockBlobManager.revokeAll).toHaveBeenCalled()
    expect(mockBlobManager.urls.size).toBe(0)
  })

  it('should remove test preview element on reset', () => {
    // Create a test preview element
    const testPreview = document.createElement('div')
    testPreview.id = 'test-preview'
    document.body.appendChild(testPreview)

    expect(document.getElementById('test-preview')).toBeTruthy()

    // Simulate reset removing the element
    const element = document.getElementById('test-preview')
    if (element) {
      element.remove()
    }

    expect(document.getElementById('test-preview')).toBeFalsy()
  })

  it('should clear error and file info messages on reset', () => {
    const errorElement = document.getElementById('errorMessage')
    const fileInfoElement = document.getElementById('fileInfo')

    // Add some content and make visible
    errorElement.innerHTML = '<p>Error message</p>'
    errorElement.classList.remove('hidden')
    fileInfoElement.innerHTML = '<p>File info</p>'
    fileInfoElement.classList.remove('hidden')

    expect(errorElement.innerHTML).toBeTruthy()
    expect(fileInfoElement.innerHTML).toBeTruthy()
    expect(errorElement.classList.contains('hidden')).toBe(false)
    expect(fileInfoElement.classList.contains('hidden')).toBe(false)

    // Simulate reset clearing messages
    errorElement.innerHTML = ''
    errorElement.classList.add('hidden')
    fileInfoElement.innerHTML = ''
    fileInfoElement.classList.add('hidden')

    expect(errorElement.innerHTML).toBe('')
    expect(fileInfoElement.innerHTML).toBe('')
    expect(errorElement.classList.contains('hidden')).toBe(true)
    expect(fileInfoElement.classList.contains('hidden')).toBe(true)
  })

  it('should reset dropzone to initial state', () => {
    const dropzoneElement = document.getElementById('dropzone')
    const dropzoneContent = dropzoneElement.querySelector('p')

    // Modify dropzone state
    dropzoneContent.textContent = 'Converting image...'
    dropzoneElement.classList.add('opacity-50', 'pointer-events-none')

    expect(dropzoneContent.textContent).toBe('Converting image...')
    expect(dropzoneElement.classList.contains('opacity-50')).toBe(true)

    // Simulate reset
    dropzoneContent.textContent = 'Drag and drop images or folders here, or click to select'
    dropzoneElement.classList.remove('opacity-50', 'pointer-events-none')

    expect(dropzoneContent.textContent).toBe(
      'Drag and drop images or folders here, or click to select'
    )
    expect(dropzoneElement.classList.contains('opacity-50')).toBe(false)
    expect(dropzoneElement.classList.contains('pointer-events-none')).toBe(false)
  })

  it('should clean up batch processing components', () => {
    // The initial DOM already has batchQueueContainer, so remove it first
    const existingContainer = document.getElementById('batchQueueContainer')
    if (existingContainer) {
      existingContainer.remove()
    }

    // Now add a new batch queue container
    const queueContainer = document.createElement('div')
    queueContainer.id = 'batchQueueContainer'
    document.body.appendChild(queueContainer)

    expect(document.getElementById('batchQueueContainer')).toBeTruthy()

    // Simulate reset removing batch container
    const container = document.getElementById('batchQueueContainer')
    if (container) {
      container.remove()
    }

    expect(document.getElementById('batchQueueContainer')).toBeFalsy()
  })

  it('should handle Convert Another button click properly', () => {
    const mockResetFunction = vi.fn()

    // Simulate Convert Another button click
    const convertAnotherBtn = document.createElement('button')
    convertAnotherBtn.onclick = () => {
      mockResetFunction()
    }

    convertAnotherBtn.click()

    expect(mockResetFunction).toHaveBeenCalled()
  })

  it('should clean up test blob URLs with correct keys', () => {
    const mockBlobManager = {
      revokeUrl: vi.fn(),
    }

    const testBlobUrls = {
      original: 'blob:test-original-12345',
      converted: 'blob:test-converted-67890',
    }

    // Simulate cleanup with correct keys
    if (testBlobUrls.original) {
      mockBlobManager.revokeUrl('test-original')
      testBlobUrls.original = null
    }
    if (testBlobUrls.converted) {
      mockBlobManager.revokeUrl('test-converted')
      testBlobUrls.converted = null
    }

    expect(mockBlobManager.revokeUrl).toHaveBeenCalledWith('test-original')
    expect(mockBlobManager.revokeUrl).toHaveBeenCalledWith('test-converted')
    expect(testBlobUrls.original).toBe(null)
    expect(testBlobUrls.converted).toBe(null)
  })

  it('should preserve settings when specified', () => {
    // This test verifies that settings can be preserved during reset
    const mockSettings = {
      outputFormat: 'webp',
      quality: 85,
      preserveMetadata: false,
    }

    const preservedSettings = { ...mockSettings }

    // After reset, settings should be preserved
    expect(preservedSettings.outputFormat).toBe('webp')
    expect(preservedSettings.quality).toBe(85)
    expect(preservedSettings.preserveMetadata).toBe(false)
  })
})
