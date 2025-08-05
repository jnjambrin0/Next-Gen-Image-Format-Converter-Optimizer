import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createComparisonViewer } from '../../src/components/comparisonViewer.js'

describe('ComparisonViewer', () => {
  let container
  let mockOptions
  let mockUrls

  beforeEach(() => {
    // Set up DOM container
    container = document.createElement('div')
    document.body.appendChild(container)

    // Mock URL.createObjectURL and revokeObjectURL
    mockUrls = new Map()
    global.URL.createObjectURL = vi.fn((blob) => {
      const url = `blob:mock-url-${mockUrls.size}`
      mockUrls.set(url, blob)
      return url
    })
    global.URL.revokeObjectURL = vi.fn((url) => {
      mockUrls.delete(url)
    })

    // Set up mock options
    mockOptions = {
      originalUrl: 'blob:mock-original',
      convertedUrl: 'blob:mock-converted',
      originalSize: 1024 * 1024, // 1MB
      convertedSize: 512 * 1024, // 512KB
      originalFilename: 'test-image.jpg',
      convertedFilename: 'test-image.webp',
      onClose: vi.fn(),
    }
  })

  afterEach(() => {
    // Clean up DOM
    document.body.innerHTML = ''
    vi.clearAllMocks()
  })

  describe('Component Creation', () => {
    it('should create comparison viewer with all required elements', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      // Check main structure
      expect(viewer.classList.contains('fixed')).toBe(true)
      expect(viewer.classList.contains('inset-0')).toBe(true)

      // Check header
      const header = viewer.querySelector('h2')
      expect(header).toBeTruthy()
      expect(header.textContent).toBe('Image Comparison')

      // Check close button
      const closeBtn = viewer.querySelector('button[aria-label="Close comparison viewer"]')
      expect(closeBtn).toBeTruthy()

      // Check toggle button
      const toggleBtn = viewer.querySelector('[data-toggle-view]')
      expect(toggleBtn).toBeTruthy()
      expect(toggleBtn.textContent).toBe('Single View')

      // Check image selector (should be hidden initially)
      const selector = viewer.querySelector('[data-image-selector]')
      expect(selector).toBeTruthy()
      expect(selector.classList.contains('hidden')).toBe(true)

      // Check images
      const images = viewer.querySelectorAll('img')
      expect(images.length).toBe(2)
      expect(images[0].src).toContain('blob:mock-original')
      expect(images[1].src).toContain('blob:mock-converted')

      // Check metrics
      const metrics = viewer.querySelectorAll('.text-lg.font-semibold')
      expect(metrics.length).toBe(3)
      expect(metrics[0].textContent).toBe('1 MB') // Original size
      expect(metrics[1].textContent).toBe('512 KB') // Converted size
      expect(metrics[2].textContent).toBe('50% saved') // Size reduction
    })

    it('should display correct file size formatting', () => {
      // Test various file sizes
      const testCases = [
        { size: 0, expected: '0 Bytes' },
        { size: 512, expected: '512 Bytes' },
        { size: 1024, expected: '1 KB' },
        { size: 1536, expected: '1.5 KB' },
        { size: 1048576, expected: '1 MB' },
        { size: 1572864, expected: '1.5 MB' },
        { size: 1073741824, expected: '1 GB' },
      ]

      testCases.forEach(({ size, expected }) => {
        const viewer = createComparisonViewer({
          ...mockOptions,
          originalSize: size,
          convertedSize: size,
        })
        document.body.appendChild(viewer)

        const metrics = viewer.querySelectorAll('.text-lg.font-semibold')
        expect(metrics[0].textContent).toBe(expected)

        document.body.removeChild(viewer)
      })
    })

    it('should calculate size reduction correctly', () => {
      const testCases = [
        { original: 1000, converted: 500, expected: '50% saved' },
        { original: 1000, converted: 750, expected: '25% saved' },
        { original: 1000, converted: 1000, expected: 'No reduction' },
        { original: 1000, converted: 1100, expected: 'No reduction' }, // Negative reduction
        { original: 0, converted: 100, expected: 'No reduction' }, // Edge case
      ]

      testCases.forEach(({ original, converted, expected }) => {
        const viewer = createComparisonViewer({
          ...mockOptions,
          originalSize: original,
          convertedSize: converted,
        })
        document.body.appendChild(viewer)

        const reductionMetric = viewer.querySelectorAll('.text-lg.font-semibold')[2]
        expect(reductionMetric.textContent).toBe(expected)

        document.body.removeChild(viewer)
      })
    })
  })

  describe('View Toggle Functionality', () => {
    it('should toggle between side-by-side and single view', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      const toggleBtn = viewer.querySelector('[data-toggle-view]')
      const selector = viewer.querySelector('[data-image-selector]')
      const imagesWrapper = viewer.querySelector('.grid')
      const imageWrappers = imagesWrapper.querySelectorAll('.bg-white.rounded-lg')

      // Initial state - side by side
      expect(toggleBtn.textContent).toBe('Single View')
      expect(selector.classList.contains('hidden')).toBe(true)
      expect(imagesWrapper.classList.contains('md:grid-cols-2')).toBe(true)
      expect(imageWrappers[0].classList.contains('hidden')).toBe(false)
      expect(imageWrappers[1].classList.contains('hidden')).toBe(false)

      // Click to switch to single view
      toggleBtn.click()

      expect(toggleBtn.textContent).toBe('Side-by-Side')
      expect(selector.classList.contains('hidden')).toBe(false)
      expect(imagesWrapper.classList.contains('md:grid-cols-2')).toBe(false)
      expect(imagesWrapper.classList.contains('flex')).toBe(true)
      expect(imageWrappers[0].classList.contains('hidden')).toBe(true) // Original hidden
      expect(imageWrappers[1].classList.contains('hidden')).toBe(false) // Converted shown

      // Click to switch back
      toggleBtn.click()

      expect(toggleBtn.textContent).toBe('Single View')
      expect(selector.classList.contains('hidden')).toBe(true)
      expect(imagesWrapper.classList.contains('md:grid-cols-2')).toBe(true)
      expect(imageWrappers[0].classList.contains('hidden')).toBe(false)
      expect(imageWrappers[1].classList.contains('hidden')).toBe(false)
    })

    it('should switch between images in single view mode', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      const toggleBtn = viewer.querySelector('[data-toggle-view]')
      const selector = viewer.querySelector('[data-image-selector]')
      const imagesWrapper = viewer.querySelector('.grid')
      const imageWrappers = imagesWrapper.querySelectorAll('.bg-white.rounded-lg')

      // Switch to single view
      toggleBtn.click()

      // Default shows converted image
      expect(imageWrappers[0].classList.contains('hidden')).toBe(true)
      expect(imageWrappers[1].classList.contains('hidden')).toBe(false)

      // Select original image
      selector.value = 'original'
      selector.dispatchEvent(new Event('change'))

      expect(imageWrappers[0].classList.contains('hidden')).toBe(false)
      expect(imageWrappers[1].classList.contains('hidden')).toBe(true)

      // Select converted image again
      selector.value = 'converted'
      selector.dispatchEvent(new Event('change'))

      expect(imageWrappers[0].classList.contains('hidden')).toBe(true)
      expect(imageWrappers[1].classList.contains('hidden')).toBe(false)
    })
  })

  describe('Close Functionality', () => {
    it('should close when close button is clicked', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      const closeBtn = viewer.querySelector('button[aria-label="Close comparison viewer"]')
      closeBtn.click()

      expect(mockOptions.onClose).toHaveBeenCalledTimes(1)
    })

    it('should close when backdrop is clicked', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      // Click on the backdrop (the main container)
      viewer.click()

      expect(mockOptions.onClose).toHaveBeenCalledTimes(1)
    })

    it('should not close when modal content is clicked', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      // Click on the modal content
      const modal = viewer.querySelector('.bg-white')
      modal.click()

      expect(mockOptions.onClose).not.toHaveBeenCalled()
    })

    it('should close when Escape key is pressed', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      // Press Escape key
      const escapeEvent = new KeyboardEvent('keydown', { key: 'Escape' })
      document.dispatchEvent(escapeEvent)

      expect(mockOptions.onClose).toHaveBeenCalledTimes(1)
    })

    it('should remove escape listener after closing', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      // Press Escape to close
      const escapeEvent = new KeyboardEvent('keydown', { key: 'Escape' })
      document.dispatchEvent(escapeEvent)

      expect(mockOptions.onClose).toHaveBeenCalledTimes(1)

      // Press Escape again - should not trigger onClose
      document.dispatchEvent(escapeEvent)

      expect(mockOptions.onClose).toHaveBeenCalledTimes(1)
    })
  })

  describe('Responsive Design', () => {
    it('should have responsive grid classes', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      const imagesWrapper = viewer.querySelector('.grid')

      // Check responsive classes
      expect(imagesWrapper.classList.contains('grid-cols-1')).toBe(true)
      expect(imagesWrapper.classList.contains('md:grid-cols-2')).toBe(true)

      // Check responsive text in metrics
      const metricsGrid = viewer.querySelector('.grid.sm\\:grid-cols-3')
      expect(metricsGrid).toBeTruthy()
    })
  })

  describe('Image Display', () => {
    it('should display images with correct attributes', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      const images = viewer.querySelectorAll('img')

      // Original image
      expect(images[0].src).toContain('blob:mock-original')
      expect(images[0].alt).toBe('Original image')
      expect(images[0].classList.contains('max-w-full')).toBe(true)
      expect(images[0].classList.contains('object-contain')).toBe(true)

      // Converted image
      expect(images[1].src).toContain('blob:mock-converted')
      expect(images[1].alt).toBe('Converted image')
      expect(images[1].classList.contains('max-w-full')).toBe(true)
      expect(images[1].classList.contains('object-contain')).toBe(true)
    })

    it('should display filenames correctly', () => {
      const viewer = createComparisonViewer(mockOptions)
      document.body.appendChild(viewer)

      const filenames = viewer.querySelectorAll('.text-sm.text-gray-600.truncate')

      expect(filenames[0].textContent).toBe('test-image.jpg')
      expect(filenames[0].title).toBe('test-image.jpg')

      expect(filenames[1].textContent).toBe('test-image.webp')
      expect(filenames[1].title).toBe('test-image.webp')
    })
  })
})
