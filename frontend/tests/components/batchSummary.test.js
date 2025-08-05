import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { BatchSummaryModal } from '../../src/components/batchSummary.js'

describe('BatchSummaryModal', () => {
  let modal

  beforeEach(() => {
    modal = new BatchSummaryModal()
  })

  afterEach(() => {
    // Clean up any modals
    const modals = document.querySelectorAll('[role="dialog"]')
    modals.forEach((m) => m.remove())
  })

  describe('initialization', () => {
    it('should create modal instance', () => {
      expect(modal).toBeDefined()
      expect(modal.modal).toBeNull()
      expect(modal.jobId).toBeNull()
      expect(modal.results).toBeNull()
    })
  })

  describe('show/hide', () => {
    const mockResults = {
      total_files: 10,
      successful_files: [
        { filename: 'test1.jpg', output_size: 1024 * 1024 },
        { filename: 'test2.png', output_size: 2 * 1024 * 1024 },
      ],
      failed_files: [{ filename: 'test3.gif', error: 'Conversion failed' }],
      processing_time_seconds: 15.5,
    }

    it('should show modal with results', () => {
      modal.show('test-job-id', mockResults)

      expect(modal.jobId).toBe('test-job-id')
      expect(modal.results).toBe(mockResults)

      const modalEl = document.querySelector('[role="dialog"]')
      expect(modalEl).toBeTruthy()

      // Check title
      const title = modalEl.querySelector('#summary-modal-title')
      expect(title.textContent).toBe('Batch Conversion Summary')
    })

    it('should hide modal and call callback', () => {
      const onClose = vi.fn()
      modal.onClose(onClose)

      modal.show('test-job-id', mockResults)
      modal.hide()

      const modalEl = document.querySelector('[role="dialog"]')
      expect(modalEl).toBeNull()
      expect(onClose).toHaveBeenCalled()
    })

    it('should close on backdrop click', () => {
      modal.show('test-job-id', mockResults)

      const backdrop = document.querySelector('.bg-gray-500')
      backdrop.click()

      const modalEl = document.querySelector('[role="dialog"]')
      expect(modalEl).toBeNull()
    })

    it('should close on close button click', () => {
      modal.show('test-job-id', mockResults)

      const closeBtn = document.querySelector('button[aria-label="Close summary"]')
      closeBtn.click()

      const modalEl = document.querySelector('[role="dialog"]')
      expect(modalEl).toBeNull()
    })
  })

  describe('statistics display', () => {
    it('should display correct statistics', () => {
      const mockResults = {
        total_files: 10,
        successful_files: Array(8).fill({ filename: 'test.jpg' }),
        failed_files: Array(2).fill({ filename: 'fail.jpg' }),
        processing_time_seconds: 25.5,
      }

      modal.show('test-job-id', mockResults)

      const statCards = document.querySelectorAll('.bg-gray-50.rounded-lg')
      expect(statCards.length).toBeGreaterThanOrEqual(4)

      // Find stat values
      const values = Array.from(statCards)
        .map((card) => card.querySelector('.text-2xl')?.textContent)
        .filter(Boolean)

      expect(values).toContain('10') // Total files
      expect(values).toContain('8') // Successful
      expect(values).toContain('2') // Failed
      expect(values).toContain('80%') // Success rate

      // Check processing time
      const timeTexts = Array.from(document.querySelectorAll('.text-gray-600'))
      const processingTimeText = timeTexts.find((el) => el.textContent.includes('processing time'))
      expect(processingTimeText.textContent).toContain('25.5 seconds')
    })

    it('should format long processing times', () => {
      const mockResults = {
        total_files: 100,
        successful_files: [],
        failed_files: [],
        processing_time_seconds: 3665, // 1 hour, 1 minute, 5 seconds
      }

      modal.show('test-job-id', mockResults)

      const timeText = Array.from(document.querySelectorAll('.text-gray-600')).find((el) =>
        el.textContent.includes('processing time')
      )

      expect(timeText.textContent).toContain('1h 1m')
    })
  })

  describe('results tables', () => {
    it('should display successful files table', () => {
      const mockResults = {
        total_files: 3,
        successful_files: [
          { filename: 'image1.jpg', output_size: 1024 * 512 },
          { filename: 'image2.png', output_size: 1024 * 1024 },
        ],
        failed_files: [],
      }

      modal.show('test-job-id', mockResults)

      // Check success table exists
      const successTitle = Array.from(document.querySelectorAll('h4')).find(
        (el) => el.textContent === 'Successfully Converted'
      )
      expect(successTitle).toBeTruthy()

      // Check table rows
      const rows = document.querySelectorAll('tbody tr')
      expect(rows.length).toBeGreaterThanOrEqual(2)

      // Check file sizes are formatted
      const cells = Array.from(document.querySelectorAll('td'))
      expect(cells.some((cell) => cell.textContent === '512 KB')).toBe(true)
      expect(cells.some((cell) => cell.textContent === '1 MB')).toBe(true)
    })

    it('should display failed files table', () => {
      const mockResults = {
        total_files: 3,
        successful_files: [],
        failed_files: [
          { filename: 'bad1.gif', error: 'Format not supported' },
          { filename: 'corrupt.jpg', error: 'Invalid image data' },
        ],
      }

      modal.show('test-job-id', mockResults)

      // Check failed table exists
      const failedTitle = Array.from(document.querySelectorAll('h4')).find(
        (el) => el.textContent === 'Failed Conversions'
      )
      expect(failedTitle).toBeTruthy()

      // Check error messages
      const cells = Array.from(document.querySelectorAll('td'))
      expect(cells.some((cell) => cell.textContent === 'Format not supported')).toBe(true)
      expect(cells.some((cell) => cell.textContent === 'Invalid image data')).toBe(true)
    })
  })

  describe('visual chart', () => {
    it('should display success/fail ratio chart', () => {
      const mockResults = {
        total_files: 10,
        successful_files: Array(7).fill({ filename: 'test.jpg' }),
        failed_files: Array(3).fill({ filename: 'fail.jpg' }),
        processing_time_seconds: 10,
      }

      modal.show('test-job-id', mockResults)

      // Check chart exists
      const chart = document.querySelector('.bg-green-500')
      expect(chart).toBeTruthy()
      expect(chart.style.width).toBe('70%')

      const failBar = document.querySelector('.bg-red-500')
      expect(failBar).toBeTruthy()
      expect(failBar.style.width).toBe('30%')

      // Check legend
      const legend = document.querySelector('.flex.justify-center')
      expect(legend.textContent).toContain('Successful (7)')
      expect(legend.textContent).toContain('Failed (3)')
    })
  })

  describe('action buttons', () => {
    it('should show retry button when there are failed files', () => {
      const mockResults = {
        total_files: 5,
        successful_files: [],
        failed_files: [
          { filename: 'fail1.jpg', error: 'Error 1' },
          { filename: 'fail2.jpg', error: 'Error 2' },
        ],
      }

      const onRetry = vi.fn()
      modal.onRetry(onRetry)
      modal.show('test-job-id', mockResults)

      const retryBtn = Array.from(document.querySelectorAll('button')).find((btn) =>
        btn.textContent.includes('Retry Failed Files')
      )

      expect(retryBtn).toBeTruthy()
      expect(retryBtn.textContent).toContain('(2)')

      retryBtn.click()

      expect(onRetry).toHaveBeenCalledWith(mockResults.failed_files)
    })

    it('should not show retry button when no failed files', () => {
      const mockResults = {
        total_files: 5,
        successful_files: Array(5).fill({ filename: 'test.jpg' }),
        failed_files: [],
      }

      modal.show('test-job-id', mockResults)

      const retryBtn = Array.from(document.querySelectorAll('button')).find((btn) =>
        btn.textContent.includes('Retry')
      )

      expect(retryBtn).toBeFalsy()
    })

    it('should call download callback', () => {
      const mockResults = {
        total_files: 1,
        successful_files: [{ filename: 'test.jpg' }],
        failed_files: [],
      }

      const onDownload = vi.fn()
      modal.onDownload(onDownload)
      modal.show('test-job-id', mockResults)

      const downloadBtn = Array.from(document.querySelectorAll('button')).find((btn) =>
        btn.textContent.includes('Download')
      )

      downloadBtn.click()

      expect(onDownload).toHaveBeenCalledWith('test-job-id')
    })
  })

  describe('utility methods', () => {
    it('should format file sizes correctly', () => {
      expect(modal.formatFileSize(0)).toBe('0 Bytes')
      expect(modal.formatFileSize(512)).toBe('512 Bytes')
      expect(modal.formatFileSize(1024)).toBe('1 KB')
      expect(modal.formatFileSize(1024 * 1024)).toBe('1 MB')
      expect(modal.formatFileSize(1.5 * 1024 * 1024)).toBe('1.5 MB')
    })

    it('should format time correctly', () => {
      expect(modal.formatTime(30)).toBe('30.0 seconds')
      expect(modal.formatTime(90)).toBe('1m 30s')
      expect(modal.formatTime(3661)).toBe('1h 1m')
    })
  })
})
