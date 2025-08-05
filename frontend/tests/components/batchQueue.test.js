import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { BatchQueueComponent } from '../../src/components/batchQueue.js'

describe('BatchQueueComponent', () => {
  let container
  let batchQueue

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
  })

  afterEach(() => {
    document.body.removeChild(container)
  })

  describe('initialization', () => {
    it('should create empty queue', () => {
      batchQueue = new BatchQueueComponent(container)

      expect(batchQueue.items).toEqual([])
      expect(batchQueue.jobId).toBeNull()
      expect(container.classList.contains('hidden')).toBe(true)
    })

    it('should set default sort and filter', () => {
      batchQueue = new BatchQueueComponent(container)

      expect(batchQueue.sortBy).toBe('index')
      expect(batchQueue.filterBy).toBe('all')
    })
  })

  describe('item management', () => {
    const mockItems = [
      { index: 0, filename: 'test1.jpg', status: 'pending', progress: 0 },
      { index: 1, filename: 'test2.png', status: 'processing', progress: 50 },
      { index: 2, filename: 'test3.webp', status: 'completed', progress: 100 },
      {
        index: 3,
        filename: 'test4.gif',
        status: 'failed',
        progress: 0,
        error: 'Conversion failed',
      },
    ]

    it('should set items and render', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)

      expect(batchQueue.items).toHaveLength(4)
      expect(container.classList.contains('hidden')).toBe(false)

      const items = container.querySelectorAll('[id^="queue-item-"]')
      expect(items).toHaveLength(4)
    })

    it('should update item progress', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)

      batchQueue.updateProgress(1, 75)

      const item = batchQueue.items.find((i) => i.index === 1)
      expect(item.progress).toBe(75)

      const progressBar = container.querySelector('#queue-item-1 .bg-blue-600')
      expect(progressBar.style.width).toBe('75%')
    })

    it('should update item status', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)

      batchQueue.updateStatus(0, 'processing')

      const item = batchQueue.items.find((i) => i.index === 0)
      expect(item.status).toBe('processing')

      const itemEl = container.querySelector('#queue-item-0')
      expect(itemEl.classList.contains('border-blue-200')).toBe(true)
    })

    it('should update status with error', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)

      batchQueue.updateStatus(1, 'failed', 'Network error')

      const item = batchQueue.items.find((i) => i.index === 1)
      expect(item.status).toBe('failed')
      expect(item.error).toBe('Network error')

      // Find error message specifically (not status text)
      // The error message is the last paragraph with text-xs and text-red-600
      const allRedTexts = container.querySelectorAll('#queue-item-1 .text-red-600')
      const errorMsg = Array.from(allRedTexts).find(
        (el) =>
          el.tagName === 'P' && el.className.includes('text-xs') && el.className.includes('mt-2') // Error messages have mt-2
      )
      expect(errorMsg).toBeTruthy()
      expect(errorMsg.textContent).toBe('Network error')
    })
  })

  describe('sorting and filtering', () => {
    const mockItems = [
      { index: 0, filename: 'zebra.jpg', status: 'completed', progress: 100 },
      { index: 1, filename: 'apple.png', status: 'processing', progress: 50 },
      { index: 2, filename: 'banana.webp', status: 'pending', progress: 0 },
      { index: 3, filename: 'cherry.gif', status: 'failed', progress: 0 },
    ]

    it('should sort by name', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)
      batchQueue.setSortBy('name')

      const items = batchQueue.getFilteredAndSortedItems()
      expect(items[0].filename).toBe('apple.png')
      expect(items[1].filename).toBe('banana.webp')
      expect(items[2].filename).toBe('cherry.gif')
      expect(items[3].filename).toBe('zebra.jpg')
    })

    it('should sort by status', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)
      batchQueue.setSortBy('status')

      const items = batchQueue.getFilteredAndSortedItems()
      expect(items[0].status).toBe('completed')
      expect(items[1].status).toBe('failed')
      expect(items[2].status).toBe('pending')
      expect(items[3].status).toBe('processing')
    })

    it('should filter by status', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)
      batchQueue.setFilterBy('pending')

      const items = batchQueue.getFilteredAndSortedItems()
      expect(items).toHaveLength(1)
      expect(items[0].status).toBe('pending')
    })

    it('should update UI controls', () => {
      batchQueue = new BatchQueueComponent(container)
      batchQueue.setItems(mockItems)

      const sortSelect = container.querySelector('#queue-sort')
      const filterSelect = container.querySelector('#queue-filter')

      expect(sortSelect.value).toBe('index')
      expect(filterSelect.value).toBe('all')

      // Change sort
      sortSelect.value = 'name'
      sortSelect.dispatchEvent(new Event('change'))
      expect(batchQueue.sortBy).toBe('name')

      // Change filter
      filterSelect.value = 'completed'
      filterSelect.dispatchEvent(new Event('change'))
      expect(batchQueue.filterBy).toBe('completed')
    })
  })

  describe('statistics', () => {
    it('should display correct stats', () => {
      batchQueue = new BatchQueueComponent(container)

      const mockItems = [
        { index: 0, filename: 'test1.jpg', status: 'pending' },
        { index: 1, filename: 'test2.png', status: 'processing' },
        { index: 2, filename: 'test3.webp', status: 'completed' },
        { index: 3, filename: 'test4.gif', status: 'failed' },
        { index: 4, filename: 'test5.jpg', status: 'completed' },
      ]

      batchQueue.setItems(mockItems)

      const stats = container.querySelectorAll('.text-sm span')
      expect(stats[0].textContent).toBe('Total: 5')
      expect(stats[1].textContent).toBe('Pending: 1')
      expect(stats[2].textContent).toBe('Processing: 1')
      expect(stats[3].textContent).toBe('Completed: 2')
      expect(stats[4].textContent).toBe('Failed: 1')
    })
  })

  describe('callbacks', () => {
    it('should call cancel item callback', () => {
      batchQueue = new BatchQueueComponent(container)
      const onCancelItem = vi.fn()
      batchQueue.onCancelItem(onCancelItem)

      const mockItems = [{ index: 0, filename: 'test1.jpg', status: 'pending' }]

      batchQueue.setItems(mockItems)

      const cancelBtn = container.querySelector('button[aria-label*="Cancel test1.jpg"]')
      cancelBtn.click()

      expect(onCancelItem).toHaveBeenCalledWith(0)
    })

    it('should call cancel all callback', () => {
      batchQueue = new BatchQueueComponent(container)
      const onCancelAll = vi.fn()
      batchQueue.onCancelAll(onCancelAll)

      const mockItems = [{ index: 0, filename: 'test1.jpg', status: 'pending' }]

      batchQueue.setItems(mockItems)

      // Find button by text content
      const buttons = Array.from(container.querySelectorAll('button'))
      const cancelAllBtn = buttons.find((btn) => btn.textContent === 'Cancel All')
      cancelAllBtn.click()

      expect(onCancelAll).toHaveBeenCalled()
    })
  })

  describe('rendering', () => {
    it('should not show cancel button for completed items', () => {
      batchQueue = new BatchQueueComponent(container)

      const mockItems = [{ index: 0, filename: 'test1.jpg', status: 'completed' }]

      batchQueue.setItems(mockItems)

      const cancelBtn = container.querySelector('#queue-item-0 button[aria-label*="Cancel"]')
      expect(cancelBtn).toBeNull()
    })

    it('should show progress bar only for pending/processing', () => {
      batchQueue = new BatchQueueComponent(container)

      const mockItems = [
        { index: 0, filename: 'test1.jpg', status: 'pending' },
        { index: 1, filename: 'test2.jpg', status: 'completed' },
      ]

      batchQueue.setItems(mockItems)

      const pendingProgress = container.querySelector('#queue-item-0 .bg-gray-200')
      const completedProgress = container.querySelector('#queue-item-1 .bg-gray-200')

      expect(pendingProgress).toBeTruthy()
      expect(completedProgress).toBeNull()
    })

    it('should show error message for failed items', () => {
      batchQueue = new BatchQueueComponent(container)

      const mockItems = [
        { index: 0, filename: 'test1.jpg', status: 'failed', error: 'Conversion error' },
      ]

      batchQueue.setItems(mockItems)

      // Find error message specifically (not status text)
      // The error message is the last paragraph with text-xs and text-red-600
      const allRedTexts = container.querySelectorAll('#queue-item-0 .text-red-600')
      const errorMsg = Array.from(allRedTexts).find(
        (el) =>
          el.tagName === 'P' && el.className.includes('text-xs') && el.className.includes('mt-2') // Error messages have mt-2
      )
      expect(errorMsg).toBeTruthy()
      expect(errorMsg.textContent).toBe('Conversion error')
    })
  })

  describe('reset', () => {
    it('should clear all data on reset', () => {
      batchQueue = new BatchQueueComponent(container)

      const mockItems = [{ index: 0, filename: 'test1.jpg', status: 'pending' }]

      batchQueue.setItems(mockItems)
      batchQueue.setJobId('test-job-id')

      batchQueue.reset()

      expect(batchQueue.items).toEqual([])
      expect(batchQueue.jobId).toBeNull()
      expect(container.classList.contains('hidden')).toBe(true)
    })
  })
})
