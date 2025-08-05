import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { FileListPreview } from '../../src/components/fileListPreview.js'

describe('FileListPreview', () => {
  let container
  let fileListPreview

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
  })

  afterEach(() => {
    document.body.removeChild(container)
  })

  describe('initialization', () => {
    it('should create empty file list', () => {
      fileListPreview = new FileListPreview(container)

      expect(fileListPreview.files).toEqual([])
      expect(container.classList.contains('hidden')).toBe(true)
    })
  })

  describe('file management', () => {
    it('should set files and render', () => {
      fileListPreview = new FileListPreview(container)

      const files = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)

      expect(fileListPreview.files).toHaveLength(2)
      expect(container.classList.contains('hidden')).toBe(false)
      expect(container.querySelector('h3').textContent).toBe('Selected Files (2)')
    })

    it('should add files to existing list', () => {
      fileListPreview = new FileListPreview(container)

      const initialFiles = [new File(['test1'], 'test1.jpg', { type: 'image/jpeg' })]
      fileListPreview.setFiles(initialFiles)

      const newFiles = [new File(['test2'], 'test2.png', { type: 'image/png' })]
      fileListPreview.addFiles(newFiles)

      expect(fileListPreview.files).toHaveLength(2)
      expect(container.querySelector('h3').textContent).toBe('Selected Files (2)')
    })

    it('should remove file by index', () => {
      fileListPreview = new FileListPreview(container)
      const onRemoveCallback = vi.fn()
      fileListPreview.onRemove(onRemoveCallback)

      const files = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)
      fileListPreview.removeFile(0)

      expect(fileListPreview.files).toHaveLength(1)
      expect(fileListPreview.files[0].name).toBe('test2.png')
      expect(onRemoveCallback).toHaveBeenCalledWith(files[0], 0)
    })

    it('should clear all files', () => {
      fileListPreview = new FileListPreview(container)
      const onClearAllCallback = vi.fn()
      fileListPreview.onClearAll(onClearAllCallback)

      const files = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)
      fileListPreview.clearAll()

      expect(fileListPreview.files).toHaveLength(0)
      expect(container.classList.contains('hidden')).toBe(true)
      expect(onClearAllCallback).toHaveBeenCalled()
    })
  })

  describe('rendering', () => {
    it('should render file items with correct information', () => {
      fileListPreview = new FileListPreview(container)

      const files = [
        new File(['x'.repeat(1024)], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['x'.repeat(2048)], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)

      const fileItems = container.querySelectorAll('.space-y-2 > div')
      expect(fileItems).toHaveLength(2)

      // Check first file
      const firstItem = fileItems[0]
      expect(firstItem.querySelector('p').textContent).toBe('test1.jpg')
      expect(firstItem.querySelector('p:last-child').textContent).toBe('1 KB')

      // Check second file
      const secondItem = fileItems[1]
      expect(secondItem.querySelector('p').textContent).toBe('test2.png')
      expect(secondItem.querySelector('p:last-child').textContent).toBe('2 KB')
    })

    it('should have remove buttons for each file', () => {
      fileListPreview = new FileListPreview(container)

      const files = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)

      const removeButtons = container.querySelectorAll('button[aria-label^="Remove"]')
      expect(removeButtons).toHaveLength(2)

      // Click first remove button
      removeButtons[0].click()

      expect(fileListPreview.files).toHaveLength(1)
      expect(fileListPreview.files[0].name).toBe('test2.png')
    })

    it('should have clear all button', () => {
      fileListPreview = new FileListPreview(container)

      const files = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)

      const clearButton = container.querySelector('button:not([aria-label])')
      expect(clearButton.textContent).toBe('Clear All')

      clearButton.click()

      expect(fileListPreview.files).toHaveLength(0)
    })
  })

  describe('utility methods', () => {
    it('should format file sizes correctly', () => {
      fileListPreview = new FileListPreview(container)

      expect(fileListPreview.formatFileSize(0)).toBe('0 Bytes')
      expect(fileListPreview.formatFileSize(500)).toBe('500 Bytes')
      expect(fileListPreview.formatFileSize(1024)).toBe('1 KB')
      expect(fileListPreview.formatFileSize(1536)).toBe('1.5 KB')
      expect(fileListPreview.formatFileSize(1048576)).toBe('1 MB')
      expect(fileListPreview.formatFileSize(10 * 1024 * 1024)).toBe('10 MB')
    })

    it('should calculate total size', () => {
      fileListPreview = new FileListPreview(container)

      const files = [
        new File(['x'.repeat(1024)], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['x'.repeat(2048)], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)

      expect(fileListPreview.getTotalSize()).toBe(3072)
    })

    it('should get file count', () => {
      fileListPreview = new FileListPreview(container)

      const files = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' }),
      ]

      fileListPreview.setFiles(files)

      expect(fileListPreview.getFileCount()).toBe(2)
    })
  })
})
