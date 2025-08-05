import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { DropZone } from '../../src/components/dropzone.js'

// Mock DataTransferItemList if not available
if (typeof DataTransferItemList === 'undefined') {
  global.DataTransferItemList = class DataTransferItemList {}
}

describe('DropZone', () => {
  let container
  let dropzone
  
  beforeEach(() => {
    // Create DOM structure
    container = document.createElement('div')
    container.innerHTML = `
      <div id="dropzone">
        <input type="file" id="fileInput" />
      </div>
      <div id="errorMessage" class="hidden"></div>
    `
    document.body.appendChild(container)
  })
  
  afterEach(() => {
    if (dropzone) {
      dropzone.destroy()
    }
    document.body.removeChild(container)
  })
  
  describe('initialization', () => {
    it('should initialize with default values', () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      expect(dropzone.element).toBe(element)
      expect(dropzone.fileInput).toBe(container.querySelector('#fileInput'))
      expect(dropzone.isDragging).toBe(false)
      expect(dropzone.maxFileCount).toBe(100)
      expect(dropzone.maxFileSize).toBe(50 * 1024 * 1024)
    })
    
    it('should bind all event handlers', () => {
      const element = container.querySelector('#dropzone')
      const addEventListenerSpy = vi.spyOn(element, 'addEventListener')
      
      dropzone = new DropZone(element)
      
      expect(addEventListenerSpy).toHaveBeenCalledWith('dragenter', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('dragover', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('dragleave', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('drop', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('click', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function))
    })
  })
  
  describe('drag and drop', () => {
    it('should add active class on drag enter', () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      const event = new Event('dragenter')
      event.preventDefault = vi.fn()
      event.stopPropagation = vi.fn()
      
      element.dispatchEvent(event)
      
      expect(element.classList.contains('dropzone-active')).toBe(true)
      expect(dropzone.isDragging).toBe(true)
    })
    
    it('should remove active class on drag leave', () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      // First enter
      element.classList.add('dropzone-active')
      dropzone.isDragging = true
      
      // Create leave event
      const event = new Event('dragleave')
      event.preventDefault = vi.fn()
      event.stopPropagation = vi.fn()
      event.clientX = -100
      event.clientY = -100
      
      // Mock getBoundingClientRect
      element.getBoundingClientRect = vi.fn(() => ({
        left: 0,
        right: 100,
        top: 0,
        bottom: 100
      }))
      
      element.dispatchEvent(event)
      
      expect(element.classList.contains('dropzone-active')).toBe(false)
      expect(dropzone.isDragging).toBe(false)
    })
  })
  
  describe('file processing', () => {
    it('should filter valid image files', () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      const files = [
        { name: 'image.jpg', size: 1024 * 1024 },
        { name: 'image.png', size: 2 * 1024 * 1024 },
        { name: 'document.pdf', size: 1024 * 1024 },
        { name: 'huge.jpg', size: 100 * 1024 * 1024 },
        { name: 'image.webp', size: 1024 * 1024 }
      ]
      
      const validFiles = dropzone.filterValidImageFiles(files)
      
      expect(validFiles).toHaveLength(3)
      expect(validFiles[0].name).toBe('image.jpg')
      expect(validFiles[1].name).toBe('image.png')
      expect(validFiles[2].name).toBe('image.webp')
    })
    
    it('should handle single file selection', async () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      const callback = vi.fn()
      dropzone.onFileSelect(callback)
      
      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' })
      await dropzone.processFiles([file])
      
      expect(callback).toHaveBeenCalledWith(file)
    })
    
    it('should handle multiple file selection', async () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      const multiCallback = vi.fn()
      dropzone.onMultipleFilesSelect(multiCallback)
      
      const files = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' })
      ]
      
      await dropzone.processFiles(files)
      
      expect(multiCallback).toHaveBeenCalledWith(files)
    })
    
    it('should show error for too many files', async () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      // Mock window.DataTransferItemList
      global.DataTransferItemList = class DataTransferItemList {}
      
      // Create 101 mock files
      const files = Array.from({ length: 101 }, (_, i) => 
        new File(['test'], `test${i}.jpg`, { type: 'image/jpeg' })
      )
      
      await dropzone.processFiles(files)
      
      const errorEl = container.querySelector('#errorMessage')
      expect(errorEl.classList.contains('hidden')).toBe(false)
      expect(errorEl.textContent).toContain('Maximum 100 files allowed')
    })
  })
  
  describe('keyboard accessibility', () => {
    it('should trigger file input on Enter key', () => {
      const element = container.querySelector('#dropzone')
      const fileInput = container.querySelector('#fileInput')
      dropzone = new DropZone(element)
      
      const clickSpy = vi.spyOn(fileInput, 'click')
      
      const event = new KeyboardEvent('keydown', { key: 'Enter' })
      event.preventDefault = vi.fn()
      
      element.dispatchEvent(event)
      
      expect(clickSpy).toHaveBeenCalled()
      expect(event.preventDefault).toHaveBeenCalled()
    })
    
    it('should trigger file input on Space key', () => {
      const element = container.querySelector('#dropzone')
      const fileInput = container.querySelector('#fileInput')
      dropzone = new DropZone(element)
      
      const clickSpy = vi.spyOn(fileInput, 'click')
      
      const event = new KeyboardEvent('keydown', { key: ' ' })
      event.preventDefault = vi.fn()
      
      element.dispatchEvent(event)
      
      expect(clickSpy).toHaveBeenCalled()
      expect(event.preventDefault).toHaveBeenCalled()
    })
  })
  
  describe('cleanup', () => {
    it('should remove all event listeners on destroy', () => {
      const element = container.querySelector('#dropzone')
      dropzone = new DropZone(element)
      
      const removeEventListenerSpy = vi.spyOn(element, 'removeEventListener')
      const fileInputRemoveEventListenerSpy = vi.spyOn(dropzone.fileInput, 'removeEventListener')
      
      dropzone.destroy()
      
      expect(removeEventListenerSpy).toHaveBeenCalledWith('dragenter', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('dragover', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('dragleave', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('drop', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('click', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function))
      expect(fileInputRemoveEventListenerSpy).toHaveBeenCalledWith('change', expect.any(Function))
    })
  })
})