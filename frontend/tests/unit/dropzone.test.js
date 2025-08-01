import { describe, it, expect, beforeEach, vi } from 'vitest'
import { DropZone } from '../../src/components/dropzone.js'

describe('DropZone', () => {
  let container
  let dropzone

  beforeEach(() => {
    // Create DOM structure
    container = document.createElement('div')
    container.innerHTML = `
      <div id="dropzone" role="button" tabindex="0">
        <input type="file" id="fileInput" class="sr-only" accept="image/*" />
        <p>Drag and drop images here</p>
      </div>
    `
    document.body.appendChild(container)

    const dropzoneElement = container.querySelector('#dropzone')
    dropzone = new DropZone(dropzoneElement)
  })

  afterEach(() => {
    document.body.removeChild(container)
  })

  describe('Drag and Drop Events', () => {
    it('should add active class on drag enter', () => {
      const event = new DragEvent('dragenter', {
        dataTransfer: new DataTransfer(),
      })

      dropzone.element.dispatchEvent(event)

      expect(dropzone.element.classList.contains('dropzone-active')).toBe(true)
      expect(dropzone.isDragging).toBe(true)
    })

    it('should prevent default on drag over', () => {
      const event = new DragEvent('dragover', {
        dataTransfer: new DataTransfer(),
      })
      const preventDefaultSpy = vi.spyOn(event, 'preventDefault')

      dropzone.element.dispatchEvent(event)

      expect(preventDefaultSpy).toHaveBeenCalled()
    })

    it('should remove active class on drag leave when leaving dropzone', () => {
      // First set to dragging state
      dropzone.isDragging = true
      dropzone.element.classList.add('dropzone-active')

      const rect = dropzone.element.getBoundingClientRect()
      const event = new DragEvent('dragleave', {
        clientX: rect.left - 10, // Outside the element
        clientY: rect.top,
      })

      dropzone.element.dispatchEvent(event)

      expect(dropzone.element.classList.contains('dropzone-active')).toBe(false)
      expect(dropzone.isDragging).toBe(false)
    })

    it('should handle file drop', () => {
      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' })
      const dataTransfer = new DataTransfer()
      dataTransfer.items.add(file)

      const event = new DragEvent('drop', {
        dataTransfer: dataTransfer,
      })

      const fileSelectCallback = vi.fn()
      dropzone.onFileSelect(fileSelectCallback)

      dropzone.element.dispatchEvent(event)

      expect(fileSelectCallback).toHaveBeenCalledWith(file)
      expect(dropzone.element.classList.contains('dropzone-active')).toBe(false)
    })
  })

  describe('Click Events', () => {
    it('should trigger file input click on element click', () => {
      const clickSpy = vi.spyOn(dropzone.fileInput, 'click')

      dropzone.element.click()

      expect(clickSpy).toHaveBeenCalled()
    })

    it('should not trigger file input click when clicking the file input itself', () => {
      const clickSpy = vi.spyOn(dropzone.fileInput, 'click')

      const event = new MouseEvent('click', { bubbles: true })
      Object.defineProperty(event, 'target', { value: dropzone.fileInput })

      dropzone.handleClick(event)

      expect(clickSpy).not.toHaveBeenCalled()
    })
  })

  describe('Keyboard Events', () => {
    it('should trigger file input on Enter key', () => {
      const clickSpy = vi.spyOn(dropzone.fileInput, 'click')

      const event = new KeyboardEvent('keydown', { key: 'Enter' })
      dropzone.element.dispatchEvent(event)

      expect(clickSpy).toHaveBeenCalled()
    })

    it('should trigger file input on Space key', () => {
      const clickSpy = vi.spyOn(dropzone.fileInput, 'click')

      const event = new KeyboardEvent('keydown', { key: ' ' })
      dropzone.element.dispatchEvent(event)

      expect(clickSpy).toHaveBeenCalled()
    })

    it('should not trigger file input on other keys', () => {
      const clickSpy = vi.spyOn(dropzone.fileInput, 'click')

      const event = new KeyboardEvent('keydown', { key: 'a' })
      dropzone.element.dispatchEvent(event)

      expect(clickSpy).not.toHaveBeenCalled()
    })
  })

  describe('File Input Change', () => {
    it('should process files when file input changes', () => {
      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' })
      const fileSelectCallback = vi.fn()
      dropzone.onFileSelect(fileSelectCallback)

      // Create a mock FileList
      Object.defineProperty(dropzone.fileInput, 'files', {
        value: [file],
        writable: false,
      })

      const event = new Event('change')
      dropzone.fileInput.dispatchEvent(event)

      expect(fileSelectCallback).toHaveBeenCalledWith(file)
    })

    it('should not call callback when no files selected', () => {
      const fileSelectCallback = vi.fn()
      dropzone.onFileSelect(fileSelectCallback)

      Object.defineProperty(dropzone.fileInput, 'files', {
        value: [],
        writable: false,
      })

      const event = new Event('change')
      dropzone.fileInput.dispatchEvent(event)

      expect(fileSelectCallback).not.toHaveBeenCalled()
    })
  })

  describe('Reset', () => {
    it('should reset the dropzone state', () => {
      dropzone.fileInput.value = 'test.jpg'
      dropzone.element.classList.add('dropzone-active')

      dropzone.reset()

      expect(dropzone.fileInput.value).toBe('')
      expect(dropzone.element.classList.contains('dropzone-active')).toBe(false)
    })
  })

  describe('Destroy', () => {
    it('should remove all event listeners and clear references', () => {
      const removeEventListenerSpy = vi.spyOn(dropzone.element, 'removeEventListener')
      const fileInputRemoveEventListenerSpy = vi.spyOn(dropzone.fileInput, 'removeEventListener')

      dropzone.destroy()

      // Check that event listeners were removed
      expect(removeEventListenerSpy).toHaveBeenCalledWith('dragenter', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('dragover', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('dragleave', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('drop', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('click', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function))
      expect(fileInputRemoveEventListenerSpy).toHaveBeenCalledWith('change', expect.any(Function))

      // Check that references were cleared
      expect(dropzone.element).toBeNull()
      expect(dropzone.fileInput).toBeNull()
      expect(dropzone.onFileSelectCallback).toBeNull()
      expect(dropzone.uiStateManager).toBeNull()
    })
  })
})
