import { describe, it, expect } from 'vitest'
import { createErrorMessage, createSuccessMessage } from '../../src/components/uiMessages.js'

describe('UI Messages Components', () => {
  describe('createErrorMessage', () => {
    it('should create error message element with single error', () => {
      const errors = ['File type not supported']
      const element = createErrorMessage(errors)

      expect(element).toBeInstanceOf(HTMLElement)
      expect(element.className).toContain('bg-red-50')
      expect(element.textContent).toContain('Error:')
      expect(element.textContent).toContain('File type not supported')
    })

    it('should create error message element with multiple errors', () => {
      const errors = ['File type not supported', 'File size too large']
      const element = createErrorMessage(errors)

      expect(element.textContent).toContain('File type not supported, File size too large')
    })

    it('should sanitize error messages to prevent XSS', () => {
      const errors = ['<script>alert("XSS")</script>']
      const element = createErrorMessage(errors)

      expect(element.innerHTML).not.toContain('<script>')
      expect(element.textContent).toContain('<script>alert("XSS")</script>')
    })

    it('should include SVG icon', () => {
      const errors = ['Test error']
      const element = createErrorMessage(errors)
      const svg = element.querySelector('svg')

      expect(svg).toBeTruthy()
      expect(svg.getAttribute('class')).toContain('text-red-400')
    })
  })

  describe('createSuccessMessage', () => {
    it('should create success message element', () => {
      const fileName = 'test.jpg'
      const fileSize = '2.5 MB'
      const element = createSuccessMessage(fileName, fileSize)

      expect(element).toBeInstanceOf(HTMLElement)
      expect(element.className).toContain('bg-green-50')
      expect(element.textContent).toContain('File ready:')
      expect(element.textContent).toContain('test.jpg (2.5 MB)')
    })

    it('should sanitize file name to prevent XSS', () => {
      const fileName = '<img src=x onerror=alert("XSS")>'
      const fileSize = '1 MB'
      const element = createSuccessMessage(fileName, fileSize)

      expect(element.innerHTML).not.toContain('<img')
      expect(element.innerHTML).not.toContain('onerror')
      expect(element.textContent).toContain('<img src=x onerror=alert("XSS")>')
    })

    it('should include SVG icon', () => {
      const element = createSuccessMessage('test.jpg', '1 MB')
      const svg = element.querySelector('svg')

      expect(svg).toBeTruthy()
      expect(svg.getAttribute('class')).toContain('text-green-400')
    })
  })
})
