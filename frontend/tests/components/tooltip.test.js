import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Tooltip } from '../../src/components/tooltip.js'

describe('Tooltip', () => {
  let tooltip
  let element

  beforeEach(() => {
    tooltip = new Tooltip()
    element = document.createElement('button')
    element.textContent = 'Test Button'
    document.body.appendChild(element)
  })

  afterEach(() => {
    document.body.innerHTML = ''
    tooltip.removeAll()
  })

  describe('create', () => {
    it('should create tooltip for element', () => {
      tooltip.create(element, {
        content: 'Test tooltip',
        position: 'top',
        delay: 100,
      })

      expect(tooltip.activeTooltips.has(element)).toBe(true)
    })

    it('should attach event listeners', () => {
      const addEventListenerSpy = vi.spyOn(element, 'addEventListener')

      tooltip.create(element, {
        content: 'Test tooltip',
      })

      expect(addEventListenerSpy).toHaveBeenCalledWith('mouseenter', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('mouseleave', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('focus', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('blur', expect.any(Function))
      expect(addEventListenerSpy).toHaveBeenCalledWith('touchstart', expect.any(Function))
    })
  })

  describe('show/hide', () => {
    beforeEach(() => {
      tooltip.create(element, {
        content: 'Test tooltip',
        delay: 0,
      })
    })

    it('should show tooltip on mouseenter', async () => {
      const tooltipData = tooltip.activeTooltips.get(element)

      // Trigger mouseenter
      element.dispatchEvent(new MouseEvent('mouseenter'))

      // Wait for delay
      await new Promise((resolve) => setTimeout(resolve, 10))

      expect(tooltipData.isVisible).toBe(true)
      expect(document.querySelector('.tooltip')).toBeTruthy()
    })

    it('should hide tooltip on mouseleave', async () => {
      const tooltipData = tooltip.activeTooltips.get(element)

      // Show tooltip first
      tooltip.show(tooltipData)
      expect(tooltipData.isVisible).toBe(true)

      // Trigger mouseleave
      element.dispatchEvent(new MouseEvent('mouseleave'))

      // Wait for animation
      await new Promise((resolve) => setTimeout(resolve, 250))

      expect(tooltipData.isVisible).toBe(false)
      expect(document.querySelector('.tooltip')).toBeFalsy()
    })

    it('should show tooltip on focus', () => {
      const tooltipData = tooltip.activeTooltips.get(element)

      // Trigger focus
      element.dispatchEvent(new FocusEvent('focus'))

      expect(tooltipData.isVisible).toBe(true)
    })

    it('should hide tooltip on blur', () => {
      const tooltipData = tooltip.activeTooltips.get(element)

      // Show tooltip first
      tooltip.show(tooltipData)

      // Trigger blur
      element.dispatchEvent(new FocusEvent('blur'))

      expect(tooltipData.isVisible).toBe(false)
    })
  })

  describe('positioning', () => {
    beforeEach(() => {
      // Mock element position
      element.getBoundingClientRect = vi.fn().mockReturnValue({
        left: 100,
        top: 100,
        right: 200,
        bottom: 120,
        width: 100,
        height: 20,
      })
    })

    it('should position tooltip above element by default', () => {
      tooltip.create(element, {
        content: 'Test tooltip',
        position: 'top',
      })

      const tooltipData = tooltip.activeTooltips.get(element)
      tooltip.show(tooltipData)

      const tooltipEl = document.querySelector('.tooltip')
      expect(tooltipEl).toBeTruthy()

      // Check if positioned above
      const top = parseFloat(tooltipEl.style.top)
      expect(top).toBeLessThan(100) // Above the element
    })

    it('should fallback to other positions if preferred doesnt fit', () => {
      // Mock window size to force fallback
      Object.defineProperty(window, 'innerHeight', {
        value: 50,
        configurable: true,
      })

      tooltip.create(element, {
        content: 'Test tooltip',
        position: 'top', // Won't fit above
      })

      const tooltipData = tooltip.activeTooltips.get(element)
      tooltip.show(tooltipData)

      const tooltipEl = document.querySelector('.tooltip')
      expect(tooltipEl).toBeTruthy()
    })
  })

  describe('Security - HTML content', () => {
    it('should always escape HTML content for security', () => {
      tooltip.create(element, {
        content: '<strong>Bold</strong> text',
      })

      const tooltipData = tooltip.activeTooltips.get(element)
      tooltip.show(tooltipData)

      const tooltipEl = document.querySelector('.tooltip')
      // Security fix: HTML is always escaped to prevent XSS
      expect(tooltipEl.textContent).toBe('<strong>Bold</strong> text')
      expect(tooltipEl.innerHTML).not.toContain('<strong>')
    })

    it('should prevent XSS attacks through tooltip content', () => {
      const maliciousContent = '<img src=x onerror="alert(\'XSS\')">'
      tooltip.create(element, {
        content: maliciousContent,
      })

      const tooltipData = tooltip.activeTooltips.get(element)
      tooltip.show(tooltipData)

      const tooltipEl = document.querySelector('.tooltip')
      expect(tooltipEl.textContent).toBe(maliciousContent)
      // Check that the malicious script is escaped as text, not executed
      expect(tooltipEl.innerHTML).toContain('&lt;img')
      expect(tooltipEl.innerHTML).not.toContain('<img')
    })
  })

  describe('createHelpIcon', () => {
    it('should create help icon with tooltip', () => {
      const helpIcon = Tooltip.createHelpIcon('Help text')

      expect(helpIcon.tagName.toLowerCase()).toBe('span')
      expect(helpIcon.querySelector('svg')).toBeTruthy()
      expect(helpIcon.getAttribute('tabindex')).toBe('0')
      expect(helpIcon.getAttribute('role')).toBe('button')
    })
  })

  describe('cleanup', () => {
    it('should remove tooltip from element', () => {
      tooltip.create(element, { content: 'Test' })

      expect(tooltip.activeTooltips.has(element)).toBe(true)

      tooltip.remove(element)

      expect(tooltip.activeTooltips.has(element)).toBe(false)
    })

    it('should remove all tooltips', () => {
      const element2 = document.createElement('button')
      document.body.appendChild(element2)

      tooltip.create(element, { content: 'Test 1' })
      tooltip.create(element2, { content: 'Test 2' })

      expect(tooltip.activeTooltips.size).toBe(2)

      tooltip.removeAll()

      expect(tooltip.activeTooltips.size).toBe(0)
    })

    it('should properly clean up event listeners on remove', () => {
      const removeEventListenerSpy = vi.spyOn(element, 'removeEventListener')

      tooltip.create(element, { content: 'Test tooltip' })
      tooltip.remove(element)

      expect(removeEventListenerSpy).toHaveBeenCalledWith('mouseenter', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('mouseleave', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('focus', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('blur', expect.any(Function))
      expect(removeEventListenerSpy).toHaveBeenCalledWith('touchstart', expect.any(Function))
      expect(tooltip.activeTooltips.has(element)).toBe(false)
    })
  })
})
