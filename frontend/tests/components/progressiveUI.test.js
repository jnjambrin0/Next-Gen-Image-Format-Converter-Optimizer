import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { ProgressiveUI } from '../../src/components/progressiveUI.js'

describe('ProgressiveUI', () => {
  let progressiveUI
  let toggleButton
  let advancedContainer
  let basicContainer

  beforeEach(() => {
    // Mock matchMedia for reduced motion tests
    window.matchMedia = vi.fn().mockImplementation(query => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }))
    
    // Create DOM elements
    toggleButton = document.createElement('button')
    advancedContainer = document.createElement('div')
    basicContainer = document.createElement('div')

    document.body.appendChild(toggleButton)
    document.body.appendChild(advancedContainer)
    document.body.appendChild(basicContainer)

    progressiveUI = new ProgressiveUI()
  })

  afterEach(() => {
    document.body.innerHTML = ''
    vi.clearAllMocks()
  })

  describe('initialization', () => {
    it('should initialize with default state', () => {
      const onModeChange = vi.fn()

      progressiveUI.init({
        toggleButton,
        advancedContainer,
        basicContainer,
        onModeChange,
      })

      expect(progressiveUI.isAdvancedMode).toBe(false)
      expect(advancedContainer.style.display).toBe('none')
      expect(toggleButton.getAttribute('aria-expanded')).toBe('false')
    })

    it('should setup event listeners', async () => {
      const onModeChange = vi.fn()

      progressiveUI.init({
        toggleButton,
        advancedContainer,
        basicContainer,
        onModeChange,
      })

      // Click toggle button
      toggleButton.click()

      // Wait for async operations
      await vi.waitFor(() => {
        expect(onModeChange).toHaveBeenCalledWith(true)
      })
      
      expect(progressiveUI.isAdvancedMode).toBe(true)
    })
  })

  describe('toggleMode', () => {
    it('should toggle between basic and advanced modes', async () => {
      const onModeChange = vi.fn()

      progressiveUI.init({
        toggleButton,
        advancedContainer,
        basicContainer,
        onModeChange,
      })

      // Initially in basic mode
      expect(progressiveUI.isAdvancedMode).toBe(false)

      // Toggle to advanced
      await progressiveUI.toggleMode()
      expect(progressiveUI.isAdvancedMode).toBe(true)
      expect(advancedContainer.style.display).toBe('block')

      // Toggle back to basic
      await progressiveUI.toggleMode()
      expect(progressiveUI.isAdvancedMode).toBe(false)
    })

    it('should update toggle button text and icon', async () => {
      progressiveUI.init({
        toggleButton,
        advancedContainer,
        basicContainer,
        onModeChange: vi.fn(),
      })

      // Check initial state
      expect(toggleButton.textContent).toContain('Show Advanced Settings')

      // Toggle to advanced
      await progressiveUI.toggleMode()
      expect(toggleButton.textContent).toContain('Hide Advanced Settings')
      expect(toggleButton.querySelector('svg')).toBeTruthy()
    })
  })

  describe('setMode', () => {
    it('should set mode programmatically', async () => {
      const onModeChange = vi.fn()

      progressiveUI.init({
        toggleButton,
        advancedContainer,
        basicContainer,
        onModeChange,
      })

      // Set to advanced mode
      await progressiveUI.setMode(true)
      expect(progressiveUI.isAdvancedMode).toBe(true)
      expect(onModeChange).toHaveBeenCalledWith(true)

      // Set to same mode (should not trigger change)
      onModeChange.mockClear()
      await progressiveUI.setMode(true)
      expect(onModeChange).not.toHaveBeenCalled()
    })
  })

  describe('animations', () => {
    it('should respect prefers-reduced-motion', () => {
      // Mock matchMedia
      const mockMatchMedia = vi.fn().mockReturnValue({
        matches: true,
      })
      window.matchMedia = mockMatchMedia

      progressiveUI.updateAnimationDuration()
      expect(progressiveUI.animationDuration).toBe(0)

      // Reset
      mockMatchMedia.mockReturnValue({ matches: false })
      progressiveUI.updateAnimationDuration()
      expect(progressiveUI.animationDuration).toBe(300)
    })
  })

  describe('cleanup', () => {
    it('should remove event listeners on destroy', () => {
      const onModeChange = vi.fn()

      progressiveUI.init({
        toggleButton,
        advancedContainer,
        basicContainer,
        onModeChange,
      })

      progressiveUI.destroy()

      // Click should not trigger after destroy
      onModeChange.mockClear()
      toggleButton.click()
      expect(onModeChange).not.toHaveBeenCalled()
    })
  })
})
