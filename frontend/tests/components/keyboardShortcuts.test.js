import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { KeyboardShortcuts } from '../../src/components/keyboardShortcuts.js'

describe('KeyboardShortcuts', () => {
  let shortcuts

  beforeEach(() => {
    shortcuts = new KeyboardShortcuts()
    shortcuts.init()
  })

  afterEach(() => {
    shortcuts.destroy()
  })

  describe('initialization', () => {
    it('should initialize and start listening', () => {
      const newShortcuts = new KeyboardShortcuts()
      expect(newShortcuts.isListening).toBe(false)

      newShortcuts.init()
      expect(newShortcuts.isListening).toBe(true)

      newShortcuts.destroy()
    })

    it('should not double-initialize', () => {
      const addEventListenerSpy = vi.spyOn(document, 'addEventListener')

      shortcuts.init() // Already initialized in beforeEach

      // Should not add listener again
      expect(addEventListenerSpy).not.toHaveBeenCalled()
    })
  })

  describe('register/unregister', () => {
    it('should register a shortcut', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'a',
        ctrl: true,
        handler,
        description: 'Test shortcut',
      })

      expect(shortcuts.shortcuts.has('ctrl+a')).toBe(true)
    })

    it('should unregister a shortcut', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'a',
        ctrl: true,
        handler,
      })

      expect(shortcuts.shortcuts.has('ctrl+a')).toBe(true)

      shortcuts.unregister({
        key: 'a',
        ctrl: true,
      })

      expect(shortcuts.shortcuts.has('ctrl+a')).toBe(false)
    })
  })

  describe('key handling', () => {
    it('should trigger shortcut handler on keydown', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'k',
        ctrl: true,
        handler,
      })

      // Simulate Ctrl+K
      const event = new KeyboardEvent('keydown', {
        key: 'k',
        ctrlKey: true,
      })

      document.dispatchEvent(event)

      expect(handler).toHaveBeenCalledWith(event)
    })

    it('should handle modifier keys correctly', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 's',
        ctrl: true,
        shift: true,
        handler,
      })

      // Wrong modifier combination
      document.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 's',
          ctrlKey: true,
          shiftKey: false,
        })
      )

      expect(handler).not.toHaveBeenCalled()

      // Correct combination
      document.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 's',
          ctrlKey: true,
          shiftKey: true,
        })
      )

      expect(handler).toHaveBeenCalled()
    })

    it('should normalize special keys', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'esc',
        handler,
      })

      document.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'Escape',
        })
      )

      expect(handler).toHaveBeenCalled()
    })

    it('should ignore shortcuts when disabled', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'a',
        handler,
      })

      shortcuts.setEnabled(false)

      document.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'a',
        })
      )

      expect(handler).not.toHaveBeenCalled()
    })

    it('should ignore shortcuts when modal is open', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'a',
        handler,
      })

      shortcuts.setModalOpen(true)

      document.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'a',
        })
      )

      expect(handler).not.toHaveBeenCalled()
    })

    it('should ignore shortcuts in input fields unless ctrl/cmd', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'a',
        handler,
      })

      const input = document.createElement('input')
      document.body.appendChild(input)
      input.focus()

      // Regular key in input - should be ignored
      input.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'a',
          bubbles: true,
        })
      )

      expect(handler).not.toHaveBeenCalled()

      // Ctrl+A in input - should work
      shortcuts.register({
        key: 'a',
        ctrl: true,
        handler,
      })

      input.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'a',
          ctrlKey: true,
          bubbles: true,
        })
      )

      expect(handler).toHaveBeenCalled()

      document.body.removeChild(input)
    })
  })

  describe('getShortcuts', () => {
    it('should return all registered shortcuts', () => {
      shortcuts.register({
        key: 'a',
        ctrl: true,
        description: 'Test A',
        category: 'Test',
      })

      shortcuts.register({
        key: 'b',
        shift: true,
        description: 'Test B',
      })

      const allShortcuts = shortcuts.getShortcuts()

      expect(allShortcuts).toHaveLength(2)
      expect(allShortcuts[0]).toMatchObject({
        key: 'a',
        ctrl: true,
        description: 'Test A',
        category: 'Test',
      })
      expect(allShortcuts[1]).toMatchObject({
        key: 'b',
        shift: true,
        description: 'Test B',
        category: 'General',
      })
    })
  })

  describe('getDisplayKey', () => {
    it('should format key combinations for display', () => {
      const shortcut = {
        key: 'a',
        ctrl: true,
        shift: true,
      }

      const display = shortcuts.getDisplayKey(shortcut)

      // Should contain Ctrl/Cmd and Shift symbols
      expect(display).toMatch(/Ctrl|⌘/)
      expect(display).toMatch(/⇧/)
      expect(display).toContain('A')
    })

    it('should detect Mac platform', () => {
      // Mock Mac platform
      Object.defineProperty(navigator, 'platform', {
        value: 'MacIntel',
        configurable: true,
      })

      const shortcut = {
        key: 'a',
        ctrl: true,
      }

      const display = shortcuts.getDisplayKey(shortcut)
      expect(display).toContain('⌘') // Mac command symbol
    })
  })

  describe('showHelp', () => {
    it('should create help modal', () => {
      shortcuts.register({
        key: 'a',
        ctrl: true,
        description: 'Test shortcut',
        category: 'Testing',
      })

      shortcuts.showHelp()

      const modal = document.querySelector('.fixed.inset-0')
      expect(modal).toBeTruthy()
      expect(modal.textContent).toContain('Keyboard Shortcuts')
      expect(modal.textContent).toContain('Test shortcut')
      expect(modal.textContent).toContain('Testing')

      shortcuts.hideHelp()
    })

    it('should close help modal on background click', () => {
      shortcuts.showHelp()

      const modal = document.querySelector('.fixed.inset-0')
      expect(modal).toBeTruthy()

      // Click on modal background
      modal.click()

      expect(document.querySelector('.fixed.inset-0')).toBeFalsy()
    })
  })

  describe('registerDefaults', () => {
    it('should register default shortcuts', () => {
      const newShortcuts = new KeyboardShortcuts()
      newShortcuts.init()

      KeyboardShortcuts.registerDefaults(newShortcuts)

      // Check some default shortcuts exist
      expect(newShortcuts.shortcuts.has('ctrl+k')).toBe(true)
      expect(newShortcuts.shortcuts.has('ctrl+enter')).toBe(true)
      expect(newShortcuts.shortcuts.has('shift+?')).toBe(true)

      newShortcuts.destroy()
    })

    it('should dispatch custom events for shortcuts', () => {
      const eventListener = vi.fn()
      window.addEventListener('shortcut:toggleAdvanced', eventListener)

      KeyboardShortcuts.registerDefaults(shortcuts)

      // Trigger Ctrl+K
      document.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'k',
          ctrlKey: true,
        })
      )

      expect(eventListener).toHaveBeenCalled()

      window.removeEventListener('shortcut:toggleAdvanced', eventListener)
    })
  })

  describe('cleanup', () => {
    it('should clean up on destroy', () => {
      const handler = vi.fn()

      shortcuts.register({
        key: 'a',
        handler,
      })

      shortcuts.destroy()

      expect(shortcuts.isListening).toBe(false)
      expect(shortcuts.shortcuts.size).toBe(0)

      // Should not trigger after destroy
      document.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'a',
        })
      )

      expect(handler).not.toHaveBeenCalled()
    })
  })
})
