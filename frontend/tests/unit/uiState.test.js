import { describe, it, expect, beforeEach, vi } from 'vitest'
import { UIStateManager, UIStates } from '../../src/utils/uiState.js'

describe('UIStateManager', () => {
  let stateManager

  beforeEach(() => {
    stateManager = new UIStateManager()
  })

  describe('Initial State', () => {
    it('should start with IDLE state', () => {
      expect(stateManager.getState()).toBe(UIStates.IDLE)
      expect(stateManager.isIdle()).toBe(true)
    })
  })

  describe('State Changes', () => {
    it('should change state correctly', () => {
      stateManager.setState(UIStates.PROCESSING)

      expect(stateManager.getState()).toBe(UIStates.PROCESSING)
      expect(stateManager.isProcessing()).toBe(true)
      expect(stateManager.isIdle()).toBe(false)
    })

    it('should notify listeners on state change', () => {
      const callback = vi.fn()
      stateManager.onStateChange(callback)

      stateManager.setState(UIStates.DRAGGING)

      expect(callback).toHaveBeenCalledWith(UIStates.DRAGGING, UIStates.IDLE)
    })

    it('should notify multiple listeners', () => {
      const callback1 = vi.fn()
      const callback2 = vi.fn()

      stateManager.onStateChange(callback1)
      stateManager.onStateChange(callback2)

      stateManager.setState(UIStates.SUCCESS)

      expect(callback1).toHaveBeenCalledWith(UIStates.SUCCESS, UIStates.IDLE)
      expect(callback2).toHaveBeenCalledWith(UIStates.SUCCESS, UIStates.IDLE)
    })
  })

  describe('State Checking Methods', () => {
    it('should correctly identify current state', () => {
      stateManager.setState(UIStates.DRAGGING)
      expect(stateManager.isDragging()).toBe(true)
      expect(stateManager.isIdle()).toBe(false)

      stateManager.setState(UIStates.PROCESSING)
      expect(stateManager.isProcessing()).toBe(true)
      expect(stateManager.isDragging()).toBe(false)

      stateManager.setState(UIStates.SUCCESS)
      expect(stateManager.isSuccess()).toBe(true)

      stateManager.setState(UIStates.ERROR)
      expect(stateManager.isError()).toBe(true)
    })
  })

  describe('Listener Management', () => {
    it('should allow unsubscribing listeners', () => {
      const callback = vi.fn()
      const unsubscribe = stateManager.onStateChange(callback)

      // First state change should trigger callback
      stateManager.setState(UIStates.PROCESSING)
      expect(callback).toHaveBeenCalledTimes(1)

      // Unsubscribe
      unsubscribe()

      // Second state change should not trigger callback
      stateManager.setState(UIStates.SUCCESS)
      expect(callback).toHaveBeenCalledTimes(1)
    })

    it('should handle multiple unsubscribes correctly', () => {
      const callback1 = vi.fn()
      const callback2 = vi.fn()

      const unsubscribe1 = stateManager.onStateChange(callback1)
      stateManager.onStateChange(callback2)

      unsubscribe1()

      stateManager.setState(UIStates.ERROR)

      expect(callback1).not.toHaveBeenCalled()
      expect(callback2).toHaveBeenCalled()
    })
  })
})
