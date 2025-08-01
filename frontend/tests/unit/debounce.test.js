import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { debounce, throttle } from '../../src/utils/debounce.js'

describe('Debounce and Throttle Utilities', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('debounce', () => {
    it('should delay function execution', () => {
      const func = vi.fn()
      const debouncedFunc = debounce(func, 100)

      debouncedFunc('test')
      expect(func).not.toHaveBeenCalled()

      vi.advanceTimersByTime(50)
      expect(func).not.toHaveBeenCalled()

      vi.advanceTimersByTime(50)
      expect(func).toHaveBeenCalledWith('test')
      expect(func).toHaveBeenCalledTimes(1)
    })

    it('should cancel previous calls when called multiple times', () => {
      const func = vi.fn()
      const debouncedFunc = debounce(func, 100)

      debouncedFunc('first')
      vi.advanceTimersByTime(50)
      debouncedFunc('second')
      vi.advanceTimersByTime(50)
      debouncedFunc('third')
      vi.advanceTimersByTime(100)

      expect(func).toHaveBeenCalledTimes(1)
      expect(func).toHaveBeenCalledWith('third')
    })

    it('should execute immediately when immediate is true', () => {
      const func = vi.fn()
      const debouncedFunc = debounce(func, 100, true)

      debouncedFunc('test')
      expect(func).toHaveBeenCalledWith('test')
      expect(func).toHaveBeenCalledTimes(1)

      // Subsequent calls within wait time should not execute
      debouncedFunc('test2')
      expect(func).toHaveBeenCalledTimes(1)

      vi.advanceTimersByTime(100)
      debouncedFunc('test3')
      expect(func).toHaveBeenCalledTimes(2)
      expect(func).toHaveBeenLastCalledWith('test3')
    })

    it('should preserve context and arguments', () => {
      const context = { value: 42 }
      const func = vi.fn(function (a, b) {
        return this.value + a + b
      })
      const debouncedFunc = debounce(func, 100)

      debouncedFunc.call(context, 1, 2)
      vi.advanceTimersByTime(100)

      expect(func).toHaveBeenCalledWith(1, 2)
      expect(func.mock.instances[0]).toBe(context)
    })
  })

  describe('throttle', () => {
    it('should limit function execution frequency', () => {
      const func = vi.fn()
      const throttledFunc = throttle(func, 100)

      throttledFunc('first')
      expect(func).toHaveBeenCalledWith('first')
      expect(func).toHaveBeenCalledTimes(1)

      // Call immediately after should be ignored
      throttledFunc('second')
      expect(func).toHaveBeenCalledTimes(1)

      vi.advanceTimersByTime(50)
      throttledFunc('third')
      expect(func).toHaveBeenCalledTimes(1)

      vi.advanceTimersByTime(50)
      throttledFunc('fourth')
      expect(func).toHaveBeenCalledTimes(2)
      expect(func).toHaveBeenLastCalledWith('fourth')
    })

    it('should execute first call immediately', () => {
      const func = vi.fn()
      const throttledFunc = throttle(func, 100)

      throttledFunc('test')
      expect(func).toHaveBeenCalledWith('test')
      expect(func).toHaveBeenCalledTimes(1)
    })

    it('should preserve context and arguments', () => {
      const context = { value: 10 }
      const func = vi.fn(function (x) {
        return this.value * x
      })
      const throttledFunc = throttle(func, 100)

      throttledFunc.call(context, 5)
      expect(func).toHaveBeenCalledWith(5)
      expect(func.mock.instances[0]).toBe(context)
    })
  })
})
