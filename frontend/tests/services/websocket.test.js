import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { WebSocketService } from '../../src/services/websocket.js'

// Mock WebSocket
class MockWebSocket {
  constructor(url) {
    this.url = url
    this.readyState = MockWebSocket.CONNECTING
    this.onopen = null
    this.onclose = null
    this.onerror = null
    this.onmessage = null

    // Simulate connection after a short delay
    setTimeout(() => {
      if (this.readyState === MockWebSocket.CONNECTING) {
        this.readyState = MockWebSocket.OPEN
        if (this.onopen) {
          this.onopen()
        }
      }
    }, 10)
  }

  send(_data) {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not open')
    }
  }

  close(code, reason) {
    this.readyState = MockWebSocket.CLOSED
    if (this.onclose) {
      this.onclose({ code, reason })
    }
  }

  simulateMessage(data) {
    if (this.onmessage) {
      this.onmessage({ data: JSON.stringify(data) })
    }
  }

  simulateError(error) {
    if (this.onerror) {
      this.onerror(error)
    }
  }

  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3
}

global.WebSocket = MockWebSocket

describe('WebSocketService', () => {
  let wsService

  beforeEach(() => {
    wsService = new WebSocketService()
    vi.useFakeTimers()
  })

  afterEach(() => {
    if (wsService) {
      wsService.close()
    }
    vi.useRealTimers()
  })

  describe('connection', () => {
    it('should connect to WebSocket URL', async () => {
      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')

      // Fast forward to trigger connection
      vi.advanceTimersByTime(20)

      await promise

      expect(wsService.jobId).toBe('test-job-id')
      expect(wsService.isConnected()).toBe(true)
      expect(wsService.getState()).toBe('connected')
    })

    it('should extract auth token from URL', async () => {
      const promise = wsService.connect(
        'test-job-id',
        'ws://localhost/ws/batch/test-job-id?token=test-token-123'
      )

      vi.advanceTimersByTime(20)
      await promise

      expect(wsService.authToken).toBe('test-token-123')
      expect(wsService.url).toContain('token=test-token-123')
    })

    it('should handle connection timeout', async () => {
      // Prevent auto-connection
      MockWebSocket.prototype.onopen = null

      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')

      // Fast forward past timeout
      vi.advanceTimersByTime(11000)

      await expect(promise).rejects.toThrow('WebSocket connection timeout')
    })
  })

  describe('message handling', () => {
    beforeEach(async () => {
      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise
    })

    it('should handle progress messages', () => {
      const progressHandler = vi.fn()
      wsService.on('progress', progressHandler)

      const progressData = {
        type: 'progress',
        job_id: 'test-job-id',
        file_index: 0,
        filename: 'test.jpg',
        status: 'processing',
        progress: 50,
        message: 'Processing...',
      }

      wsService.ws.simulateMessage(progressData)

      expect(progressHandler).toHaveBeenCalledWith(progressData)
    })

    it('should handle job status messages', () => {
      const statusHandler = vi.fn()
      wsService.on('job_status', statusHandler)

      const statusData = {
        type: 'job_status',
        job_id: 'test-job-id',
        status: 'completed',
      }

      wsService.ws.simulateMessage(statusData)

      expect(statusHandler).toHaveBeenCalledWith(statusData)
    })

    it('should respond to ping with pong', () => {
      const sendSpy = vi.spyOn(wsService.ws, 'send')

      wsService.ws.simulateMessage({ type: 'ping' })

      expect(sendSpy).toHaveBeenCalledWith(JSON.stringify({ type: 'pong' }))
    })

    it('should handle error messages', () => {
      const errorHandler = vi.fn()
      wsService.on('error', errorHandler)

      const errorData = {
        type: 'error',
        message: 'Something went wrong',
      }

      wsService.ws.simulateMessage(errorData)

      expect(errorHandler).toHaveBeenCalledWith(errorData)
    })

    it('should handle malformed messages', () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      // Send invalid JSON
      if (wsService.ws.onmessage) {
        wsService.ws.onmessage({ data: 'invalid json' })
      }

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to parse WebSocket message:',
        expect.any(Error)
      )

      consoleErrorSpy.mockRestore()
    })
  })

  describe('reconnection', () => {
    it('should attempt reconnection on close', async () => {
      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise

      const statusCallback = vi.fn()
      wsService.onConnectionStatus(statusCallback)

      // Simulate connection close
      wsService.ws.close(1006, 'Connection lost')

      expect(statusCallback).toHaveBeenCalledWith('disconnected')
      expect(statusCallback).toHaveBeenCalledWith('reconnecting')

      // Fast forward to trigger reconnection
      vi.advanceTimersByTime(1100)

      // Should create new connection
      expect(wsService.ws).toBeTruthy()
    })

    it('should use exponential backoff for reconnections', async () => {
      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise

      // First reconnection - 1 second
      wsService.ws.close(1006, 'Connection lost')
      vi.advanceTimersByTime(1100)

      // Second reconnection - 2 seconds
      wsService.ws.close(1006, 'Connection lost')
      expect(wsService.reconnectAttempts).toBe(2)

      // Should not reconnect immediately
      vi.advanceTimersByTime(1500)
      expect(wsService.ws.readyState).toBe(MockWebSocket.CLOSED)

      // Should reconnect after 2 seconds
      vi.advanceTimersByTime(600)
      expect(wsService.ws.readyState).toBe(MockWebSocket.CONNECTING)
    })

    it('should stop reconnecting after max attempts', async () => {
      wsService.maxReconnectAttempts = 2

      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise

      const statusCallback = vi.fn()
      wsService.onConnectionStatus(statusCallback)

      // Fail multiple times
      for (let i = 0; i < 3; i++) {
        wsService.ws.close(1006, 'Connection lost')
        vi.advanceTimersByTime(35000) // Max delay
      }

      expect(statusCallback).toHaveBeenCalledWith('failed')
      expect(wsService.reconnectAttempts).toBe(2)
    })
  })

  describe('event handlers', () => {
    beforeEach(async () => {
      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise
    })

    it('should register and call multiple handlers', () => {
      const handler1 = vi.fn()
      const handler2 = vi.fn()

      wsService.on('progress', handler1)
      wsService.on('progress', handler2)

      const data = { type: 'progress', progress: 50 }
      wsService.ws.simulateMessage(data)

      expect(handler1).toHaveBeenCalledWith(data)
      expect(handler2).toHaveBeenCalledWith(data)
    })

    it('should remove handlers', () => {
      const handler = vi.fn()

      wsService.on('progress', handler)
      wsService.off('progress', handler)

      const data = { type: 'progress', progress: 50 }
      wsService.ws.simulateMessage(data)

      expect(handler).not.toHaveBeenCalled()
    })

    it('should handle errors in handlers gracefully', () => {
      const errorHandler = vi.fn(() => {
        throw new Error('Handler error')
      })
      const goodHandler = vi.fn()

      wsService.on('progress', errorHandler)
      wsService.on('progress', goodHandler)

      const data = { type: 'progress', progress: 50 }
      wsService.ws.simulateMessage(data)

      // Good handler should still be called
      expect(goodHandler).toHaveBeenCalledWith(data)
    })
  })

  describe('connection status', () => {
    it('should notify connection status changes', async () => {
      const statusCallback = vi.fn()
      wsService.onConnectionStatus(statusCallback)

      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise

      expect(statusCallback).toHaveBeenCalledWith('connected')

      wsService.ws.simulateError(new Error('Network error'))
      expect(statusCallback).toHaveBeenCalledWith('error')

      wsService.close()
      expect(statusCallback).toHaveBeenCalledWith('disconnected')
    })
  })

  describe('send functionality', () => {
    beforeEach(async () => {
      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise
    })

    it('should send messages when connected', () => {
      const sendSpy = vi.spyOn(wsService.ws, 'send')

      wsService.send({ type: 'test', data: 'hello' })

      expect(sendSpy).toHaveBeenCalledWith(JSON.stringify({ type: 'test', data: 'hello' }))
    })

    it('should not send when disconnected', () => {
      wsService.ws.close()

      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      wsService.send({ type: 'test' })

      expect(consoleWarnSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message')

      consoleWarnSpy.mockRestore()
    })
  })

  describe('cleanup', () => {
    it('should clean up on close', async () => {
      const promise = wsService.connect('test-job-id', 'ws://localhost/ws/batch/test-job-id')
      vi.advanceTimersByTime(20)
      await promise

      const handler = vi.fn()
      wsService.on('progress', handler)

      wsService.close()

      expect(wsService.isIntentionallyClosed).toBe(true)
      expect(wsService.ws).toBeNull()
      expect(wsService.messageHandlers.size).toBe(0)
      expect(wsService.connectionStatusCallbacks).toHaveLength(0)
    })
  })
})
