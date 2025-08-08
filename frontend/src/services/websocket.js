/**
 * WebSocket service for batch processing progress updates
 */

export class WebSocketService {
  constructor() {
    this.ws = null
    this.url = null
    this.jobId = null
    this.reconnectAttempts = 0
    this.maxReconnectAttempts = 5
    this.reconnectDelay = 1000 // Start with 1 second
    this.maxReconnectDelay = 30000 // Max 30 seconds
    this.isIntentionallyClosed = false
    this.messageHandlers = new Map()
    this.connectionStatusCallbacks = []
    this.authToken = null
  }

  /**
   * Connect to WebSocket for a specific batch job
   * @param {string} jobId - Batch job ID
   * @param {string} wsUrl - WebSocket URL (may include auth token)
   * @returns {Promise<void>}
   */
  connect(jobId, wsUrl) {
    this.jobId = jobId
    this.isIntentionallyClosed = false

    // Parse the WebSocket URL properly
    // wsUrl from backend is like "ws://localhost:8000/ws/batch/{job_id}?token=xxx"
    if (wsUrl.startsWith('ws://') || wsUrl.startsWith('wss://')) {
      // Full URL provided from backend - use it directly
      this.url = wsUrl
      const urlObj = new URL(wsUrl)
      this.authToken = urlObj.searchParams.get('token')
    } else {
      // Relative URL - build with backend port
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      // Use backend port 8000, not frontend port 5173
      const host = `${window.location.hostname}:8000`
      
      // Parse any query parameters
      const urlObj = new URL(wsUrl, `http://${host}`)
      this.authToken = urlObj.searchParams.get('token')
      
      // Build the full WebSocket URL
      this.url = `${protocol}//${host}${urlObj.pathname}`
      if (this.authToken) {
        this.url += `?token=${this.authToken}`
      }
    }

    return this.createConnection()
  }

  createConnection() {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url)

        this.ws.onopen = () => {
          // WebSocket connected successfully
          this.reconnectAttempts = 0
          this.reconnectDelay = 1000
          this.notifyConnectionStatus('connected')
          resolve()
        }

        this.ws.onmessage = (event) => {
          this.handleMessage(event)
        }

        this.ws.onerror = (error) => {
          // WebSocket error occurred
          this.notifyConnectionStatus('error')
        }

        this.ws.onclose = (event) => {
          // WebSocket closed
          this.notifyConnectionStatus('disconnected')

          if (!this.isIntentionallyClosed) {
            this.attemptReconnect()
          }
        }

        // Set a timeout for initial connection
        setTimeout(() => {
          if (this.ws.readyState === WebSocket.CONNECTING) {
            this.ws.close()
            reject(new Error('WebSocket connection timeout'))
          }
        }, 10000)
      } catch (error) {
        console.error('Failed to create WebSocket:', error)
        reject(error)
      }
    })
  }

  handleMessage(event) {
    try {
      const data = JSON.parse(event.data)

      // Handle different message types
      switch (data.type) {
        case 'connection':
          break

        case 'progress':
          this.notifyHandlers('progress', data)
          break

        case 'job_status':
          this.notifyHandlers('job_status', data)
          break

        case 'ping':
          // Respond with pong
          this.send({ type: 'pong' })
          break

        case 'pong':
          // Server acknowledged our ping
          break

        case 'error':
          console.error('Server error:', data.message)
          this.notifyHandlers('error', data)
          break

        default:
          console.warn('Unknown message type:', data.type)
      }
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error)
    }
  }

  notifyHandlers(type, data) {
    const handlers = this.messageHandlers.get(type) || []
    handlers.forEach((handler) => {
      try {
        handler(data)
      } catch (error) {
        console.error(`Error in ${type} handler:`, error)
      }
    })
  }

  notifyConnectionStatus(status) {
    this.connectionStatusCallbacks.forEach((callback) => {
      try {
        callback(status)
      } catch (error) {
        console.error('Error in connection status callback:', error)
      }
    })
  }

  attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached')
      this.notifyConnectionStatus('failed')
      return
    }

    this.reconnectAttempts++
    const delay = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
      this.maxReconnectDelay
    )

    // Attempting reconnect
    this.notifyConnectionStatus('reconnecting')

    setTimeout(() => {
      if (!this.isIntentionallyClosed) {
        this.createConnection().catch((error) => {
          console.error('Reconnection failed:', error)
        })
      }
    }, delay)
  }

  /**
   * Register a handler for a specific message type
   * @param {string} type - Message type (progress, job_status, error)
   * @param {Function} handler - Handler function
   */
  on(type, handler) {
    if (!this.messageHandlers.has(type)) {
      this.messageHandlers.set(type, [])
    }
    this.messageHandlers.get(type).push(handler)
  }

  /**
   * Remove a handler for a specific message type
   * @param {string} type - Message type
   * @param {Function} handler - Handler function to remove
   */
  off(type, handler) {
    const handlers = this.messageHandlers.get(type)
    if (handlers) {
      const index = handlers.indexOf(handler)
      if (index > -1) {
        handlers.splice(index, 1)
      }
    }
  }

  /**
   * Register a connection status callback
   * @param {Function} callback - Callback function (status: connected|disconnected|reconnecting|error|failed)
   */
  onConnectionStatus(callback) {
    this.connectionStatusCallbacks.push(callback)
  }

  /**
   * Send a message to the server
   * @param {Object} data - Data to send
   */
  send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    } else {
      console.warn('WebSocket not connected, cannot send message')
    }
  }

  /**
   * Send a ping to keep the connection alive
   */
  ping() {
    this.send({ type: 'ping' })
  }

  /**
   * Close the WebSocket connection
   */
  close() {
    this.isIntentionallyClosed = true
    if (this.ws) {
      this.ws.close(1000, 'Client closing connection')
      this.ws = null
    }
    this.messageHandlers.clear()
    this.connectionStatusCallbacks = []
  }

  /**
   * Get the current connection state
   * @returns {string} Connection state
   */
  getState() {
    if (!this.ws) {
      return 'disconnected'
    }

    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting'
      case WebSocket.OPEN:
        return 'connected'
      case WebSocket.CLOSING:
        return 'closing'
      case WebSocket.CLOSED:
        return 'disconnected'
      default:
        return 'unknown'
    }
  }

  /**
   * Check if connected
   * @returns {boolean}
   */
  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN
  }
}

// Export singleton instance
export const websocketService = new WebSocketService()
