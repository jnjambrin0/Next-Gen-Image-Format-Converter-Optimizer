/**
 * WebSocket connection status indicator component
 */

export class WebSocketStatus {
  constructor(container) {
    this.container = container
    this.status = 'disconnected'
    this.render()
  }

  setStatus(status) {
    if (this.status !== status) {
      this.status = status
      this.render()
    }
  }

  render() {
    this.container.innerHTML = ''

    const statusEl = document.createElement('div')
    statusEl.className = 'flex items-center space-x-2 text-sm'

    // Status dot
    const dot = document.createElement('span')
    dot.className = 'w-2 h-2 rounded-full'

    // Status text
    const text = document.createElement('span')

    switch (this.status) {
      case 'connected':
        dot.className += ' bg-green-500'
        text.className = 'text-green-700'
        text.textContent = 'Connected'
        break

      case 'connecting':
      case 'reconnecting':
        dot.className += ' bg-yellow-500 animate-pulse'
        text.className = 'text-yellow-700'
        text.textContent = this.status === 'connecting' ? 'Connecting...' : 'Reconnecting...'
        break

      case 'disconnected':
        dot.className += ' bg-gray-400'
        text.className = 'text-gray-600'
        text.textContent = 'Disconnected'
        break

      case 'error':
      case 'failed':
        dot.className += ' bg-red-500'
        text.className = 'text-red-700'
        text.textContent = 'Connection Error'
        break

      default:
        dot.className += ' bg-gray-400'
        text.className = 'text-gray-600'
        text.textContent = 'Unknown'
    }

    statusEl.appendChild(dot)
    statusEl.appendChild(text)

    // Add retry button for failed state
    if (this.status === 'failed') {
      const retryBtn = document.createElement('button')
      retryBtn.className = 'ml-2 text-xs text-blue-600 hover:text-blue-800 underline'
      retryBtn.textContent = 'Retry'
      retryBtn.onclick = () => {
        if (this.onRetryCallback) {
          this.onRetryCallback()
        }
      }
      statusEl.appendChild(retryBtn)
    }

    this.container.appendChild(statusEl)
  }

  onRetry(callback) {
    this.onRetryCallback = callback
  }
}
