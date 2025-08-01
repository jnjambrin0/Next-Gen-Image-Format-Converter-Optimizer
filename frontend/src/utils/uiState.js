export const UIStates = {
  IDLE: 'idle',
  DRAGGING: 'dragging',
  PROCESSING: 'processing',
  SUCCESS: 'success',
  ERROR: 'error',
}

/**
 * Create a safe text node to prevent XSS attacks
 * @param {string} text - Text to sanitize
 * @returns {string} Sanitized text
 */
export function sanitizeText(text) {
  const div = document.createElement('div')
  div.textContent = text
  return div.innerHTML
}

export class UIStateManager {
  constructor() {
    this.currentState = UIStates.IDLE
    this.stateChangeCallbacks = []
  }

  getState() {
    return this.currentState
  }

  setState(newState) {
    const oldState = this.currentState
    this.currentState = newState

    // Notify all listeners
    this.stateChangeCallbacks.forEach((callback) => {
      callback(newState, oldState)
    })
  }

  onStateChange(callback) {
    this.stateChangeCallbacks.push(callback)

    // Return unsubscribe function
    return () => {
      const index = this.stateChangeCallbacks.indexOf(callback)
      if (index > -1) {
        this.stateChangeCallbacks.splice(index, 1)
      }
    }
  }

  isIdle() {
    return this.currentState === UIStates.IDLE
  }

  isDragging() {
    return this.currentState === UIStates.DRAGGING
  }

  isProcessing() {
    return this.currentState === UIStates.PROCESSING
  }

  isSuccess() {
    return this.currentState === UIStates.SUCCESS
  }

  isError() {
    return this.currentState === UIStates.ERROR
  }
}
