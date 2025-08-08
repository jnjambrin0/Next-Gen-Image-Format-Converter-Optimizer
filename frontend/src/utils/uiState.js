export const UIStates = {
  IDLE: 'idle',
  DRAGGING: 'dragging',
  PROCESSING: 'processing',
  UPLOADING: 'uploading',
  CONVERTING: 'converting',
  DOWNLOADING: 'downloading',
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
    this.mode = 'single' // 'single' | 'batch'
    this.stateChangeCallbacks = []
    this.modeChangeCallbacks = []
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

  isUploading() {
    return this.currentState === UIStates.UPLOADING
  }

  isConverting() {
    return this.currentState === UIStates.CONVERTING
  }

  isDownloading() {
    return this.currentState === UIStates.DOWNLOADING
  }

  /**
   * Get current mode
   */
  getMode() {
    return this.mode
  }

  /**
   * Switch between single and batch modes
   */
  switchMode(newMode) {
    if (newMode !== 'single' && newMode !== 'batch') {
      console.error('Invalid mode:', newMode)
      return
    }

    if (this.mode === newMode) {
      return
    }

    const oldMode = this.mode
    this.mode = newMode

    // Notify all mode change listeners
    this.modeChangeCallbacks.forEach((callback) => {
      callback(newMode, oldMode)
    })
  }

  /**
   * Register mode change callback
   */
  onModeChange(callback) {
    this.modeChangeCallbacks.push(callback)

    // Return unsubscribe function
    return () => {
      const index = this.modeChangeCallbacks.indexOf(callback)
      if (index > -1) {
        this.modeChangeCallbacks.splice(index, 1)
      }
    }
  }

  /**
   * Check if in single mode
   */
  isSingleMode() {
    return this.mode === 'single'
  }

  /**
   * Check if in batch mode
   */
  isBatchMode() {
    return this.mode === 'batch'
  }
}
