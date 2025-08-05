/**
 * Simple notification system for user feedback
 */

/**
 * Show a notification message to the user
 * @param {string} message - The message to display
 * @param {string} type - The type of notification ('success', 'error', 'info', 'warning')
 * @param {number} duration - How long to show the notification in milliseconds (default: 3000)
 */
export function showNotification(message, type = 'info', duration = 3000) {
  // Create notification element
  const notification = document.createElement('div')
  notification.className = `notification notification-${type}`

  // Set up styling based on type
  const baseClasses =
    'fixed top-4 right-4 px-4 py-3 rounded-md shadow-lg z-50 transition-all duration-300 max-w-sm'
  const typeClasses = {
    success: 'bg-green-500 text-white',
    error: 'bg-red-500 text-white',
    warning: 'bg-yellow-500 text-black',
    info: 'bg-blue-500 text-white',
  }

  notification.className = `${baseClasses} ${typeClasses[type] || typeClasses.info}`
  notification.textContent = message

  // Add close button
  const closeButton = document.createElement('button')
  closeButton.innerHTML = '×'
  closeButton.className = 'ml-3 text-lg font-bold opacity-70 hover:opacity-100'
  closeButton.onclick = () => removeNotification(notification)
  notification.appendChild(closeButton)

  // Add to DOM
  document.body.appendChild(notification)

  // Animate in
  requestAnimationFrame(() => {
    notification.style.transform = 'translateX(0)'
    notification.style.opacity = '1'
  })

  // Auto-remove after duration
  if (duration > 0) {
    setTimeout(() => {
      removeNotification(notification)
    }, duration)
  }

  return notification
}

/**
 * Remove a notification from the DOM
 * @param {HTMLElement} notification - The notification element to remove
 */
function removeNotification(notification) {
  if (!notification || !notification.parentNode) {
    return
  }

  // Animate out
  notification.style.transform = 'translateX(100%)'
  notification.style.opacity = '0'

  // Remove from DOM after animation
  setTimeout(() => {
    if (notification.parentNode) {
      notification.parentNode.removeChild(notification)
    }
  }, 300)
}

/**
 * Show a success notification
 * @param {string} message - The success message
 * @param {number} duration - Duration in milliseconds
 */
export function showSuccess(message, duration = 3000) {
  return showNotification(message, 'success', duration)
}

/**
 * Show an error notification
 * @param {string} message - The error message
 * @param {number} duration - Duration in milliseconds (0 = persistent)
 */
export function showError(message, duration = 5000) {
  return showNotification(message, 'error', duration)
}

/**
 * Show a warning notification
 * @param {string} message - The warning message
 * @param {number} duration - Duration in milliseconds
 */
export function showWarning(message, duration = 4000) {
  return showNotification(message, 'warning', duration)
}

/**
 * Show an info notification
 * @param {string} message - The info message
 * @param {number} duration - Duration in milliseconds
 */
export function showInfo(message, duration = 3000) {
  return showNotification(message, 'info', duration)
}
