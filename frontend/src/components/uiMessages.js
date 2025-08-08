import { sanitizeText } from '../utils/uiState.js'

/**
 * Create an error message UI component
 * @param {string[]} errors - Array of error messages
 * @returns {HTMLElement} Error message element
 */
export function createErrorMessage(errors) {
  const container = document.createElement('div')
  container.className =
    'bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-start'

  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  icon.setAttribute('class', 'w-5 h-5 text-red-400 mr-3 flex-shrink-0 mt-0.5')
  icon.setAttribute('fill', 'currentColor')
  icon.setAttribute('viewBox', '0 0 20 20')

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
  path.setAttribute('fill-rule', 'evenodd')
  path.setAttribute(
    'd',
    'M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z'
  )
  path.setAttribute('clip-rule', 'evenodd')
  icon.appendChild(path)

  const content = document.createElement('div')
  const strong = document.createElement('strong')
  strong.className = 'font-medium'
  strong.textContent = 'Error:'

  const errorText = document.createTextNode(' ' + errors.map(sanitizeText).join(', '))

  content.appendChild(strong)
  content.appendChild(errorText)

  container.appendChild(icon)
  container.appendChild(content)

  return container
}

/**
 * Create a success message UI component
 * @param {string} fileName - Name of the file
 * @param {string} fileSize - Formatted file size
 * @returns {HTMLElement} Success message element
 */
export function createSuccessMessage(fileName, fileSize) {
  const container = document.createElement('div')
  container.className =
    'bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg flex items-start'

  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  icon.setAttribute('class', 'w-5 h-5 text-green-400 mr-3 flex-shrink-0 mt-0.5')
  icon.setAttribute('fill', 'currentColor')
  icon.setAttribute('viewBox', '0 0 20 20')

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
  path.setAttribute('fill-rule', 'evenodd')
  path.setAttribute(
    'd',
    'M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z'
  )
  path.setAttribute('clip-rule', 'evenodd')
  icon.appendChild(path)

  const content = document.createElement('div')
  const strong = document.createElement('strong')
  strong.className = 'font-medium'
  strong.textContent = 'File ready:'

  const fileText = document.createTextNode(
    ' ' + sanitizeText(fileName) + ' (' + sanitizeText(fileSize) + ')'
  )

  content.appendChild(strong)
  content.appendChild(fileText)

  container.appendChild(icon)
  container.appendChild(content)

  return container
}

/**
 * Creates a batch success message element
 * @param {string} message - Success message to display
 * @returns {HTMLElement} The message element
 */
export function createBatchSuccessMessage(message) {
  const container = document.createElement('div')
  container.className =
    'bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg flex items-start'

  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  icon.setAttribute('class', 'w-5 h-5 text-green-400 mr-3 flex-shrink-0 mt-0.5')
  icon.setAttribute('fill', 'currentColor')
  icon.setAttribute('viewBox', '0 0 20 20')

  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path')
  path.setAttribute('fill-rule', 'evenodd')
  path.setAttribute(
    'd',
    'M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z'
  )
  path.setAttribute('clip-rule', 'evenodd')
  icon.appendChild(path)

  const content = document.createElement('div')
  content.className = 'font-medium'
  content.textContent = sanitizeText(message)

  container.appendChild(icon)
  container.appendChild(content)

  return container
}
