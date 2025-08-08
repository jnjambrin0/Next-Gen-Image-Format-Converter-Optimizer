export function createLoadingSpinner(statusText = null) {
  const spinner = document.createElement('div')
  spinner.className = 'flex flex-col items-center justify-center py-4'

  // Logo with pulse animation
  const logoContainer = document.createElement('div')
  logoContainer.className = 'relative mb-4'
  
  const logo = document.createElement('img')
  logo.src = '/logo.png'
  logo.alt = 'Image Converter Logo'
  logo.className = 'w-12 h-12 animate-pulse'
  logo.style.filter = 'drop-shadow(0 2px 4px rgba(0, 0, 0, 0.1))'
  
  logoContainer.appendChild(logo)
  spinner.appendChild(logoContainer)

  const spinnerElement = document.createElement('div')
  spinnerElement.className = 'animate-spin rounded-full h-8 w-8 border-b-2 border-primary'
  spinnerElement.setAttribute('role', 'status')
  spinnerElement.setAttribute('aria-label', statusText || 'Loading')

  const srOnly = document.createElement('span')
  srOnly.className = 'sr-only'
  srOnly.textContent = statusText || 'Loading...'

  spinnerElement.appendChild(srOnly)
  spinner.appendChild(spinnerElement)

  // Add status text if provided
  if (statusText) {
    const textElement = document.createElement('p')
    textElement.className = 'mt-3 text-sm text-gray-600'
    textElement.textContent = statusText
    spinner.appendChild(textElement)
  }

  return spinner
}

export function createProgressBar(progress = 0) {
  const container = document.createElement('div')
  container.className = 'w-full bg-gray-200 rounded-full h-2.5 mt-4'

  const progressBar = document.createElement('div')
  progressBar.className = 'bg-primary h-2.5 rounded-full transition-all duration-300'
  progressBar.style.width = `${progress}%`
  progressBar.setAttribute('role', 'progressbar')
  progressBar.setAttribute('aria-valuenow', progress)
  progressBar.setAttribute('aria-valuemin', '0')
  progressBar.setAttribute('aria-valuemax', '100')

  container.appendChild(progressBar)

  return container
}

export function updateProgressBar(container, progress) {
  const bar = container.querySelector('[role="progressbar"]')
  if (bar) {
    bar.style.width = `${progress}%`
    bar.setAttribute('aria-valuenow', progress)
  }
}
