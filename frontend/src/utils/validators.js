// Supported image MIME types
const SUPPORTED_IMAGE_TYPES = [
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/webp',
  'image/heif',
  'image/heic',
  'image/bmp',
  'image/tiff',
  'image/gif',
  'image/avif',
]

// Maximum file size (50MB as per backend requirement)
const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50MB in bytes

export function validateImageFile(file) {
  const errors = []

  // Check if file exists
  if (!file) {
    errors.push('No file selected')
    return { valid: false, errors }
  }

  // Check MIME type
  if (!SUPPORTED_IMAGE_TYPES.includes(file.type.toLowerCase())) {
    // Some browsers don't recognize HEIC/HEIF properly, check extension as fallback
    const extension = file.name.split('.').pop().toLowerCase()
    const heicExtensions = ['heic', 'heif']

    if (!heicExtensions.includes(extension)) {
      errors.push(
        `Unsupported file type: ${file.type || 'unknown'}. Please select a valid image file.`
      )
    }
  }

  // Check file size
  if (file.size > MAX_FILE_SIZE) {
    const sizeMB = (file.size / (1024 * 1024)).toFixed(1)
    errors.push(`File too large: ${sizeMB}MB. Maximum allowed size is 50MB.`)
  }

  // Check if it's actually an image by trying to read it
  // This will be done asynchronously in the component

  return {
    valid: errors.length === 0,
    errors,
  }
}

export function formatFileSize(bytes) {
  if (bytes === 0) {
    return '0 Bytes'
  }

  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export function getFileExtension(filename) {
  return filename.split('.').pop().toLowerCase()
}

export function isImageFile(file) {
  const validation = validateImageFile(file)
  return validation.valid
}

export function calculateSizeReduction(originalSize, convertedSize) {
  if (originalSize === 0) {
    return 0
  }
  const reduction = ((originalSize - convertedSize) / originalSize) * 100
  return Math.max(0, Math.round(reduction))
}
