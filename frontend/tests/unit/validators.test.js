import { describe, it, expect } from 'vitest'
import {
  validateImageFile,
  formatFileSize,
  getFileExtension,
  isImageFile,
  calculateSizeReduction,
} from '../../src/utils/validators.js'

describe('validateImageFile', () => {
  it('should return valid for supported image types', () => {
    const validFiles = [
      { name: 'test.jpg', type: 'image/jpeg', size: 1024 * 1024 },
      { name: 'test.png', type: 'image/png', size: 1024 * 1024 },
      { name: 'test.webp', type: 'image/webp', size: 1024 * 1024 },
      { name: 'test.gif', type: 'image/gif', size: 1024 * 1024 },
      { name: 'test.avif', type: 'image/avif', size: 1024 * 1024 },
    ]

    validFiles.forEach((file) => {
      const result = validateImageFile(file)
      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })
  })

  it('should return invalid for unsupported file types', () => {
    const invalidFile = { name: 'test.pdf', type: 'application/pdf', size: 1024 * 1024 }
    const result = validateImageFile(invalidFile)

    expect(result.valid).toBe(false)
    expect(result.errors).toContain(
      'Unsupported file type: application/pdf. Please select a valid image file.'
    )
  })

  it('should handle HEIC/HEIF files by extension when MIME type is not recognized', () => {
    const heicFile = { name: 'test.heic', type: 'application/octet-stream', size: 1024 * 1024 }
    const result = validateImageFile(heicFile)

    expect(result.valid).toBe(true)
    expect(result.errors).toHaveLength(0)
  })

  it('should return invalid for files exceeding size limit', () => {
    const largeFile = { name: 'test.jpg', type: 'image/jpeg', size: 51 * 1024 * 1024 } // 51MB
    const result = validateImageFile(largeFile)

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('File too large: 51.0MB. Maximum allowed size is 50MB.')
  })

  it('should return invalid when no file is provided', () => {
    const result = validateImageFile(null)

    expect(result.valid).toBe(false)
    expect(result.errors).toContain('No file selected')
  })

  it('should handle multiple validation errors', () => {
    const invalidFile = { name: 'test.pdf', type: 'application/pdf', size: 51 * 1024 * 1024 }
    const result = validateImageFile(invalidFile)

    expect(result.valid).toBe(false)
    expect(result.errors).toHaveLength(2)
  })
})

describe('formatFileSize', () => {
  it('should format bytes correctly', () => {
    expect(formatFileSize(0)).toBe('0 Bytes')
    expect(formatFileSize(1024)).toBe('1 KB')
    expect(formatFileSize(1024 * 1024)).toBe('1 MB')
    expect(formatFileSize(1024 * 1024 * 1024)).toBe('1 GB')
    expect(formatFileSize(1536)).toBe('1.5 KB')
    expect(formatFileSize(1572864)).toBe('1.5 MB')
  })
})

describe('getFileExtension', () => {
  it('should extract file extension correctly', () => {
    expect(getFileExtension('image.jpg')).toBe('jpg')
    expect(getFileExtension('document.PDF')).toBe('pdf')
    expect(getFileExtension('file.name.with.dots.png')).toBe('png')
    expect(getFileExtension('noextension')).toBe('noextension')
  })
})

describe('isImageFile', () => {
  it('should return true for valid image files', () => {
    const validFile = { name: 'test.jpg', type: 'image/jpeg', size: 1024 * 1024 }
    expect(isImageFile(validFile)).toBe(true)
  })

  it('should return false for invalid files', () => {
    const invalidFile = { name: 'test.pdf', type: 'application/pdf', size: 1024 * 1024 }
    expect(isImageFile(invalidFile)).toBe(false)
  })
})

describe('calculateSizeReduction', () => {
  it('should calculate size reduction correctly', () => {
    expect(calculateSizeReduction(1000, 500)).toBe(50)
    expect(calculateSizeReduction(1000, 750)).toBe(25)
    expect(calculateSizeReduction(1000, 1000)).toBe(0)
    expect(calculateSizeReduction(1000, 100)).toBe(90)
  })

  it('should handle edge cases', () => {
    expect(calculateSizeReduction(0, 100)).toBe(0) // Division by zero
    expect(calculateSizeReduction(1000, 1100)).toBe(0) // Negative reduction
    expect(calculateSizeReduction(1000, 0)).toBe(100) // 100% reduction
  })

  it('should round to nearest integer', () => {
    expect(calculateSizeReduction(1000, 666)).toBe(33) // 33.4% rounds to 33
    expect(calculateSizeReduction(1000, 665)).toBe(34) // 33.5% rounds to 34
  })
})
