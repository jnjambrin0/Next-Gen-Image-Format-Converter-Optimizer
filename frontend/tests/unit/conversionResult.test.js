import { describe, it, expect, vi } from 'vitest'
import { createConversionResult } from '../../src/components/conversionResult.js'

describe('ConversionResult Component', () => {
  const defaultOptions = {
    originalFilename: 'test.jpg',
    convertedFilename: 'test_converted.webp',
    outputFormat: 'webp',
    originalSize: 1024 * 1024, // 1MB
    convertedSize: 512 * 1024, // 512KB
    conversionTime: '1.5',
    onConvertAnother: vi.fn(),
  }

  it('should create conversion result element with correct structure', () => {
    const result = createConversionResult(defaultOptions)

    expect(result).toBeTruthy()
    expect(result.tagName).toBe('DIV')
    expect(result.className).toContain('bg-green-50')
    expect(result.className).toContain('border-green-200')
  })

  it('should display success title', () => {
    const result = createConversionResult(defaultOptions)
    const title = result.querySelector('h3')

    expect(title).toBeTruthy()
    expect(title.textContent).toBe('Conversion Successful!')
    expect(title.className).toContain('text-green-800')
  })

  it('should display all file details correctly', () => {
    const result = createConversionResult(defaultOptions)
    const content = result.textContent

    expect(content).toContain('Original File:')
    expect(content).toContain('test.jpg')
    expect(content).toContain('Converted File:')
    expect(content).toContain('test_converted.webp')
    expect(content).toContain('Output Format:')
    expect(content).toContain('WEBP')
    expect(content).toContain('Conversion Time:')
    expect(content).toContain('1.5s')
    expect(content).toContain('Original Size:')
    expect(content).toContain('1 MB')
    expect(content).toContain('Converted Size:')
    expect(content).toContain('512 KB')
  })

  it('should calculate and display size reduction percentage', () => {
    const result = createConversionResult(defaultOptions)
    const reductionBadge = result.querySelector('.bg-green-100')

    expect(reductionBadge).toBeTruthy()
    expect(reductionBadge.textContent).toBe('50% size reduction')
  })

  it('should not display size reduction when file size increases', () => {
    const options = {
      ...defaultOptions,
      convertedSize: 2 * 1024 * 1024, // 2MB (larger than original)
    }
    const result = createConversionResult(options)
    const badges = result.querySelectorAll('.bg-green-100')

    // Should not find the reduction badge
    const reductionBadge = Array.from(badges).find((badge) =>
      badge.textContent.includes('size reduction')
    )
    expect(reductionBadge).toBeFalsy()
  })

  it('should create Convert Another button', () => {
    const result = createConversionResult(defaultOptions)
    const button = result.querySelector('button')

    expect(button).toBeTruthy()
    expect(button.textContent).toBe('Convert Another Image')
    expect(button.className).toContain('bg-blue-600')
    expect(button.className).toContain('hover:bg-blue-700')
  })

  it('should call onConvertAnother callback when button is clicked', () => {
    const mockCallback = vi.fn()
    const options = { ...defaultOptions, onConvertAnother: mockCallback }
    const result = createConversionResult(options)
    const button = result.querySelector('button')

    button.click()

    expect(mockCallback).toHaveBeenCalledTimes(1)
  })

  it('should format file sizes correctly', () => {
    const testCases = [
      { size: 0, expected: '0 Bytes' },
      { size: 100, expected: '100 Bytes' },
      { size: 1024, expected: '1 KB' },
      { size: 1024 * 1024, expected: '1 MB' },
      { size: 1.5 * 1024 * 1024, expected: '1.5 MB' },
      { size: 1024 * 1024 * 1024, expected: '1 GB' },
    ]

    testCases.forEach(({ size, expected }) => {
      const options = { ...defaultOptions, originalSize: size, convertedSize: size }
      const result = createConversionResult(options)
      const content = result.textContent

      expect(content).toContain(expected)
    })
  })

  it('should include success icon SVG', () => {
    const result = createConversionResult(defaultOptions)
    const svg = result.querySelector('svg')

    expect(svg).toBeTruthy()
    expect(svg.getAttribute('class')).toContain('text-green-600')
    expect(svg.getAttribute('viewBox')).toBe('0 0 20 20')
  })

  it('should handle different output formats', () => {
    const formats = ['avif', 'jpeg', 'png', 'webp2']

    formats.forEach((format) => {
      const options = { ...defaultOptions, outputFormat: format }
      const result = createConversionResult(options)
      const content = result.textContent

      expect(content).toContain(format.toUpperCase())
    })
  })
})
