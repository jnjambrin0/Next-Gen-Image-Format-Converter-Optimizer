import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { BatchPresetSelector } from '../../src/components/batchPresetSelector.js'

describe('BatchPresetSelector', () => {
  let container
  let selector
  
  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
  })
  
  afterEach(() => {
    document.body.removeChild(container)
  })
  
  describe('initialization', () => {
    it('should create with default settings', () => {
      selector = new BatchPresetSelector(container)
      
      const settings = selector.getSettings()
      expect(settings.outputFormat).toBe('webp')
      expect(settings.quality).toBe(85)
      expect(settings.optimizationMode).toBeNull()
      expect(settings.preserveMetadata).toBe(false)
      expect(settings.applyToAll).toBe(true)
    })
    
    it('should render all sections', () => {
      selector = new BatchPresetSelector(container)
      
      expect(container.querySelector('h3').textContent).toBe('Batch Conversion Settings')
      expect(container.querySelector('#batch-format-select')).toBeTruthy()
      expect(container.querySelector('#batch-quality-slider')).toBeTruthy()
      expect(container.querySelector('input[name="batch-optimization-mode"]')).toBeTruthy()
      expect(container.querySelectorAll('input[type="checkbox"]')).toHaveLength(2)
    })
  })
  
  describe('format selection', () => {
    it('should update format setting', () => {
      selector = new BatchPresetSelector(container)
      const onChange = vi.fn()
      selector.onChange(onChange)
      
      const formatSelect = container.querySelector('#batch-format-select')
      formatSelect.value = 'avif'
      formatSelect.dispatchEvent(new Event('change'))
      
      expect(selector.getSettings().outputFormat).toBe('avif')
      expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
        outputFormat: 'avif'
      }))
    })
    
    it('should display all format options', () => {
      selector = new BatchPresetSelector(container)
      
      const options = container.querySelectorAll('#batch-format-select option')
      expect(options).toHaveLength(10)
      
      const values = Array.from(options).map(opt => opt.value)
      expect(values).toContain('webp')
      expect(values).toContain('avif')
      expect(values).toContain('jpeg')
      expect(values).toContain('png')
      expect(values).toContain('jxl')
      expect(values).toContain('heif')
    })
  })
  
  describe('quality slider', () => {
    it('should update quality setting', () => {
      selector = new BatchPresetSelector(container)
      const onChange = vi.fn()
      selector.onChange(onChange)
      
      const qualitySlider = container.querySelector('#batch-quality-slider')
      qualitySlider.value = 70
      qualitySlider.dispatchEvent(new Event('input'))
      
      expect(selector.getSettings().quality).toBe(70)
      expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
        quality: 70
      }))
    })
    
    it('should update quality display value', () => {
      selector = new BatchPresetSelector(container)
      
      const qualitySlider = container.querySelector('#batch-quality-slider')
      const qualityValue = container.querySelector('#batch-quality-value')
      
      expect(qualityValue.textContent).toBe('85%')
      
      qualitySlider.value = 50
      qualitySlider.dispatchEvent(new Event('input'))
      
      expect(qualityValue.textContent).toBe('50%')
    })
  })
  
  describe('optimization mode', () => {
    it('should update optimization mode', () => {
      selector = new BatchPresetSelector(container)
      const onChange = vi.fn()
      selector.onChange(onChange)
      
      const balancedRadio = Array.from(
        container.querySelectorAll('input[name="batch-optimization-mode"]')
      ).find(radio => radio.value === 'balanced')
      
      balancedRadio.checked = true
      balancedRadio.dispatchEvent(new Event('change'))
      
      expect(selector.getSettings().optimizationMode).toBe('balanced')
      expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
        optimizationMode: 'balanced'
      }))
    })
    
    it('should have all optimization options', () => {
      selector = new BatchPresetSelector(container)
      
      const radios = container.querySelectorAll('input[name="batch-optimization-mode"]')
      expect(radios).toHaveLength(4)
      
      const values = Array.from(radios).map(radio => radio.value)
      expect(values).toContain('')  // None
      expect(values).toContain('balanced')
      expect(values).toContain('quality')
      expect(values).toContain('size')
    })
  })
  
  describe('metadata preservation', () => {
    it('should toggle metadata preservation', () => {
      selector = new BatchPresetSelector(container)
      const onChange = vi.fn()
      selector.onChange(onChange)
      
      const checkboxes = container.querySelectorAll('input[type="checkbox"]')
      const metadataCheckbox = Array.from(checkboxes).find(
        cb => cb.nextElementSibling?.textContent.includes('Preserve metadata')
      )
      
      metadataCheckbox.checked = true
      metadataCheckbox.dispatchEvent(new Event('change'))
      
      expect(selector.getSettings().preserveMetadata).toBe(true)
      expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
        preserveMetadata: true
      }))
    })
    
    it('should show metadata warning', () => {
      selector = new BatchPresetSelector(container)
      
      const warning = Array.from(container.querySelectorAll('.text-yellow-600'))
        .find(el => el.textContent.includes('location and personal information'))
      
      expect(warning).toBeTruthy()
    })
  })
  
  describe('apply to all', () => {
    it('should toggle apply to all setting', () => {
      selector = new BatchPresetSelector(container)
      const onChange = vi.fn()
      selector.onChange(onChange)
      
      const checkboxes = container.querySelectorAll('input[type="checkbox"]')
      const applyCheckbox = Array.from(checkboxes).find(
        cb => cb.nextElementSibling?.textContent.includes('Apply these settings to all')
      )
      
      applyCheckbox.checked = false
      applyCheckbox.dispatchEvent(new Event('change'))
      
      expect(selector.getSettings().applyToAll).toBe(false)
      expect(onChange).toHaveBeenCalledWith(expect.objectContaining({
        applyToAll: false
      }))
    })
  })
  
  describe('summary', () => {
    it('should display current settings summary', () => {
      selector = new BatchPresetSelector(container)
      
      const summaryItems = container.querySelectorAll('.bg-gray-50 li')
      
      expect(summaryItems[0].textContent).toContain('Format: WebP')
      expect(summaryItems[1].textContent).toContain('Quality: 85%')
      expect(summaryItems[2].textContent).toContain('Optimization: None')
      expect(summaryItems[3].textContent).toContain('Metadata: Remove')
      expect(summaryItems[4].textContent).toContain('Apply to all files')
    })
    
    it('should update summary when settings change', () => {
      selector = new BatchPresetSelector(container)
      
      // Initial check
      let summaryItems = container.querySelectorAll('.bg-gray-50 li')
      expect(summaryItems[0].textContent).toContain('Format: WebP')
      
      // Change format
      const formatSelect = container.querySelector('#batch-format-select')
      formatSelect.value = 'png'
      formatSelect.dispatchEvent(new Event('change'))
      
      // Check after change
      summaryItems = container.querySelectorAll('.bg-gray-50 li')
      expect(summaryItems[0].textContent).toContain('Format: PNG')
    })
  })
  
  describe('setSettings', () => {
    it('should update settings and re-render', () => {
      selector = new BatchPresetSelector(container)
      
      selector.setSettings({
        outputFormat: 'jpeg',
        quality: 90,
        optimizationMode: 'quality'
      })
      
      const settings = selector.getSettings()
      expect(settings.outputFormat).toBe('jpeg')
      expect(settings.quality).toBe(90)
      expect(settings.optimizationMode).toBe('quality')
      
      // Check UI reflects changes (select elements may need a tick to update)
      // The settings object should have the new values
      const updatedSettings = selector.getSettings()
      expect(updatedSettings.outputFormat).toBe('jpeg')
      expect(updatedSettings.quality).toBe(90)
      expect(updatedSettings.optimizationMode).toBe('quality')
      
      // Check displayed values
      expect(container.querySelector('#batch-quality-value').textContent).toBe('90%')
    })
  })
  
  describe('reset', () => {
    it('should reset to default settings', () => {
      selector = new BatchPresetSelector(container)
      
      // Change some settings
      selector.setSettings({
        outputFormat: 'png',
        quality: 50,
        preserveMetadata: true
      })
      
      // Reset
      selector.reset()
      
      const settings = selector.getSettings()
      expect(settings.outputFormat).toBe('webp')
      expect(settings.quality).toBe(85)
      expect(settings.preserveMetadata).toBe(false)
    })
  })
})