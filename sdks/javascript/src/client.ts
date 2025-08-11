/**
 * Main client for Image Converter API
 * Enforces localhost-only connections for security
 */

import FormData from 'form-data';
import fetch, { Response } from 'node-fetch';
import { promises as fs } from 'fs';
import { URL } from 'url';
import path from 'path';

import {
  ClientOptions,
  ConversionRequest,
  ConversionResponse,
  BatchRequest,
  BatchStatus,
  FormatInfo,
  ContentClassification,
  FormatRecommendation
} from './models';

import {
  ImageConverterError,
  NetworkSecurityError,
  RateLimitError,
  ValidationError,
  ServiceUnavailableError,
  FileError
} from './errors';

import { SecureAPIKeyManager } from './auth';

export class ImageConverterClient {
  private readonly allowedHosts = ['localhost', '127.0.0.1', '::1', '[::1]'];
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeout: number;
  private readonly verifyLocalhost: boolean;
  private readonly keyManager: SecureAPIKeyManager;

  constructor(options: ClientOptions = {}) {
    const {
      host = 'localhost',
      port = 8000,
      apiKey,
      apiVersion = 'v1',
      timeout = 30000,
      verifyLocalhost = true
    } = options;

    this.verifyLocalhost = verifyLocalhost;
    this.timeout = timeout;
    this.keyManager = new SecureAPIKeyManager();

    // Security check: Enforce localhost only
    if (this.verifyLocalhost && !this.allowedHosts.includes(host)) {
      throw new NetworkSecurityError(
        'Connection to non-localhost host blocked for security'
      );
    }

    this.baseUrl = `http://${host}:${port}/api`;
    if (apiVersion) {
      this.baseUrl = `${this.baseUrl}/${apiVersion}`;
    }

    // Try to get API key from various sources
    this.apiKey = apiKey || 
                  process.env.IMAGE_CONVERTER_API_KEY || 
                  this.keyManager.retrieve('default') || undefined;
  }

  /**
   * Verify URL is localhost only
   */
  private verifyUrlSecurity(url: string): void {
    if (!this.verifyLocalhost) return;

    const parsed = new URL(url);
    if (parsed.hostname && !this.allowedHosts.includes(parsed.hostname)) {
      throw new NetworkSecurityError(
        'Attempted connection to non-localhost address blocked'
      );
    }
  }

  /**
   * Make HTTP request with error handling
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    this.verifyUrlSecurity(url);

    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string> || {})
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
        body: options.body as any  // Type compatibility with node-fetch
      });

      clearTimeout(timeoutId);
      return await this.handleResponse<T>(response);
    } catch (error: any) {
      clearTimeout(timeoutId);
      
      if (error.name === 'AbortError') {
        throw new ServiceUnavailableError('Request timeout');
      }
      
      if (error.code === 'ECONNREFUSED') {
        throw new ServiceUnavailableError('Local service is not running');
      }
      
      throw new ImageConverterError(
        'Request failed',
        'network',
        { originalError: error.message }
      );
    }
  }

  /**
   * Handle API response with proper error handling
   */
  private async handleResponse<T>(response: Response): Promise<T> {
    if (response.ok) {
      const contentType = response.headers.get('content-type') || '';
      
      if (contentType.startsWith('image/')) {
        // For binary responses, return buffer
        const buffer = await response.buffer();
        return buffer as unknown as T;
      }
      
      return await response.json() as T;
    }

    // Handle errors
    let errorMsg = `HTTP ${response.status}`;
    let errorCode = String(response.status);
    
    try {
      const errorData = await response.json() as any;
      errorMsg = errorData.message || errorMsg;
      errorCode = errorData.error_code || errorCode;
    } catch {
      // Ignore JSON parse errors
    }

    switch (response.status) {
      case 413:
        throw new ValidationError('File too large');
      case 415:
        throw new ValidationError('Unsupported file format');
      case 422:
        throw new ValidationError(errorMsg);
      case 429:
        const retryAfter = response.headers.get('X-RateLimit-Reset');
        throw new RateLimitError(errorMsg, retryAfter ? parseInt(retryAfter) : undefined);
      case 503:
        throw new ServiceUnavailableError(errorMsg);
      default:
        throw new ImageConverterError(errorMsg, errorCode);
    }
  }

  /**
   * Convert a single image
   */
  async convertImage(
    imagePath: string,
    outputFormat: string,
    options: Partial<ConversionRequest> = {}
  ): Promise<{ data: Buffer; metadata: ConversionResponse }> {
    // Read file
    let imageData: Buffer;
    try {
      imageData = await fs.readFile(imagePath);
    } catch (error) {
      throw new FileError('Failed to read input file');
    }

    const formData = new FormData();
    formData.append('file', imageData, {
      filename: path.basename(imagePath),
      contentType: 'application/octet-stream'
    });
    formData.append('output_format', outputFormat);
    
    if (options.quality !== undefined) {
      formData.append('quality', String(options.quality));
    }
    if (options.stripMetadata !== undefined) {
      formData.append('strip_metadata', String(options.stripMetadata));
    }
    if (options.presetId) {
      formData.append('preset_id', options.presetId);
    }

    const response = await fetch(`${this.baseUrl}/convert`, {
      method: 'POST',
      body: formData as any,
      headers: this.apiKey ? { 'X-API-Key': this.apiKey } : {}
    });

    if (!response.ok) {
      await this.handleResponse(response);
    }

    const data = await response.buffer();
    
    // Extract metadata from headers
    const metadata: ConversionResponse = {
      conversionId: response.headers.get('X-Conversion-Id') || '',
      processingTime: parseFloat(response.headers.get('X-Processing-Time') || '0'),
      compressionRatio: parseFloat(response.headers.get('X-Compression-Ratio') || '1'),
      inputFormat: response.headers.get('X-Input-Format') || '',
      outputFormat: response.headers.get('X-Output-Format') || outputFormat,
      inputSize: parseInt(response.headers.get('X-Input-Size') || '0'),
      outputSize: parseInt(response.headers.get('X-Output-Size') || String(data.length)),
      qualityUsed: parseInt(response.headers.get('X-Quality-Used') || String(options.quality || 85)),
      metadataRemoved: response.headers.get('X-Metadata-Removed') === 'true'
    };

    return { data, metadata };
  }

  /**
   * Create a batch conversion job
   */
  async createBatch(
    imagePaths: string[],
    outputFormat: string,
    options: Partial<BatchRequest> = {}
  ): Promise<BatchStatus> {
    const formData = new FormData();
    
    // Add files
    for (const imagePath of imagePaths) {
      try {
        const imageData = await fs.readFile(imagePath);
        formData.append('files', imageData, {
          filename: path.basename(imagePath),
          contentType: 'application/octet-stream'
        });
      } catch (error) {
        throw new FileError('Failed to read input file');
      }
    }
    
    formData.append('output_format', outputFormat);
    
    if (options.quality !== undefined) {
      formData.append('quality', String(options.quality));
    }
    if (options.stripMetadata !== undefined) {
      formData.append('strip_metadata', String(options.stripMetadata));
    }
    if (options.maxConcurrent !== undefined) {
      formData.append('max_concurrent', String(options.maxConcurrent));
    }
    if (options.presetId) {
      formData.append('preset_id', options.presetId);
    }

    const response = await fetch(`${this.baseUrl}/batch`, {
      method: 'POST',
      body: formData as any,
      headers: this.apiKey ? { 'X-API-Key': this.apiKey } : {}
    });

    return await this.handleResponse<BatchStatus>(response);
  }

  /**
   * Get batch job status
   */
  async getBatchStatus(jobId: string): Promise<BatchStatus> {
    return await this.request<BatchStatus>(`/batch/${jobId}/status`);
  }

  /**
   * Analyze image content
   */
  async analyzeImage(
    imagePath: string,
    debug = false
  ): Promise<ContentClassification> {
    const imageData = await fs.readFile(imagePath);
    const formData = new FormData();
    
    formData.append('file', imageData, {
      filename: path.basename(imagePath),
      contentType: 'application/octet-stream'
    });

    const url = debug ? '/intelligence/analyze?debug=true' : '/intelligence/analyze';
    
    const response = await fetch(`${this.baseUrl}${url}`, {
      method: 'POST',
      body: formData as any,
      headers: this.apiKey ? { 'X-API-Key': this.apiKey } : {}
    });

    return await this.handleResponse<ContentClassification>(response);
  }

  /**
   * Get format recommendations
   */
  async getFormatRecommendations(
    classification: ContentClassification,
    originalFormat: string,
    originalSizeKb: number,
    useCase?: string,
    prioritize?: string
  ): Promise<FormatRecommendation> {
    const body = {
      content_classification: classification,
      original_format: originalFormat,
      original_size_kb: originalSizeKb,
      use_case: useCase,
      prioritize: prioritize
    };

    return await this.request<FormatRecommendation>('/intelligence/recommend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  /**
   * Get supported formats
   */
  async getSupportedFormats(): Promise<FormatInfo[]> {
    const response = await this.request<{ formats: FormatInfo[] }>('/formats');
    return response.formats;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<Record<string, any>> {
    return await this.request<Record<string, any>>('/health');
  }

  /**
   * Store API key securely
   */
  async storeApiKey(apiKey: string, keyName = 'default'): Promise<boolean> {
    return this.keyManager.store(keyName, apiKey);
  }

  /**
   * Retrieve stored API key
   */
  retrieveApiKey(keyName = 'default'): string | null {
    return this.keyManager.retrieve(keyName);
  }
}