/**
 * Privacy-aware error classes for Image Converter SDK
 */

export class ImageConverterError extends Error {
  public readonly errorCode?: string;
  public readonly details?: Record<string, any>;

  constructor(message: string, errorCode?: string, details?: Record<string, any>) {
    super(message);
    this.name = 'ImageConverterError';
    this.errorCode = errorCode;
    this.details = details || {};
    Object.setPrototypeOf(this, ImageConverterError.prototype);
  }
}

export class NetworkSecurityError extends ImageConverterError {
  constructor(message = 'Network access blocked - only localhost connections allowed') {
    super(message, 'network');
    this.name = 'NetworkSecurityError';
    Object.setPrototypeOf(this, NetworkSecurityError.prototype);
  }
}

export class RateLimitError extends ImageConverterError {
  public readonly retryAfter?: number;

  constructor(message = 'Rate limit exceeded', retryAfter?: number) {
    const details = retryAfter ? { retryAfter } : undefined;
    super(message, 'rate_limit', details);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

export class ValidationError extends ImageConverterError {
  constructor(message = 'Invalid request parameters') {
    super(message, 'verification');
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

export class ServiceUnavailableError extends ImageConverterError {
  constructor(message = 'Local service temporarily unavailable') {
    super(message, 'service_unavailable');
    this.name = 'ServiceUnavailableError';
    Object.setPrototypeOf(this, ServiceUnavailableError.prototype);
  }
}

export class FileError extends ImageConverterError {
  constructor(message = 'File operation failed') {
    // Never include filename in error message for privacy
    super(message, 'file');
    this.name = 'FileError';
    Object.setPrototypeOf(this, FileError.prototype);
  }
}

export class SandboxError extends ImageConverterError {
  constructor(message = 'Security sandbox violation') {
    super(message, 'sandbox');
    this.name = 'SandboxError';
    Object.setPrototypeOf(this, SandboxError.prototype);
  }
}