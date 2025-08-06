/**
 * Data models for Image Converter SDK
 */

export enum OutputFormat {
  WEBP = 'webp',
  AVIF = 'avif',
  JPEG = 'jpeg',
  PNG = 'png',
  HEIF = 'heif',
  JXL = 'jxl',
  WEBP2 = 'webp2'
}

export enum ContentType {
  PHOTO = 'photo',
  ILLUSTRATION = 'illustration',
  SCREENSHOT = 'screenshot',
  DOCUMENT = 'document',
  UNKNOWN = 'unknown'
}

export enum UseCaseType {
  WEB = 'web',
  PRINT = 'print',
  ARCHIVE = 'archive'
}

export interface ConversionRequest {
  outputFormat: OutputFormat | string;
  quality?: number;
  stripMetadata?: boolean;
  preserveMetadata?: boolean;
  preserveGps?: boolean;
  presetId?: string;
}

export interface ConversionResponse {
  conversionId: string;
  processingTime: number;
  compressionRatio: number;
  inputFormat: string;
  outputFormat: string;
  inputSize: number;
  outputSize: number;
  qualityUsed?: number;
  metadataRemoved: boolean;
}

export interface BatchRequest {
  outputFormat: OutputFormat | string;
  quality?: number;
  stripMetadata?: boolean;
  preserveMetadata?: boolean;
  preserveGps?: boolean;
  presetId?: string;
  maxConcurrent?: number;
}

export interface BatchStatus {
  jobId: string;
  status: string;
  totalFiles: number;
  completedFiles: number;
  failedFiles: number;
  progressPercentage: number;
  createdAt: Date;
  updatedAt: Date;
  estimatedCompletion?: Date;
  errors: Array<Record<string, any>>;
}

export interface FormatInfo {
  format: string;
  mimeType: string;
  extensions: string[];
  supportsTransparency: boolean;
  supportsAnimation: boolean;
  lossy: boolean;
  maxDimensions?: { width: number; height: number };
  recommendedUseCases: string[];
}

export interface ContentClassification {
  contentType: ContentType;
  confidence: number;
  processingTimeMs: number;
  faceRegions: Array<{ x: number; y: number; width: number; height: number }>;
  textRegions: Array<{ x: number; y: number; width: number; height: number }>;
  metadata: Record<string, any>;
}

export interface FormatRecommendation {
  recommendedFormats: Array<{
    format: string;
    score: number;
    reasons: string[];
  }>;
  reasoning: Record<string, string>;
  tradeOffs: Record<string, string[]>;
  sizePredictions: Record<string, number>;
  qualityPredictions: Record<string, number>;
}

export interface APIKeyInfo {
  keyId: string;
  name: string;
  createdAt: Date;
  lastUsed?: Date;
  usageCount: number;
  active: boolean;
}

export interface ClientOptions {
  host?: string;
  port?: number;
  apiKey?: string;
  apiVersion?: string;
  timeout?: number;
  verifyLocalhost?: boolean;
}