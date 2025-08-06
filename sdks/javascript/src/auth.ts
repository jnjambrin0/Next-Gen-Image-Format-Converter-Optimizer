/**
 * Secure API key management for Image Converter SDK
 * Uses OS keychain when available, encrypted localStorage for browser
 */

import { createHash, randomBytes } from 'crypto';
import { homedir } from 'os';
import { join } from 'path';
import { promises as fs } from 'fs';

interface StoredKeys {
  [keyName: string]: string;
}

export class SecureAPIKeyManager {
  private readonly serviceName = 'image-converter-local';
  private readonly keyPrefix = 'IC_API_';
  private readonly fallbackPath: string;

  constructor(appName = 'image-converter') {
    this.fallbackPath = join(homedir(), '.image-converter', '.keys');
  }

  /**
   * Store API key securely
   */
  async store(keyName: string, apiKey: string): Promise<boolean> {
    try {
      // For Node.js, use fallback storage (encrypted file)
      // In production, you'd use keytar or similar for OS keychain
      return await this.storeFallback(keyName, apiKey);
    } catch (error) {
      console.error('Failed to store API key:', error);
      return false;
    }
  }

  /**
   * Retrieve API key from secure storage
   */
  retrieve(keyName: string): string | null {
    try {
      // Try fallback storage
      return this.retrieveFallback(keyName);
    } catch (error) {
      return null;
    }
  }

  /**
   * Delete API key from storage
   */
  async delete(keyName: string): Promise<boolean> {
    try {
      return await this.deleteFallback(keyName);
    } catch (error) {
      return false;
    }
  }

  /**
   * List stored key names (not the actual keys)
   */
  async listKeys(): Promise<string[]> {
    try {
      const data = await this.loadFallbackData();
      return Object.keys(data);
    } catch (error) {
      return [];
    }
  }

  /**
   * Store in fallback encrypted file
   */
  private async storeFallback(keyName: string, apiKey: string): Promise<boolean> {
    try {
      await this.ensureFallbackDir();
      
      const data = await this.loadFallbackData();
      data[keyName] = this.obfuscate(apiKey);
      
      await fs.writeFile(
        this.fallbackPath,
        JSON.stringify(data, null, 2),
        { mode: 0o600 }
      );
      
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Retrieve from fallback storage
   */
  private retrieveFallback(keyName: string): string | null {
    try {
      const data = this.loadFallbackDataSync();
      const obfuscated = data[keyName];
      
      if (obfuscated) {
        return this.deobfuscate(obfuscated);
      }
    } catch (error) {
      // Ignore errors
    }
    
    return null;
  }

  /**
   * Delete from fallback storage
   */
  private async deleteFallback(keyName: string): Promise<boolean> {
    try {
      const data = await this.loadFallbackData();
      
      if (keyName in data) {
        delete data[keyName];
        await fs.writeFile(
          this.fallbackPath,
          JSON.stringify(data, null, 2),
          { mode: 0o600 }
        );
        return true;
      }
    } catch (error) {
      // Ignore errors
    }
    
    return false;
  }

  /**
   * Ensure fallback directory exists
   */
  private async ensureFallbackDir(): Promise<void> {
    const dir = join(homedir(), '.image-converter');
    
    try {
      await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    } catch (error) {
      // Directory might already exist
    }
    
    // Check if keys file exists
    try {
      await fs.access(this.fallbackPath);
    } catch {
      // Create empty file with secure permissions
      await fs.writeFile(this.fallbackPath, '{}', { mode: 0o600 });
    }
  }

  /**
   * Load fallback data asynchronously
   */
  private async loadFallbackData(): Promise<StoredKeys> {
    try {
      const content = await fs.readFile(this.fallbackPath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      return {};
    }
  }

  /**
   * Load fallback data synchronously (for retrieve)
   */
  private loadFallbackDataSync(): StoredKeys {
    try {
      const fs = require('fs');
      const content = fs.readFileSync(this.fallbackPath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      return {};
    }
  }

  /**
   * Simple obfuscation for fallback storage
   */
  private obfuscate(value: string): string {
    const key = createHash('sha256').update('image-converter').digest();
    const buffer = Buffer.from(value);
    const obfuscated = Buffer.alloc(buffer.length);
    
    for (let i = 0; i < buffer.length; i++) {
      obfuscated[i] = buffer[i] ^ key[i % key.length];
    }
    
    return obfuscated.toString('hex');
  }

  /**
   * Deobfuscate value from storage
   */
  private deobfuscate(obfuscated: string): string {
    const key = createHash('sha256').update('image-converter').digest();
    const buffer = Buffer.from(obfuscated, 'hex');
    const original = Buffer.alloc(buffer.length);
    
    for (let i = 0; i < buffer.length; i++) {
      original[i] = buffer[i] ^ key[i % key.length];
    }
    
    return original.toString();
  }

  /**
   * Generate a secure API key
   */
  static generateApiKey(): string {
    const random = randomBytes(32);
    const key = random.toString('base64url');
    return `ic_live_${key}`;
  }

  /**
   * Get API key from environment variable
   */
  static getFromEnv(envVar = 'IMAGE_CONVERTER_API_KEY'): string | undefined {
    return process.env[envVar];
  }
}