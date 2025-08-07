/**
 * Integration tests for Image Converter JavaScript SDK
 */

const { ImageConverterClient, NetworkSecurityError, ValidationError } = require('../../dist/index');
const fs = require('fs').promises;
const path = require('path');

describe('ImageConverterClient', () => {
  let client;

  beforeEach(() => {
    client = new ImageConverterClient({
      port: 8000,
      timeout: 5000,
    });
  });

  describe('Security Features', () => {
    test('should enforce localhost-only connections', () => {
      expect(() => {
        new ImageConverterClient({ host: 'example.com' });
      }).toThrow(NetworkSecurityError);

      expect(() => {
        new ImageConverterClient({ host: '192.168.1.100' });
      }).toThrow(NetworkSecurityError);

      expect(() => {
        new ImageConverterClient({ host: 'google.com' });
      }).toThrow(NetworkSecurityError);
    });

    test('should allow localhost connections', () => {
      expect(() => {
        new ImageConverterClient({ host: 'localhost' });
      }).not.toThrow();

      expect(() => {
        new ImageConverterClient({ host: '127.0.0.1' });
      }).not.toThrow();

      expect(() => {
        new ImageConverterClient({ host: '::1' });
      }).not.toThrow();
    });

    test('should allow disabling localhost verification (dangerous)', () => {
      expect(() => {
        new ImageConverterClient({
          host: '192.168.1.100',
          verifyLocalhost: false,
        });
      }).not.toThrow();
    });
  });

  describe('API Key Management', () => {
    test('should load API key from environment', () => {
      const originalEnv = process.env.IMAGE_CONVERTER_API_KEY;
      process.env.IMAGE_CONVERTER_API_KEY = 'test_key_123';

      const clientWithEnvKey = new ImageConverterClient();
      expect(clientWithEnvKey.apiKey).toBe('test_key_123');

      // Restore original env
      if (originalEnv) {
        process.env.IMAGE_CONVERTER_API_KEY = originalEnv;
      } else {
        delete process.env.IMAGE_CONVERTER_API_KEY;
      }
    });

    test('should store and retrieve API keys securely', async () => {
      const testKey = 'ic_live_test_key_12345';
      
      const success = await client.storeApiKey(testKey, 'test');
      expect(success).toBe(true);

      const retrieved = client.retrieveApiKey('test');
      expect(retrieved).toBe(testKey);

      // Clean up
      await client.keyManager.delete('test');
    });
  });

  describe('Error Handling', () => {
    test('should have privacy-aware error messages', () => {
      const fileError = new FileError();
      expect(fileError.message).not.toContain('/');
      expect(fileError.message).not.toContain('\\');
      expect(fileError.errorCode).toBe('file');

      const validationError = new ValidationError('Invalid parameters');
      expect(validationError.message).toBe('Invalid parameters');
      expect(validationError.errorCode).toBe('verification');
    });

    test('should handle rate limit errors', () => {
      const rateLimitError = new RateLimitError('Too many requests', 60);
      expect(rateLimitError.retryAfter).toBe(60);
      expect(rateLimitError.errorCode).toBe('rate_limit');
    });
  });

  describe('API Integration', () => {
    // Skip these tests if API server is not running
    const skipIfNoServer = async () => {
      try {
        await client.healthCheck();
        return false;
      } catch (error) {
        return true;
      }
    };

    test('should check health status', async () => {
      if (await skipIfNoServer()) {
        console.log('Skipping: API server not running');
        return;
      }

      const health = await client.healthCheck();
      expect(health).toHaveProperty('status');
      expect(health.status).toBe('healthy');
    });

    test('should get supported formats', async () => {
      if (await skipIfNoServer()) {
        console.log('Skipping: API server not running');
        return;
      }

      const formats = await client.getSupportedFormats();
      expect(Array.isArray(formats)).toBe(true);
      expect(formats.length).toBeGreaterThan(0);

      // Check for expected formats
      const formatNames = formats.map(f => f.format);
      expect(formatNames).toContain('webp');
      expect(formatNames).toContain('jpeg');
      expect(formatNames).toContain('png');
    });

    test('should convert image', async () => {
      if (await skipIfNoServer()) {
        console.log('Skipping: API server not running');
        return;
      }

      // Create a test image file
      const testImagePath = path.join(__dirname, 'test.jpg');
      const testImageData = Buffer.from('/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAA==', 'base64');
      await fs.writeFile(testImagePath, testImageData);

      try {
        const { data, metadata } = await client.convertImage(
          testImagePath,
          'webp',
          { quality: 85, stripMetadata: true }
        );

        expect(Buffer.isBuffer(data)).toBe(true);
        expect(metadata).toHaveProperty('conversionId');
        expect(metadata).toHaveProperty('processingTime');
        expect(metadata).toHaveProperty('outputFormat');
        expect(metadata.outputFormat).toBe('webp');
      } finally {
        // Clean up test file
        await fs.unlink(testImagePath).catch(() => {});
      }
    });
  });
});

describe('SecureAPIKeyManager', () => {
  const { SecureAPIKeyManager } = require('../../dist/auth');
  let manager;

  beforeEach(() => {
    manager = new SecureAPIKeyManager();
  });

  test('should generate secure API keys', () => {
    const key = SecureAPIKeyManager.generateApiKey();
    expect(key).toMatch(/^ic_live_[\w-]+$/);
    expect(key.length).toBeGreaterThan(40);

    // Should generate unique keys
    const key2 = SecureAPIKeyManager.generateApiKey();
    expect(key2).not.toBe(key);
  });

  test('should obfuscate and deobfuscate values', () => {
    const originalValue = 'sensitive_api_key_12345';
    
    const obfuscated = manager.obfuscate(originalValue);
    expect(obfuscated).not.toBe(originalValue);
    expect(obfuscated.length).toBeGreaterThan(0);

    const deobfuscated = manager.deobfuscate(obfuscated);
    expect(deobfuscated).toBe(originalValue);
  });

  test('should store and retrieve keys', async () => {
    const keyName = 'test_key';
    const apiKey = 'ic_live_test_12345';

    const stored = await manager.store(keyName, apiKey);
    expect(stored).toBe(true);

    const retrieved = manager.retrieve(keyName);
    expect(retrieved).toBe(apiKey);

    // Clean up
    await manager.delete(keyName);

    const afterDelete = manager.retrieve(keyName);
    expect(afterDelete).toBeNull();
  });

  test('should list stored key names', async () => {
    await manager.store('key1', 'value1');
    await manager.store('key2', 'value2');

    const keys = await manager.listKeys();
    expect(keys).toContain('key1');
    expect(keys).toContain('key2');

    // Clean up
    await manager.delete('key1');
    await manager.delete('key2');
  });
});