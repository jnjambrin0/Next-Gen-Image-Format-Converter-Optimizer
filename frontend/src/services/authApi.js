/**
 * API client for authentication and API key management
 */

const API_BASE_URL = `http://${import.meta.env.VITE_API_HOST || 'localhost'}:${import.meta.env.VITE_API_PORT || 8080}/api`;

class AuthApiError extends Error {
    constructor(message, status, details = null) {
        super(message);
        this.name = 'AuthApiError';
        this.status = status;
        this.details = details;
    }
}

class AuthApi {
    constructor() {
        this.baseUrl = `${API_BASE_URL}/auth`;
    }

    /**
     * Make an authenticated API request
     */
    async makeRequest(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        };

        const requestOptions = { ...defaultOptions, ...options };

        try {
            const response = await fetch(url, requestOptions);
            
            // Handle rate limiting
            if (response.status === 429) {
                const retryAfter = response.headers.get('Retry-After') || '60';
                throw new AuthApiError(
                    `Rate limit exceeded. Please try again in ${retryAfter} seconds.`,
                    429,
                    { retryAfter: parseInt(retryAfter) }
                );
            }

            // Parse response
            let data = null;
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            }

            if (!response.ok) {
                const errorMessage = data?.message || `HTTP error ${response.status}`;
                throw new AuthApiError(errorMessage, response.status, data);
            }

            return data;
            
        } catch (error) {
            if (error instanceof AuthApiError) {
                throw error;
            }
            
            // Network or other errors
            console.error('API request failed:', error);
            throw new AuthApiError(
                'Network error. Please check your connection and try again.',
                0,
                { originalError: error.message }
            );
        }
    }

    /**
     * Create a new API key
     */
    async createApiKey(keyData) {
        return await this.makeRequest('/api-keys', {
            method: 'POST',
            body: JSON.stringify(keyData)
        });
    }

    /**
     * List all API keys
     */
    async listApiKeys(includeInactive = false) {
        const params = new URLSearchParams();
        if (includeInactive) {
            params.append('include_inactive', 'true');
        }
        
        const endpoint = `/api-keys${params.toString() ? '?' + params.toString() : ''}`;
        return await this.makeRequest(endpoint);
    }

    /**
     * Get a specific API key by ID
     */
    async getApiKey(keyId) {
        return await this.makeRequest(`/api-keys/${keyId}`);
    }

    /**
     * Update an API key
     */
    async updateApiKey(keyId, updateData) {
        return await this.makeRequest(`/api-keys/${keyId}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
        });
    }

    /**
     * Revoke (deactivate) an API key
     */
    async revokeApiKey(keyId) {
        return await this.makeRequest(`/api-keys/${keyId}`, {
            method: 'DELETE'
        });
    }

    /**
     * Get usage statistics for a specific API key
     */
    async getApiKeyUsage(keyId, days = 7) {
        const params = new URLSearchParams();
        params.append('days', days.toString());
        
        return await this.makeRequest(`/api-keys/${keyId}/usage?${params.toString()}`);
    }

    /**
     * Get overall usage statistics
     */
    async getOverallUsage(days = 7) {
        const params = new URLSearchParams();
        params.append('days', days.toString());
        
        return await this.makeRequest(`/usage?${params.toString()}`);
    }

    /**
     * Clean up expired API keys
     */
    async cleanupExpiredKeys() {
        return await this.makeRequest('/cleanup-expired', {
            method: 'POST'
        });
    }

    /**
     * Test API key authentication
     */
    async testApiKey(apiKey) {
        try {
            // Make a simple authenticated request to test the key
            const response = await fetch(`${API_BASE_URL}/health`, {
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                }
            });

            return {
                valid: response.ok,
                status: response.status,
                authenticated: response.headers.get('X-Authenticated') === 'true'
            };
            
        } catch (error) {
            return {
                valid: false,
                status: 0,
                error: error.message,
                authenticated: false
            };
        }
    }

    /**
     * Get rate limit status for current client
     */
    async getRateLimitStatus() {
        try {
            const response = await fetch(`${API_BASE_URL}/health`, {
                method: 'HEAD' // Just get headers
            });

            return {
                limit: parseInt(response.headers.get('X-RateLimit-Limit') || '60'),
                remaining: parseInt(response.headers.get('X-RateLimit-Remaining') || '60'),
                reset: parseInt(response.headers.get('X-RateLimit-Reset') || '0'),
                window: parseInt(response.headers.get('X-RateLimit-Window') || '60')
            };
            
        } catch (error) {
            console.warn('Failed to get rate limit status:', error);
            return {
                limit: 60,
                remaining: 60,
                reset: Math.floor(Date.now() / 1000) + 60,
                window: 60
            };
        }
    }

    /**
     * Validate API key format
     */
    validateApiKeyFormat(apiKey) {
        if (!apiKey || typeof apiKey !== 'string') {
            return { valid: false, error: 'API key must be a non-empty string' };
        }

        // Check basic format (should be URL-safe base64, around 43 chars)
        const base64Pattern = /^[A-Za-z0-9_-]+$/;
        if (!base64Pattern.test(apiKey)) {
            return { valid: false, error: 'API key contains invalid characters' };
        }

        if (apiKey.length < 20 || apiKey.length > 100) {
            return { valid: false, error: 'API key length is invalid' };
        }

        return { valid: true };
    }

    /**
     * Format error message for display
     */
    formatErrorMessage(error) {
        if (error instanceof AuthApiError) {
            if (error.details && error.details.error_code) {
                return `${error.message} (${error.details.error_code})`;
            }
            return error.message;
        }
        
        return error.message || 'An unknown error occurred';
    }

    /**
     * Get API documentation info
     */
    getApiDocumentation() {
        return {
            baseUrl: this.baseUrl,
            endpoints: {
                'POST /api-keys': 'Create a new API key',
                'GET /api-keys': 'List all API keys',
                'GET /api-keys/{id}': 'Get specific API key',
                'PUT /api-keys/{id}': 'Update API key',
                'DELETE /api-keys/{id}': 'Revoke API key',
                'GET /api-keys/{id}/usage': 'Get usage stats for key',
                'GET /usage': 'Get overall usage stats',
                'POST /cleanup-expired': 'Clean up expired keys'
            },
            authentication: {
                methods: ['Bearer token', 'X-API-Key header', 'api_key query parameter'],
                example: 'Authorization: Bearer YOUR_API_KEY_HERE'
            },
            rateLimiting: {
                default: '60 requests per minute',
                headers: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
                customizable: 'API keys can have custom rate limits'
            }
        };
    }
}

// Global instance
export const authApi = new AuthApi();

// Export error class for custom error handling
export { AuthApiError };