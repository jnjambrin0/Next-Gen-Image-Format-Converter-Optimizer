import { authApi } from '../services/authApi.js';

export class ApiKeyManager {
    constructor() {
        this.apiKeys = [];
        this.isVisible = false;
        this.eventHandlers = new Map();
        this.container = null;
    }

    render() {
        if (this.container) {
            this.container.remove();
        }

        this.container = document.createElement('div');
        this.container.className = 'api-key-manager';
        this.container.innerHTML = `
            <div class="modal-overlay" style="display: ${this.isVisible ? 'flex' : 'none'}">
                <div class="modal-content api-key-modal">
                    <div class="modal-header">
                        <h2>API Key Management</h2>
                        <button class="btn-close" type="button">&times;</button>
                    </div>
                    
                    <div class="modal-body">
                        <!-- Create New API Key Section -->
                        <div class="create-key-section">
                            <h3>Create New API Key</h3>
                            <form class="create-key-form">
                                <div class="form-group">
                                    <label for="keyName">Name (optional):</label>
                                    <input type="text" id="keyName" placeholder="e.g., Production App" maxlength="100">
                                </div>
                                <div class="form-group">
                                    <label for="rateLimitOverride">Rate Limit Override (requests/minute):</label>
                                    <input type="number" id="rateLimitOverride" min="1" max="1000" placeholder="Default: 60">
                                </div>
                                <div class="form-group">
                                    <label for="expiresDays">Expires in (days):</label>
                                    <input type="number" id="expiresDays" min="1" max="365" placeholder="Never expires">
                                </div>
                                <button type="submit" class="btn btn-primary">Create API Key</button>
                            </form>
                        </div>

                        <!-- API Keys List -->
                        <div class="keys-list-section">
                            <h3>Existing API Keys</h3>
                            <div class="keys-list"></div>
                        </div>

                        <!-- Usage Statistics -->
                        <div class="usage-stats-section" style="display: none;">
                            <h3>Usage Statistics</h3>
                            <div class="usage-stats-content"></div>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button class="btn btn-secondary close-modal">Close</button>
                        <button class="btn btn-info show-usage-stats">Show Usage Stats</button>
                    </div>
                </div>
            </div>

            <!-- New API Key Display Modal -->
            <div class="new-key-modal" style="display: none;">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>API Key Created Successfully</h3>
                        <span class="close-new-key">&times;</span>
                    </div>
                    <div class="modal-body">
                        <div class="warning-message">
                            <strong>⚠️ Important:</strong> This API key will only be shown once. Please copy it now and store it securely.
                        </div>
                        <div class="api-key-display">
                            <label>Your new API key:</label>
                            <div class="key-container">
                                <input type="text" class="api-key-value" readonly>
                                <button class="btn btn-copy" type="button">Copy</button>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary close-new-key">I've saved the key</button>
                    </div>
                </div>
            </div>
        `;

        // Add styles
        this.addStyles();

        // Attach event handlers
        this.attachEventHandlers();

        document.body.appendChild(this.container);
        return this.container;
    }

    addStyles() {
        if (document.getElementById('api-key-manager-styles')) {
            return;
        }

        const styles = document.createElement('style');
        styles.id = 'api-key-manager-styles';
        styles.textContent = `
            .api-key-manager .modal-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 1000;
            }

            .api-key-modal {
                width: 90%;
                max-width: 800px;
                max-height: 90vh;
                overflow-y: auto;
                background: white;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }

            .api-key-manager .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1rem;
                border-bottom: 1px solid #e0e0e0;
            }

            .api-key-manager .modal-header h2 {
                margin: 0;
                color: #333;
            }

            .api-key-manager .btn-close {
                background: none;
                border: none;
                font-size: 1.5rem;
                cursor: pointer;
                color: #666;
            }

            .api-key-manager .modal-body {
                padding: 1rem;
            }

            .api-key-manager .create-key-section,
            .api-key-manager .keys-list-section,
            .api-key-manager .usage-stats-section {
                margin-bottom: 2rem;
                padding: 1rem;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                background: #f9f9f9;
            }

            .api-key-manager .form-group {
                margin-bottom: 1rem;
            }

            .api-key-manager .form-group label {
                display: block;
                margin-bottom: 0.5rem;
                font-weight: bold;
                color: #555;
            }

            .api-key-manager .form-group input {
                width: 100%;
                padding: 0.75rem;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 1rem;
            }

            .api-key-manager .api-key-item {
                background: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 1rem;
                margin-bottom: 1rem;
            }

            .api-key-manager .key-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 0.5rem;
            }

            .api-key-manager .key-name {
                font-weight: bold;
                color: #333;
            }

            .api-key-manager .key-status {
                padding: 0.25rem 0.5rem;
                border-radius: 3px;
                font-size: 0.8rem;
                font-weight: bold;
                text-transform: uppercase;
            }

            .api-key-manager .key-status.active {
                background: #d4edda;
                color: #155724;
            }

            .api-key-manager .key-status.inactive {
                background: #f8d7da;
                color: #721c24;
            }

            .api-key-manager .key-details {
                font-size: 0.9rem;
                color: #666;
                margin-bottom: 1rem;
            }

            .api-key-manager .key-actions {
                display: flex;
                gap: 0.5rem;
            }

            .api-key-manager .btn {
                padding: 0.5rem 1rem;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 0.9rem;
                transition: background-color 0.2s;
            }

            .api-key-manager .btn-primary {
                background: #007bff;
                color: white;
            }

            .api-key-manager .btn-primary:hover {
                background: #0056b3;
            }

            .api-key-manager .btn-secondary {
                background: #6c757d;
                color: white;
            }

            .api-key-manager .btn-secondary:hover {
                background: #545b62;
            }

            .api-key-manager .btn-danger {
                background: #dc3545;
                color: white;
            }

            .api-key-manager .btn-danger:hover {
                background: #c82333;
            }

            .api-key-manager .btn-info {
                background: #17a2b8;
                color: white;
            }

            .api-key-manager .btn-info:hover {
                background: #138496;
            }

            .api-key-manager .btn-copy {
                background: #28a745;
                color: white;
                margin-left: 0.5rem;
            }

            .api-key-manager .btn-copy:hover {
                background: #218838;
            }

            .api-key-manager .modal-footer {
                display: flex;
                justify-content: space-between;
                padding: 1rem;
                border-top: 1px solid #e0e0e0;
                background: #f8f9fa;
            }

            .api-key-manager .new-key-modal {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 1001;
            }

            .api-key-manager .new-key-modal .modal-content {
                width: 90%;
                max-width: 500px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }

            .api-key-manager .warning-message {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                color: #856404;
                padding: 1rem;
                border-radius: 4px;
                margin-bottom: 1rem;
            }

            .api-key-manager .api-key-display {
                margin-bottom: 1rem;
            }

            .api-key-manager .key-container {
                display: flex;
                align-items: center;
            }

            .api-key-manager .api-key-value {
                flex: 1;
                font-family: monospace;
                background: #f8f9fa;
                border: 1px solid #ddd;
                padding: 0.75rem;
                border-radius: 4px 0 0 4px;
            }

            .api-key-manager .usage-stats-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 1rem;
            }

            .api-key-manager .usage-stats-table th,
            .api-key-manager .usage-stats-table td {
                text-align: left;
                padding: 0.5rem;
                border-bottom: 1px solid #ddd;
            }

            .api-key-manager .usage-stats-table th {
                background: #f8f9fa;
                font-weight: bold;
            }

            .api-key-manager .error-message {
                background: #f8d7da;
                border: 1px solid #f1aeb5;
                color: #721c24;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }

            .api-key-manager .success-message {
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
                padding: 1rem;
                border-radius: 4px;
                margin: 1rem 0;
            }

            .loading {
                opacity: 0.6;
                pointer-events: none;
            }
        `;

        document.head.appendChild(styles);
    }

    attachEventHandlers() {
        // Store handlers for cleanup
        const handlers = new Map();

        // Close modal handlers
        const closeHandler = () => this.hide();
        const closeButtons = this.container.querySelectorAll('.btn-close, .close-modal');
        closeButtons.forEach(btn => {
            btn.addEventListener('click', closeHandler);
            handlers.set(`close-${btn.className}`, { element: btn, event: 'click', handler: closeHandler });
        });

        // Create API key form
        const createForm = this.container.querySelector('.create-key-form');
        const createFormHandler = (e) => this.handleCreateKey(e);
        createForm.addEventListener('submit', createFormHandler);
        handlers.set('create-form', { element: createForm, event: 'submit', handler: createFormHandler });

        // Usage stats button
        const statsBtn = this.container.querySelector('.show-usage-stats');
        const statsHandler = () => this.showUsageStats();
        statsBtn.addEventListener('click', statsHandler);
        handlers.set('stats-btn', { element: statsBtn, event: 'click', handler: statsHandler });

        // New key modal handlers
        const newKeyCloseButtons = this.container.querySelectorAll('.close-new-key');
        const newKeyCloseHandler = () => this.hideNewKeyModal();
        newKeyCloseButtons.forEach(btn => {
            btn.addEventListener('click', newKeyCloseHandler);
            handlers.set(`new-key-close-${btn.className}`, { element: btn, event: 'click', handler: newKeyCloseHandler });
        });

        // Copy button handler
        const copyBtn = this.container.querySelector('.btn-copy');
        const copyHandler = () => this.copyApiKey();
        copyBtn.addEventListener('click', copyHandler);
        handlers.set('copy-btn', { element: copyBtn, event: 'click', handler: copyHandler });

        // Store all handlers for cleanup
        this.eventHandlers = handlers;
    }

    show() {
        this.isVisible = true;
        if (!this.container) {
            this.render();
        } else {
            this.container.querySelector('.modal-overlay').style.display = 'flex';
        }
        this.loadApiKeys();
    }

    hide() {
        this.isVisible = false;
        if (this.container) {
            this.container.querySelector('.modal-overlay').style.display = 'none';
        }
    }

    async loadApiKeys() {
        try {
            const keysList = this.container.querySelector('.keys-list');
            keysList.innerHTML = '<div class="loading">Loading API keys...</div>';

            this.apiKeys = await authApi.listApiKeys();
            this.renderApiKeysList();
        } catch (error) {
            console.error('Failed to load API keys:', error);
            this.showError('Failed to load API keys. Please try again.');
        }
    }

    renderApiKeysList() {
        const keysList = this.container.querySelector('.keys-list');
        
        if (this.apiKeys.length === 0) {
            keysList.innerHTML = '<p>No API keys found. Create your first API key above.</p>';
            return;
        }

        keysList.innerHTML = this.apiKeys.map(key => `
            <div class="api-key-item">
                <div class="key-header">
                    <span class="key-name">${key.name || `Key ${key.id.substring(0, 8)}`}</span>
                    <span class="key-status ${key.is_active ? 'active' : 'inactive'}">
                        ${key.is_active ? 'Active' : 'Inactive'}
                    </span>
                </div>
                <div class="key-details">
                    <div><strong>ID:</strong> ${key.id}</div>
                    <div><strong>Created:</strong> ${new Date(key.created_at).toLocaleDateString()}</div>
                    <div><strong>Last Used:</strong> ${key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}</div>
                    ${key.rate_limit_override ? `<div><strong>Rate Limit:</strong> ${key.rate_limit_override}/min</div>` : ''}
                    ${key.expires_at ? `<div><strong>Expires:</strong> ${new Date(key.expires_at).toLocaleDateString()}</div>` : ''}
                </div>
                <div class="key-actions">
                    <button class="btn btn-info" onclick="apiKeyManager.showKeyUsage('${key.id}')">Usage Stats</button>
                    ${key.is_active ? `<button class="btn btn-danger" onclick="apiKeyManager.revokeKey('${key.id}')">Revoke</button>` : ''}
                </div>
            </div>
        `).join('');
    }

    async handleCreateKey(event) {
        event.preventDefault();
        
        try {
            const form = event.target;
            const formData = new FormData(form);
            
            const keyData = {
                name: this.container.querySelector('#keyName').value.trim() || null,
                rate_limit_override: parseInt(this.container.querySelector('#rateLimitOverride').value) || null,
                expires_days: parseInt(this.container.querySelector('#expiresDays').value) || null
            };

            // Remove null values
            Object.keys(keyData).forEach(key => {
                if (keyData[key] === null || keyData[key] === '') {
                    delete keyData[key];
                }
            });

            form.classList.add('loading');
            
            const result = await authApi.createApiKey(keyData);
            
            // Show the new API key
            this.showNewApiKey(result.api_key);
            
            // Clear form and reload keys list
            form.reset();
            this.loadApiKeys();
            
        } catch (error) {
            console.error('Failed to create API key:', error);
            this.showError('Failed to create API key. Please check your input and try again.');
        } finally {
            event.target.classList.remove('loading');
        }
    }

    showNewApiKey(apiKey) {
        const modal = this.container.querySelector('.new-key-modal');
        const input = modal.querySelector('.api-key-value');
        input.value = apiKey;
        modal.style.display = 'flex';
    }

    hideNewKeyModal() {
        const modal = this.container.querySelector('.new-key-modal');
        modal.style.display = 'none';
        // Clear the key value for security
        const input = modal.querySelector('.api-key-value');
        input.value = '';
    }

    copyApiKey() {
        const input = this.container.querySelector('.api-key-value');
        input.select();
        document.execCommand('copy');
        
        const btn = this.container.querySelector('.btn-copy');
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    }

    async revokeKey(keyId) {
        if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) {
            return;
        }

        try {
            await authApi.revokeApiKey(keyId);
            this.showSuccess('API key revoked successfully.');
            this.loadApiKeys();
        } catch (error) {
            console.error('Failed to revoke API key:', error);
            this.showError('Failed to revoke API key. Please try again.');
        }
    }

    async showKeyUsage(keyId) {
        try {
            const usage = await authApi.getApiKeyUsage(keyId);
            this.displayUsageStats(usage, `API Key ${keyId.substring(0, 8)} Usage`);
        } catch (error) {
            console.error('Failed to load usage stats:', error);
            this.showError('Failed to load usage statistics. Please try again.');
        }
    }

    async showUsageStats() {
        try {
            const usage = await authApi.getOverallUsage();
            this.displayUsageStats(usage, 'Overall API Usage Statistics');
        } catch (error) {
            console.error('Failed to load usage stats:', error);
            this.showError('Failed to load usage statistics. Please try again.');
        }
    }

    displayUsageStats(usage, title) {
        const section = this.container.querySelector('.usage-stats-section');
        const content = section.querySelector('.usage-stats-content');
        
        content.innerHTML = `
            <h4>${title} (Last ${usage.period_days} days)</h4>
            <div class="stats-summary">
                <p><strong>Total Requests:</strong> ${usage.total_requests}</p>
                <p><strong>Unique Endpoints:</strong> ${usage.unique_endpoints}</p>
                <p><strong>Average Response Time:</strong> ${usage.avg_response_time_ms}ms</p>
            </div>
            
            <h5>Status Codes</h5>
            <table class="usage-stats-table">
                <thead>
                    <tr><th>Status Code</th><th>Count</th></tr>
                </thead>
                <tbody>
                    ${Object.entries(usage.status_codes).map(([code, count]) => 
                        `<tr><td>${code}</td><td>${count}</td></tr>`
                    ).join('')}
                </tbody>
            </table>
            
            <h5>Top Endpoints</h5>
            <table class="usage-stats-table">
                <thead>
                    <tr><th>Endpoint</th><th>Requests</th></tr>
                </thead>
                <tbody>
                    ${Object.entries(usage.endpoints)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 10)
                        .map(([endpoint, count]) => 
                            `<tr><td>${endpoint}</td><td>${count}</td></tr>`
                        ).join('')}
                </tbody>
            </table>
        `;
        
        section.style.display = 'block';
    }

    showError(message) {
        this.showMessage(message, 'error');
    }

    showSuccess(message) {
        this.showMessage(message, 'success');
    }

    showMessage(message, type) {
        // Remove existing messages
        const existing = this.container.querySelectorAll('.error-message, .success-message');
        existing.forEach(el => el.remove());

        const messageEl = document.createElement('div');
        messageEl.className = `${type}-message`;
        messageEl.textContent = message;
        
        const modalBody = this.container.querySelector('.modal-body');
        modalBody.insertBefore(messageEl, modalBody.firstChild);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            messageEl.remove();
        }, 5000);
    }

    destroy() {
        // Clean up event listeners
        this.eventHandlers.forEach(({ element, event, handler }) => {
            element?.removeEventListener(event, handler);
        });
        this.eventHandlers.clear();

        // Remove container
        if (this.container) {
            this.container.remove();
            this.container = null;
        }
    }
}

// Global instance
export const apiKeyManager = new ApiKeyManager();