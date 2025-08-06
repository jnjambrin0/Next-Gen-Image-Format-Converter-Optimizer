package imageconverter

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const (
	serviceName = "image-converter-local"
	keyPrefix   = "IC_API_"
)

// SecureKeyManager handles secure API key storage
type SecureKeyManager struct {
	appName      string
	fallbackPath string
}

// NewSecureKeyManager creates a new secure key manager
func NewSecureKeyManager(appName string) *SecureKeyManager {
	homeDir, _ := os.UserHomeDir()
	fallbackPath := filepath.Join(homeDir, ".image-converter", ".keys")
	
	return &SecureKeyManager{
		appName:      appName,
		fallbackPath: fallbackPath,
	}
}

// Store stores an API key securely
func (m *SecureKeyManager) Store(keyName, apiKey string) error {
	// Try OS keychain first
	err := keyring.Set(serviceName, keyPrefix+keyName, apiKey)
	if err == nil {
		return nil
	}
	
	// Fall back to encrypted local storage
	return m.storeFallback(keyName, apiKey)
}

// Retrieve retrieves an API key from secure storage
func (m *SecureKeyManager) Retrieve(keyName string) (string, error) {
	// Try OS keychain first
	key, err := keyring.Get(serviceName, keyPrefix+keyName)
	if err == nil {
		return key, nil
	}
	
	// Try fallback storage
	return m.retrieveFallback(keyName)
}

// Delete deletes an API key from storage
func (m *SecureKeyManager) Delete(keyName string) error {
	// Try to delete from keychain
	_ = keyring.Delete(serviceName, keyPrefix+keyName)
	
	// Also try to delete from fallback
	return m.deleteFallback(keyName)
}

// ListKeys lists all stored key names (not the actual keys)
func (m *SecureKeyManager) ListKeys() ([]string, error) {
	keys := make(map[string]bool)
	
	// Get from fallback storage
	data, err := m.loadFallbackData()
	if err == nil {
		for k := range data {
			keys[k] = true
		}
	}
	
	// Convert to slice
	result := make([]string, 0, len(keys))
	for k := range keys {
		result = append(result, k)
	}
	
	return result, nil
}

// GenerateAPIKey generates a secure API key
func GenerateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	key := base64.URLEncoding.EncodeToString(b)
	return fmt.Sprintf("ic_live_%s", key)
}

// GetFromEnv gets API key from environment variable
func GetFromEnv(envVar string) string {
	if envVar == "" {
		envVar = "IMAGE_CONVERTER_API_KEY"
	}
	return os.Getenv(envVar)
}

// Fallback storage methods

func (m *SecureKeyManager) ensureFallbackDir() error {
	dir := filepath.Dir(m.fallbackPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	
	// Check if keys file exists
	if _, err := os.Stat(m.fallbackPath); os.IsNotExist(err) {
		// Create empty file with secure permissions
		return os.WriteFile(m.fallbackPath, []byte("{}"), 0600)
	}
	
	return nil
}

func (m *SecureKeyManager) loadFallbackData() (map[string]string, error) {
	data := make(map[string]string)
	
	content, err := os.ReadFile(m.fallbackPath)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return nil, err
	}
	
	err = json.Unmarshal(content, &data)
	return data, err
}

func (m *SecureKeyManager) saveFallbackData(data map[string]string) error {
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(m.fallbackPath, content, 0600)
}

func (m *SecureKeyManager) storeFallback(keyName, apiKey string) error {
	if err := m.ensureFallbackDir(); err != nil {
		return err
	}
	
	data, err := m.loadFallbackData()
	if err != nil {
		return err
	}
	
	data[keyName] = m.obfuscate(apiKey)
	
	return m.saveFallbackData(data)
}

func (m *SecureKeyManager) retrieveFallback(keyName string) (string, error) {
	data, err := m.loadFallbackData()
	if err != nil {
		return "", err
	}
	
	obfuscated, exists := data[keyName]
	if !exists {
		return "", fmt.Errorf("key not found")
	}
	
	return m.deobfuscate(obfuscated), nil
}

func (m *SecureKeyManager) deleteFallback(keyName string) error {
	data, err := m.loadFallbackData()
	if err != nil {
		return err
	}
	
	delete(data, keyName)
	
	return m.saveFallbackData(data)
}

func (m *SecureKeyManager) obfuscate(value string) string {
	key := sha256.Sum256([]byte(m.appName))
	valueBytes := []byte(value)
	obfuscated := make([]byte, len(valueBytes))
	
	for i := range valueBytes {
		obfuscated[i] = valueBytes[i] ^ key[i%len(key)]
	}
	
	return hex.EncodeToString(obfuscated)
}

func (m *SecureKeyManager) deobfuscate(obfuscated string) string {
	key := sha256.Sum256([]byte(m.appName))
	obfuscatedBytes, _ := hex.DecodeString(obfuscated)
	original := make([]byte, len(obfuscatedBytes))
	
	for i := range obfuscatedBytes {
		original[i] = obfuscatedBytes[i] ^ key[i%len(key)]
	}
	
	return string(original)
}