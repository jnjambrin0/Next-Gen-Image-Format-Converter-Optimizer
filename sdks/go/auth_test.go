package imageconverter

import (
	"os"
	"strings"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	key := GenerateAPIKey()
	
	// Check prefix
	if !strings.HasPrefix(key, "ic_live_") {
		t.Errorf("API key should start with 'ic_live_', got %s", key)
	}
	
	// Check length
	if len(key) < 40 {
		t.Errorf("API key should be at least 40 characters, got %d", len(key))
	}
	
	// Check uniqueness
	key2 := GenerateAPIKey()
	if key == key2 {
		t.Error("Generated keys should be unique")
	}
}

func TestGetFromEnv(t *testing.T) {
	// Save original env
	originalKey := os.Getenv("IMAGE_CONVERTER_API_KEY")
	defer func() {
		if originalKey != "" {
			os.Setenv("IMAGE_CONVERTER_API_KEY", originalKey)
		} else {
			os.Unsetenv("IMAGE_CONVERTER_API_KEY")
		}
	}()
	
	// Test with env var set
	testKey := "ic_live_test_key_123"
	os.Setenv("IMAGE_CONVERTER_API_KEY", testKey)
	
	key := GetFromEnv("")
	if key != testKey {
		t.Errorf("Expected %s, got %s", testKey, key)
	}
	
	// Test with custom env var
	os.Setenv("CUSTOM_API_KEY", "custom_key")
	customKey := GetFromEnv("CUSTOM_API_KEY")
	if customKey != "custom_key" {
		t.Errorf("Expected 'custom_key', got %s", customKey)
	}
	os.Unsetenv("CUSTOM_API_KEY")
	
	// Test with no env var
	os.Unsetenv("IMAGE_CONVERTER_API_KEY")
	emptyKey := GetFromEnv("")
	if emptyKey != "" {
		t.Errorf("Expected empty string, got %s", emptyKey)
	}
}

func TestSecureKeyManager(t *testing.T) {
	manager := NewSecureKeyManager("test-app")
	
	t.Run("store and retrieve", func(t *testing.T) {
		keyName := "test_key"
		apiKey := "ic_live_test_12345"
		
		// Store key
		err := manager.Store(keyName, apiKey)
		if err != nil {
			// May fail if keyring is not available
			t.Skipf("Keyring not available: %v", err)
		}
		
		// Retrieve key
		retrieved, err := manager.Retrieve(keyName)
		if err != nil {
			t.Errorf("Failed to retrieve key: %v", err)
		}
		if retrieved != apiKey {
			t.Errorf("Expected %s, got %s", apiKey, retrieved)
		}
		
		// Clean up
		manager.Delete(keyName)
	})
	
	t.Run("obfuscation", func(t *testing.T) {
		original := "sensitive_api_key"
		
		obfuscated := manager.obfuscate(original)
		if obfuscated == original {
			t.Error("Obfuscated value should not equal original")
		}
		if len(obfuscated) == 0 {
			t.Error("Obfuscated value should not be empty")
		}
		
		deobfuscated := manager.deobfuscate(obfuscated)
		if deobfuscated != original {
			t.Errorf("Deobfuscated value should equal original, got %s", deobfuscated)
		}
	})
	
	t.Run("list keys", func(t *testing.T) {
		// Store multiple keys
		manager.Store("key1", "value1")
		manager.Store("key2", "value2")
		
		keys, err := manager.ListKeys()
		if err != nil {
			t.Skipf("Failed to list keys: %v", err)
		}
		
		// Check if keys are in list
		hasKey1 := false
		hasKey2 := false
		for _, k := range keys {
			if k == "key1" {
				hasKey1 = true
			}
			if k == "key2" {
				hasKey2 = true
			}
		}
		
		if !hasKey1 || !hasKey2 {
			t.Error("Expected both keys to be in list")
		}
		
		// Clean up
		manager.Delete("key1")
		manager.Delete("key2")
	})
	
	t.Run("delete key", func(t *testing.T) {
		keyName := "temp_key"
		apiKey := "temp_value"
		
		// Store key
		err := manager.Store(keyName, apiKey)
		if err != nil {
			t.Skipf("Keyring not available: %v", err)
		}
		
		// Delete key
		err = manager.Delete(keyName)
		if err != nil {
			t.Errorf("Failed to delete key: %v", err)
		}
		
		// Try to retrieve deleted key
		retrieved, err := manager.Retrieve(keyName)
		if err == nil && retrieved != "" {
			t.Error("Should not retrieve deleted key")
		}
	})
}

func TestFallbackStorage(t *testing.T) {
	manager := NewSecureKeyManager("test-app")
	
	// Force use of fallback storage by testing directly
	keyName := "fallback_test"
	apiKey := "fallback_value"
	
	err := manager.storeFallback(keyName, apiKey)
	if err != nil {
		t.Fatalf("Failed to store in fallback: %v", err)
	}
	
	retrieved, err := manager.retrieveFallback(keyName)
	if err != nil {
		t.Fatalf("Failed to retrieve from fallback: %v", err)
	}
	
	if retrieved != apiKey {
		t.Errorf("Expected %s, got %s", apiKey, retrieved)
	}
	
	// Clean up
	manager.deleteFallback(keyName)
}