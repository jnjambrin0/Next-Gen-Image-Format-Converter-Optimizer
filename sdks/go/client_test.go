package imageconverter

import (
	"context"
	"testing"
	"time"
)

func TestClientCreation(t *testing.T) {
	tests := []struct {
		name        string
		opts        *ClientOptions
		shouldError bool
		errorType   string
	}{
		{
			name: "default localhost",
			opts: nil,
			shouldError: false,
		},
		{
			name: "explicit localhost",
			opts: &ClientOptions{
				Host: "localhost",
				Port: 8000,
			},
			shouldError: false,
		},
		{
			name: "127.0.0.1 allowed",
			opts: &ClientOptions{
				Host: "127.0.0.1",
			},
			shouldError: false,
		},
		{
			name: "::1 allowed",
			opts: &ClientOptions{
				Host: "::1",
			},
			shouldError: false,
		},
		{
			name: "external host blocked",
			opts: &ClientOptions{
				Host: "example.com",
			},
			shouldError: true,
			errorType: "NetworkSecurityError",
		},
		{
			name: "private IP blocked",
			opts: &ClientOptions{
				Host: "192.168.1.100",
			},
			shouldError: true,
			errorType: "NetworkSecurityError",
		},
		{
			name: "external allowed with verification disabled",
			opts: &ClientOptions{
				Host:            "example.com",
				VerifyLocalhost: false,
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.opts)
			
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorType != "" {
					switch tt.errorType {
					case "NetworkSecurityError":
						if _, ok := err.(*NetworkSecurityError); !ok {
							t.Errorf("Expected NetworkSecurityError, got %T", err)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if client == nil {
					t.Error("Expected client to be created")
				}
			}
		})
	}
}

func TestLocalhostValidation(t *testing.T) {
	tests := []struct {
		host     string
		expected bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"[::1]", true},
		{"example.com", false},
		{"google.com", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := isLocalhost(tt.host)
			if result != tt.expected {
				t.Errorf("isLocalhost(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestClientConfiguration(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		client, err := NewClient(nil)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		expectedURL := "http://localhost:8000/api/v1"
		if client.baseURL != expectedURL {
			t.Errorf("Expected baseURL %q, got %q", expectedURL, client.baseURL)
		}

		if client.httpClient.Timeout != defaultTimeout {
			t.Errorf("Expected timeout %v, got %v", defaultTimeout, client.httpClient.Timeout)
		}
	})

	t.Run("custom configuration", func(t *testing.T) {
		opts := &ClientOptions{
			Host:       "127.0.0.1",
			Port:       9090,
			APIVersion: "v2",
			Timeout:    10 * time.Second,
		}

		client, err := NewClient(opts)
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		expectedURL := "http://127.0.0.1:9090/api/v2"
		if client.baseURL != expectedURL {
			t.Errorf("Expected baseURL %q, got %q", expectedURL, client.baseURL)
		}

		if client.httpClient.Timeout != opts.Timeout {
			t.Errorf("Expected timeout %v, got %v", opts.Timeout, client.httpClient.Timeout)
		}
	})
}

func TestHelperFunctions(t *testing.T) {
	t.Run("parseFloat", func(t *testing.T) {
		tests := []struct {
			input    string
			expected float64
		}{
			{"3.14", 3.14},
			{"0", 0},
			{"-1.5", -1.5},
			{"invalid", 0},
			{"", 0},
		}

		for _, tt := range tests {
			result := parseFloat(tt.input)
			if result != tt.expected {
				t.Errorf("parseFloat(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("parseInt", func(t *testing.T) {
		tests := []struct {
			input    string
			expected int
		}{
			{"42", 42},
			{"0", 0},
			{"-10", -10},
			{"invalid", 0},
			{"", 0},
		}

		for _, tt := range tests {
			result := parseInt(tt.input)
			if result != tt.expected {
				t.Errorf("parseInt(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		}
	})
}

// Integration tests (requires running API server)
func TestAPIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, err := NewClient(nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	t.Run("health check", func(t *testing.T) {
		health, err := client.HealthCheck(ctx)
		if err != nil {
			t.Skipf("API server not running: %v", err)
		}

		if health == nil {
			t.Error("Expected health response, got nil")
		}

		if status, ok := health["status"]; ok {
			if status != "healthy" {
				t.Errorf("Expected status 'healthy', got %v", status)
			}
		}
	})

	t.Run("supported formats", func(t *testing.T) {
		formats, err := client.GetSupportedFormats(ctx)
		if err != nil {
			t.Skipf("API server not running: %v", err)
		}

		if len(formats) == 0 {
			t.Error("Expected at least one supported format")
		}

		// Check for common formats
		hasWebP := false
		hasJPEG := false
		for _, f := range formats {
			if f.Format == "webp" {
				hasWebP = true
			}
			if f.Format == "jpeg" {
				hasJPEG = true
			}
		}

		if !hasWebP {
			t.Error("Expected WebP to be supported")
		}
		if !hasJPEG {
			t.Error("Expected JPEG to be supported")
		}
	})
}