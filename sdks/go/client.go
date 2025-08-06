// Package imageconverter provides a Go SDK for the Image Converter API
// with localhost-only enforcement for security.
package imageconverter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
	defaultHost    = "localhost"
	defaultPort    = 8080
	defaultVersion = "v1"
)

var allowedHosts = []string{"localhost", "127.0.0.1", "::1", "[::1]"}

// Client is the main client for interacting with the Image Converter API
type Client struct {
	baseURL         string
	apiKey          string
	httpClient      *http.Client
	verifyLocalhost bool
	keyManager      *SecureKeyManager
}

// ClientOptions contains options for creating a new client
type ClientOptions struct {
	Host            string
	Port            int
	APIKey          string
	APIVersion      string
	Timeout         time.Duration
	VerifyLocalhost bool
}

// NewClient creates a new Image Converter client with security checks
func NewClient(opts *ClientOptions) (*Client, error) {
	if opts == nil {
		opts = &ClientOptions{}
	}

	// Set defaults
	if opts.Host == "" {
		opts.Host = defaultHost
	}
	if opts.Port == 0 {
		opts.Port = defaultPort
	}
	if opts.APIVersion == "" {
		opts.APIVersion = defaultVersion
	}
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.VerifyLocalhost == false {
		opts.VerifyLocalhost = true
	}

	// Security check: Enforce localhost only
	if opts.VerifyLocalhost && !isLocalhost(opts.Host) {
		return nil, &NetworkSecurityError{
			Message: "connection to non-localhost host blocked for security",
		}
	}

	baseURL := fmt.Sprintf("http://%s:%d/api", opts.Host, opts.Port)
	if opts.APIVersion != "" {
		baseURL = fmt.Sprintf("%s/%s", baseURL, opts.APIVersion)
	}

	client := &Client{
		baseURL: baseURL,
		apiKey:  opts.APIKey,
		httpClient: &http.Client{
			Timeout: opts.Timeout,
		},
		verifyLocalhost: opts.VerifyLocalhost,
		keyManager:      NewSecureKeyManager("image-converter"),
	}

	// Try to get API key from environment or secure storage if not provided
	if client.apiKey == "" {
		if envKey := os.Getenv("IMAGE_CONVERTER_API_KEY"); envKey != "" {
			client.apiKey = envKey
		} else if storedKey, err := client.keyManager.Retrieve("default"); err == nil {
			client.apiKey = storedKey
		}
	}

	return client, nil
}

// ConvertImage converts a single image to the specified format
func (c *Client) ConvertImage(ctx context.Context, imagePath string, outputFormat string, opts *ConversionOptions) ([]byte, *ConversionResponse, error) {
	// Read file
	imageData, err := os.ReadFile(imagePath)
	if err != nil {
		return nil, nil, &FileError{Message: "failed to read input file"}
	}

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file
	part, err := writer.CreateFormFile("file", filepath.Base(imagePath))
	if err != nil {
		return nil, nil, err
	}
	if _, err := part.Write(imageData); err != nil {
		return nil, nil, err
	}

	// Add form fields
	writer.WriteField("output_format", outputFormat)
	
	if opts != nil {
		if opts.Quality > 0 {
			writer.WriteField("quality", strconv.Itoa(opts.Quality))
		}
		if opts.StripMetadata {
			writer.WriteField("strip_metadata", "true")
		}
		if opts.PresetID != "" {
			writer.WriteField("preset_id", opts.PresetID)
		}
	}

	writer.Close()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/convert", &buf)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, &ServiceUnavailableError{Message: "local service is not running"}
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		return nil, nil, c.handleErrorResponse(resp)
	}

	// Read response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	// Extract metadata from headers
	metadata := &ConversionResponse{
		ConversionID:     resp.Header.Get("X-Conversion-Id"),
		ProcessingTime:   parseFloat(resp.Header.Get("X-Processing-Time")),
		CompressionRatio: parseFloat(resp.Header.Get("X-Compression-Ratio")),
		InputFormat:      resp.Header.Get("X-Input-Format"),
		OutputFormat:     resp.Header.Get("X-Output-Format"),
		InputSize:        parseInt(resp.Header.Get("X-Input-Size")),
		OutputSize:       parseInt(resp.Header.Get("X-Output-Size")),
		QualityUsed:      parseInt(resp.Header.Get("X-Quality-Used")),
		MetadataRemoved:  resp.Header.Get("X-Metadata-Removed") == "true",
	}

	return data, metadata, nil
}

// CreateBatch creates a batch conversion job
func (c *Client) CreateBatch(ctx context.Context, imagePaths []string, outputFormat string, opts *BatchOptions) (*BatchStatus, error) {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add files
	for _, imagePath := range imagePaths {
		imageData, err := os.ReadFile(imagePath)
		if err != nil {
			return nil, &FileError{Message: "failed to read input file"}
		}

		part, err := writer.CreateFormFile("files", filepath.Base(imagePath))
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(imageData); err != nil {
			return nil, err
		}
	}

	// Add form fields
	writer.WriteField("output_format", outputFormat)
	
	if opts != nil {
		if opts.Quality > 0 {
			writer.WriteField("quality", strconv.Itoa(opts.Quality))
		}
		if opts.StripMetadata {
			writer.WriteField("strip_metadata", "true")
		}
		if opts.MaxConcurrent > 0 {
			writer.WriteField("max_concurrent", strconv.Itoa(opts.MaxConcurrent))
		}
		if opts.PresetID != "" {
			writer.WriteField("preset_id", opts.PresetID)
		}
	}

	writer.Close()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/batch", &buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ServiceUnavailableError{Message: "local service is not running"}
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	// Parse response
	var batchStatus BatchStatus
	if err := json.NewDecoder(resp.Body).Decode(&batchStatus); err != nil {
		return nil, err
	}

	return &batchStatus, nil
}

// GetBatchStatus retrieves the status of a batch job
func (c *Client) GetBatchStatus(ctx context.Context, jobID string) (*BatchStatus, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/batch/"+jobID+"/status", nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ServiceUnavailableError{Message: "local service is not running"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var batchStatus BatchStatus
	if err := json.NewDecoder(resp.Body).Decode(&batchStatus); err != nil {
		return nil, err
	}

	return &batchStatus, nil
}

// AnalyzeImage analyzes image content using ML models
func (c *Client) AnalyzeImage(ctx context.Context, imagePath string, debug bool) (*ContentClassification, error) {
	imageData, err := os.ReadFile(imagePath)
	if err != nil {
		return nil, &FileError{Message: "failed to read input file"}
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", filepath.Base(imagePath))
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(imageData); err != nil {
		return nil, err
	}

	writer.Close()

	endpoint := "/intelligence/analyze"
	if debug {
		endpoint += "?debug=true"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+endpoint, &buf)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ServiceUnavailableError{Message: "local service is not running"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var classification ContentClassification
	if err := json.NewDecoder(resp.Body).Decode(&classification); err != nil {
		return nil, err
	}

	return &classification, nil
}

// GetSupportedFormats returns a list of supported formats
func (c *Client) GetSupportedFormats(ctx context.Context) ([]FormatInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/formats", nil)
	if err != nil {
		return nil, err
	}

	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ServiceUnavailableError{Message: "local service is not running"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var result struct {
		Formats []FormatInfo `json:"formats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Formats, nil
}

// HealthCheck checks the API health status
func (c *Client) HealthCheck(ctx context.Context) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ServiceUnavailableError{Message: "local service is not running"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// StoreAPIKey stores an API key securely
func (c *Client) StoreAPIKey(keyName, apiKey string) error {
	return c.keyManager.Store(keyName, apiKey)
}

// RetrieveAPIKey retrieves a stored API key
func (c *Client) RetrieveAPIKey(keyName string) (string, error) {
	return c.keyManager.Retrieve(keyName)
}

// handleErrorResponse processes error responses from the API
func (c *Client) handleErrorResponse(resp *http.Response) error {
	var errorData struct {
		Message   string `json:"message"`
		ErrorCode string `json:"error_code"`
	}

	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &errorData)

	switch resp.StatusCode {
	case http.StatusRequestEntityTooLarge:
		return &ValidationError{Message: "file too large"}
	case http.StatusUnsupportedMediaType:
		return &ValidationError{Message: "unsupported file format"}
	case http.StatusUnprocessableEntity:
		return &ValidationError{Message: errorData.Message}
	case http.StatusTooManyRequests:
		retryAfter, _ := strconv.Atoi(resp.Header.Get("X-RateLimit-Reset"))
		return &RateLimitError{
			Message:    errorData.Message,
			RetryAfter: retryAfter,
		}
	case http.StatusServiceUnavailable:
		return &ServiceUnavailableError{Message: errorData.Message}
	default:
		return &ImageConverterError{
			Message:   errorData.Message,
			ErrorCode: errorData.ErrorCode,
		}
	}
}

// Helper functions
func isLocalhost(host string) bool {
	for _, allowed := range allowedHosts {
		if host == allowed {
			return true
		}
	}
	return false
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}