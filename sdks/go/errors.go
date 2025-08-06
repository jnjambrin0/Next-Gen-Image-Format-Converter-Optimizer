package imageconverter

import "fmt"

// ImageConverterError is the base error type for all SDK errors
type ImageConverterError struct {
	Message   string
	ErrorCode string
	Details   map[string]interface{}
}

func (e *ImageConverterError) Error() string {
	if e.ErrorCode != "" {
		return fmt.Sprintf("[%s] %s", e.ErrorCode, e.Message)
	}
	return e.Message
}

// NetworkSecurityError is raised when attempting to connect to non-localhost addresses
type NetworkSecurityError struct {
	Message string
}

func (e *NetworkSecurityError) Error() string {
	if e.Message == "" {
		return "network access blocked - only localhost connections allowed"
	}
	return e.Message
}

// RateLimitError is raised when API rate limit is exceeded
type RateLimitError struct {
	Message    string
	RetryAfter int
}

func (e *RateLimitError) Error() string {
	if e.Message == "" {
		return "rate limit exceeded"
	}
	return e.Message
}

// ValidationError is raised when request validation fails
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	if e.Message == "" {
		return "invalid request parameters"
	}
	return e.Message
}

// ServiceUnavailableError is raised when the local service is unavailable
type ServiceUnavailableError struct {
	Message string
}

func (e *ServiceUnavailableError) Error() string {
	if e.Message == "" {
		return "local service temporarily unavailable"
	}
	return e.Message
}

// FileError is raised for file-related errors
type FileError struct {
	Message string
}

func (e *FileError) Error() string {
	if e.Message == "" {
		return "file operation failed"
	}
	// Never include filename in error message for privacy
	return e.Message
}

// SandboxError is raised when sandbox security is violated
type SandboxError struct {
	Message string
}

func (e *SandboxError) Error() string {
	if e.Message == "" {
		return "security sandbox violation"
	}
	return e.Message
}