package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	ic "github.com/image-converter/image-converter-sdk-go"
)

// Microservice that wraps the Image Converter API
// Demonstrates integration patterns for service-oriented architecture

type Server struct {
	client       *ic.Client
	mu           sync.RWMutex
	stats        Stats
	rateLimiter  *RateLimiter
}

type Stats struct {
	TotalRequests   int64
	TotalSuccess    int64
	TotalErrors     int64
	TotalBytes      int64
	AverageTime     time.Duration
	LastConversion  time.Time
}

type ConversionRequest struct {
	OutputFormat string `json:"output_format"`
	Quality      int    `json:"quality,omitempty"`
	StripMetadata bool  `json:"strip_metadata,omitempty"`
}

type ConversionResponse struct {
	Success         bool    `json:"success"`
	ConversionID    string  `json:"conversion_id,omitempty"`
	ProcessingTime  float64 `json:"processing_time,omitempty"`
	CompressionRatio float64 `json:"compression_ratio,omitempty"`
	InputSize       int     `json:"input_size,omitempty"`
	OutputSize      int     `json:"output_size,omitempty"`
	Error           string  `json:"error,omitempty"`
}

type HealthResponse struct {
	Status       string    `json:"status"`
	Uptime       string    `json:"uptime"`
	APIConnected bool      `json:"api_connected"`
	Stats        Stats     `json:"stats"`
}

var startTime = time.Now()

func main() {
	// Initialize Image Converter client
	client, err := ic.NewClient(&ic.ClientOptions{
		Host:    "localhost",
		Port:    8000,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to create Image Converter client: %v", err)
	}

	// Create server
	server := &Server{
		client:      client,
		rateLimiter: NewRateLimiter(10, time.Minute), // 10 requests per minute
	}

	// Set up routes
	mux := http.NewServeMux()
	
	// Health check endpoint
	mux.HandleFunc("/health", server.handleHealth)
	
	// Conversion endpoint
	mux.HandleFunc("/convert", server.handleConvert)
	
	// Batch conversion endpoint
	mux.HandleFunc("/batch", server.handleBatch)
	
	// Analysis endpoint
	mux.HandleFunc("/analyze", server.handleAnalyze)
	
	// Stats endpoint
	mux.HandleFunc("/stats", server.handleStats)
	
	// Middleware chain
	handler := loggingMiddleware(corsMiddleware(mux))

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("🚀 Microservice starting on port %s", port)
	log.Printf("🔒 Connected to Image Converter API on localhost:8000")
	log.Printf("📊 Endpoints available:")
	log.Printf("   GET  /health  - Health check")
	log.Printf("   POST /convert - Convert single image")
	log.Printf("   POST /batch   - Batch conversion")
	log.Printf("   POST /analyze - Analyze image content")
	log.Printf("   GET  /stats   - Service statistics")
	
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check API connection
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	apiConnected := false
	if _, err := s.client.HealthCheck(ctx); err == nil {
		apiConnected = true
	}

	s.mu.RLock()
	stats := s.stats
	s.mu.RUnlock()

	response := HealthResponse{
		Status:       "healthy",
		Uptime:       time.Since(startTime).String(),
		APIConnected: apiConnected,
		Stats:        stats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting
	if !s.rateLimiter.Allow(getClientIP(r)) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		s.incrementError()
		return
	}

	s.incrementRequest()
	startTime := time.Now()

	// Parse multipart form
	err := r.ParseMultipartForm(10 << 20) // 10 MB max
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		s.incrementError()
		return
	}

	// Get file
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File required", http.StatusBadRequest)
		s.incrementError()
		return
	}
	defer file.Close()

	// Read file data
	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		s.incrementError()
		return
	}

	// Parse conversion options
	var req ConversionRequest
	req.OutputFormat = r.FormValue("output_format")
	if req.OutputFormat == "" {
		req.OutputFormat = "webp"
	}

	quality := r.FormValue("quality")
	if quality != "" {
		fmt.Sscanf(quality, "%d", &req.Quality)
	} else {
		req.Quality = 85
	}

	req.StripMetadata = r.FormValue("strip_metadata") != "false"

	// Save temp file (SDK requires file path)
	tempFile, err := os.CreateTemp("", "upload-*.tmp")
	if err != nil {
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		s.incrementError()
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if _, err := tempFile.Write(fileData); err != nil {
		http.Error(w, "Failed to write temp file", http.StatusInternalServerError)
		s.incrementError()
		return
	}

	// Convert image using SDK
	ctx := r.Context()
	convertedData, metadata, err := s.client.ConvertImage(
		ctx,
		tempFile.Name(),
		req.OutputFormat,
		&ic.ConversionOptions{
			Quality:       req.Quality,
			StripMetadata: req.StripMetadata,
		},
	)

	if err != nil {
		response := ConversionResponse{
			Success: false,
			Error:   "Conversion failed",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		s.incrementError()
		return
	}

	// Update stats
	duration := time.Since(startTime)
	s.updateStats(true, int64(len(fileData)), duration)

	// Return converted image
	w.Header().Set("Content-Type", getMimeType(req.OutputFormat))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"converted.%s\"", req.OutputFormat))
	w.Header().Set("X-Conversion-Id", metadata.ConversionID)
	w.Header().Set("X-Processing-Time", fmt.Sprintf("%.3f", metadata.ProcessingTime))
	w.Header().Set("X-Compression-Ratio", fmt.Sprintf("%.2f", metadata.CompressionRatio))
	w.Header().Set("X-Original-Name", header.Filename)
	
	w.Write(convertedData)
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Implementation would handle multiple files
	// For brevity, returning a simple response
	response := map[string]interface{}{
		"message": "Batch endpoint - implementation pending",
		"info":    "Use the Image Converter batch API directly for now",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.incrementRequest()

	// Parse multipart form
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		s.incrementError()
		return
	}

	// Get file
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File required", http.StatusBadRequest)
		s.incrementError()
		return
	}
	defer file.Close()

	// Read file data
	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		s.incrementError()
		return
	}

	// Save temp file
	tempFile, err := os.CreateTemp("", "analyze-*.tmp")
	if err != nil {
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		s.incrementError()
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if _, err := tempFile.Write(fileData); err != nil {
		http.Error(w, "Failed to write temp file", http.StatusInternalServerError)
		s.incrementError()
		return
	}

	// Analyze image
	ctx := r.Context()
	classification, err := s.client.AnalyzeImage(ctx, tempFile.Name(), false)
	if err != nil {
		http.Error(w, "Analysis failed", http.StatusInternalServerError)
		s.incrementError()
		return
	}

	s.updateStats(true, 0, 0)

	// Return analysis results
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(classification)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	stats := s.stats
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// Helper functions
func (s *Server) incrementRequest() {
	s.mu.Lock()
	s.stats.TotalRequests++
	s.mu.Unlock()
}

func (s *Server) incrementError() {
	s.mu.Lock()
	s.stats.TotalErrors++
	s.mu.Unlock()
}

func (s *Server) updateStats(success bool, bytes int64, duration time.Duration) {
	s.mu.Lock()
	if success {
		s.stats.TotalSuccess++
		s.stats.TotalBytes += bytes
		s.stats.LastConversion = time.Now()
		
		// Update average time
		if s.stats.AverageTime == 0 {
			s.stats.AverageTime = duration
		} else {
			// Simple moving average
			s.stats.AverageTime = (s.stats.AverageTime + duration) / 2
		}
	} else {
		s.stats.TotalErrors++
	}
	s.mu.Unlock()
}

func getMimeType(format string) string {
	mimeTypes := map[string]string{
		"webp": "image/webp",
		"avif": "image/avif",
		"jpeg": "image/jpeg",
		"jpg":  "image/jpeg",
		"png":  "image/png",
		"heif": "image/heif",
		"jxl":  "image/jxl",
	}
	
	if mime, ok := mimeTypes[format]; ok {
		return mime
	}
	return "application/octet-stream"
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// Middleware functions
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		log.Printf("%s %s %d %s",
			r.Method,
			r.URL.Path,
			wrapped.statusCode,
			time.Since(start),
		)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers for local development
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Simple rate limiter
type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.Mutex
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	windowStart := now.Add(-rl.window)
	
	// Get or create request list for IP
	requests, exists := rl.requests[ip]
	if !exists {
		rl.requests[ip] = []time.Time{now}
		return true
	}
	
	// Remove old requests outside window
	var validRequests []time.Time
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}
	
	// Check if under limit
	if len(validRequests) < rl.limit {
		validRequests = append(validRequests, now)
		rl.requests[ip] = validRequests
		return true
	}
	
	rl.requests[ip] = validRequests
	return false
}