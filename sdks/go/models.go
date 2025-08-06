package imageconverter

import "time"

// OutputFormat represents supported output formats
type OutputFormat string

const (
	FormatWebP  OutputFormat = "webp"
	FormatAVIF  OutputFormat = "avif"
	FormatJPEG  OutputFormat = "jpeg"
	FormatPNG   OutputFormat = "png"
	FormatHEIF  OutputFormat = "heif"
	FormatJXL   OutputFormat = "jxl"
	FormatWebP2 OutputFormat = "webp2"
)

// ContentType represents content classification types
type ContentType string

const (
	ContentPhoto        ContentType = "photo"
	ContentIllustration ContentType = "illustration"
	ContentScreenshot   ContentType = "screenshot"
	ContentDocument     ContentType = "document"
	ContentUnknown      ContentType = "unknown"
)

// UseCaseType represents use case types for optimization
type UseCaseType string

const (
	UseCaseWeb     UseCaseType = "web"
	UseCasePrint   UseCaseType = "print"
	UseCaseArchive UseCaseType = "archive"
)

// ConversionOptions contains options for image conversion
type ConversionOptions struct {
	Quality       int    `json:"quality,omitempty"`
	StripMetadata bool   `json:"strip_metadata,omitempty"`
	PresetID      string `json:"preset_id,omitempty"`
}

// ConversionResponse contains metadata about a conversion
type ConversionResponse struct {
	ConversionID     string  `json:"conversion_id"`
	ProcessingTime   float64 `json:"processing_time"`
	CompressionRatio float64 `json:"compression_ratio"`
	InputFormat      string  `json:"input_format"`
	OutputFormat     string  `json:"output_format"`
	InputSize        int     `json:"input_size"`
	OutputSize       int     `json:"output_size"`
	QualityUsed      int     `json:"quality_used"`
	MetadataRemoved  bool    `json:"metadata_removed"`
}

// BatchOptions contains options for batch conversion
type BatchOptions struct {
	Quality       int    `json:"quality,omitempty"`
	StripMetadata bool   `json:"strip_metadata,omitempty"`
	MaxConcurrent int    `json:"max_concurrent,omitempty"`
	PresetID      string `json:"preset_id,omitempty"`
}

// BatchStatus represents the status of a batch job
type BatchStatus struct {
	JobID               string                   `json:"job_id"`
	Status              string                   `json:"status"`
	TotalFiles          int                      `json:"total_files"`
	CompletedFiles      int                      `json:"completed_files"`
	FailedFiles         int                      `json:"failed_files"`
	ProgressPercentage  float64                  `json:"progress_percentage"`
	CreatedAt           time.Time                `json:"created_at"`
	UpdatedAt           time.Time                `json:"updated_at"`
	EstimatedCompletion *time.Time               `json:"estimated_completion,omitempty"`
	Errors              []map[string]interface{} `json:"errors"`
}

// FormatInfo contains information about a supported format
type FormatInfo struct {
	Format               string   `json:"format"`
	MimeType             string   `json:"mime_type"`
	Extensions           []string `json:"extensions"`
	SupportsTransparency bool     `json:"supports_transparency"`
	SupportsAnimation    bool     `json:"supports_animation"`
	Lossy                bool     `json:"lossy"`
	MaxDimensions        *struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	} `json:"max_dimensions,omitempty"`
	RecommendedUseCases []string `json:"recommended_use_cases"`
}

// ContentClassification represents content analysis results
type ContentClassification struct {
	ContentType      ContentType            `json:"content_type"`
	Confidence       float64                `json:"confidence"`
	ProcessingTimeMs float64                `json:"processing_time_ms"`
	FaceRegions      []BoundingBox          `json:"face_regions"`
	TextRegions      []BoundingBox          `json:"text_regions"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// BoundingBox represents a region in an image
type BoundingBox struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

// FormatRecommendation contains format recommendations
type FormatRecommendation struct {
	RecommendedFormats []struct {
		Format  string   `json:"format"`
		Score   float64  `json:"score"`
		Reasons []string `json:"reasons"`
	} `json:"recommended_formats"`
	Reasoning         map[string]string   `json:"reasoning"`
	TradeOffs         map[string][]string `json:"trade_offs"`
	SizePredictions   map[string]float64  `json:"size_predictions"`
	QualityPredictions map[string]float64  `json:"quality_predictions"`
}