package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ic "github.com/image-converter/image-converter-sdk-go"
)

// High-performance batch processor for image conversion
// Demonstrates concurrent processing with progress tracking

var (
	inputDir     = flag.String("input", ".", "Input directory containing images")
	outputDir    = flag.String("output", "./converted", "Output directory for converted images")
	format       = flag.String("format", "webp", "Output format (webp, avif, jpeg, png)")
	quality      = flag.Int("quality", 85, "Quality (1-100)")
	workers      = flag.Int("workers", 4, "Number of concurrent workers")
	stripMeta    = flag.Bool("strip-metadata", true, "Remove metadata from images")
	port         = flag.Int("port", 8000, "API server port")
	apiKey       = flag.String("api-key", "", "API key (optional)")
	showProgress = flag.Bool("progress", true, "Show progress bar")
)

type Result struct {
	InputPath  string
	OutputPath string
	Success    bool
	Error      error
	InputSize  int64
	OutputSize int
	Duration   time.Duration
}

func main() {
	flag.Parse()

	// Validate arguments
	if *inputDir == "" {
		log.Fatal("Input directory is required")
	}

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Initialize client (localhost only for security)
	client, err := ic.NewClient(&ic.ClientOptions{
		Host:   "localhost",
		Port:   *port,
		APIKey: *apiKey,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Find all image files
	images, err := findImages(*inputDir)
	if err != nil {
		log.Fatalf("Failed to find images: %v", err)
	}

	if len(images) == 0 {
		fmt.Println("No images found in directory")
		return
	}

	fmt.Printf("🔍 Found %d images to convert to %s\n", len(images), *format)
	fmt.Printf("⚙️  Using %d concurrent workers\n", *workers)
	fmt.Println()

	// Process images concurrently
	results := processImages(client, images)

	// Display summary
	displaySummary(results)
}

func findImages(dir string) ([]string, error) {
	var images []string
	supportedExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".webp": true,
		".heic": true,
		".heif": true,
		".bmp":  true,
		".tiff": true,
		".gif":  true,
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if supportedExts[ext] {
				images = append(images, path)
			}
		}

		return nil
	})

	return images, err
}

func processImages(client *ic.Client, images []string) []Result {
	var (
		wg          sync.WaitGroup
		results     []Result
		resultsMu   sync.Mutex
		processed   int32
		failed      int32
		totalSize   int64
		outputSize  int64
	)

	// Create channels
	jobs := make(chan string, len(images))
	resultsChan := make(chan Result, len(images))

	// Start workers
	ctx := context.Background()
	startTime := time.Now()

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for imagePath := range jobs {
				result := processImage(ctx, client, imagePath, workerID)
				resultsChan <- result

				// Update counters
				if result.Success {
					atomic.AddInt32(&processed, 1)
					atomic.AddInt64(&totalSize, result.InputSize)
					atomic.AddInt64(&outputSize, int64(result.OutputSize))
				} else {
					atomic.AddInt32(&failed, 1)
				}

				// Show progress
				if *showProgress {
					current := atomic.LoadInt32(&processed) + atomic.LoadInt32(&failed)
					showProgressBar(int(current), len(images), startTime)
				}
			}
		}(i)
	}

	// Queue all jobs
	for _, image := range images {
		jobs <- image
	}
	close(jobs)

	// Wait for all workers
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		resultsMu.Lock()
		results = append(results, result)
		resultsMu.Unlock()
	}

	if *showProgress {
		fmt.Println() // New line after progress bar
	}

	return results
}

func processImage(ctx context.Context, client *ic.Client, imagePath string, workerID int) Result {
	result := Result{
		InputPath: imagePath,
	}

	// Get file info
	fileInfo, err := os.Stat(imagePath)
	if err != nil {
		result.Error = err
		return result
	}
	result.InputSize = fileInfo.Size()

	// Generate output path
	baseName := filepath.Base(imagePath)
	nameWithoutExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	outputName := fmt.Sprintf("%s.%s", nameWithoutExt, *format)
	result.OutputPath = filepath.Join(*outputDir, outputName)

	// Convert image
	startTime := time.Now()
	
	data, metadata, err := client.ConvertImage(ctx, imagePath, *format, &ic.ConversionOptions{
		Quality:       *quality,
		StripMetadata: *stripMeta,
	})
	
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Error = err
		return result
	}

	// Save converted image
	err = os.WriteFile(result.OutputPath, data, 0644)
	if err != nil {
		result.Error = err
		return result
	}

	result.Success = true
	result.OutputSize = metadata.OutputSize

	return result
}

func showProgressBar(current, total int, startTime time.Time) {
	percentage := float64(current) / float64(total) * 100
	filled := int(percentage / 2)
	empty := 50 - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	
	elapsed := time.Since(startTime)
	var eta time.Duration
	if current > 0 {
		eta = time.Duration(float64(elapsed) / float64(current) * float64(total-current))
	}

	fmt.Printf("\r[%s] %.0f%% (%d/%d) ETA: %s", 
		bar, percentage, current, total, formatDuration(eta))
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "< 1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}

func displaySummary(results []Result) {
	var (
		successful   int
		failed       int
		totalInput   int64
		totalOutput  int64
		totalTime    time.Duration
		fastestTime  = time.Hour
		slowestTime  time.Duration
		errors       = make(map[string]int)
	)

	for _, r := range results {
		if r.Success {
			successful++
			totalInput += r.InputSize
			totalOutput += int64(r.OutputSize)
			totalTime += r.Duration

			if r.Duration < fastestTime {
				fastestTime = r.Duration
			}
			if r.Duration > slowestTime {
				slowestTime = r.Duration
			}
		} else {
			failed++
			if r.Error != nil {
				errStr := r.Error.Error()
				// Truncate long error messages
				if len(errStr) > 50 {
					errStr = errStr[:50] + "..."
				}
				errors[errStr]++
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📊 BATCH CONVERSION SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	
	fmt.Printf("✅ Successful: %d\n", successful)
	fmt.Printf("❌ Failed: %d\n", failed)
	fmt.Printf("📁 Total: %d\n", len(results))
	
	if successful > 0 {
		avgTime := totalTime / time.Duration(successful)
		compressionRatio := float64(totalOutput) / float64(totalInput) * 100
		
		fmt.Println("\n📈 Performance Metrics:")
		fmt.Printf("   Input size:  %s\n", formatBytes(totalInput))
		fmt.Printf("   Output size: %s\n", formatBytes(totalOutput))
		fmt.Printf("   Compression: %.1f%%\n", compressionRatio)
		fmt.Printf("   Saved:       %s (%.1f%%)\n", 
			formatBytes(totalInput-totalOutput), 
			(1-float64(totalOutput)/float64(totalInput))*100)
		
		fmt.Println("\n⏱️  Timing Statistics:")
		fmt.Printf("   Total time:   %s\n", totalTime)
		fmt.Printf("   Average time: %s per image\n", avgTime)
		fmt.Printf("   Fastest:      %s\n", fastestTime)
		fmt.Printf("   Slowest:      %s\n", slowestTime)
		
		throughput := float64(successful) / totalTime.Seconds()
		fmt.Printf("   Throughput:   %.2f images/second\n", throughput)
	}
	
	if len(errors) > 0 {
		fmt.Println("\n⚠️  Error Summary:")
		for errMsg, count := range errors {
			fmt.Printf("   %s: %d\n", errMsg, count)
		}
	}
	
	fmt.Println(strings.Repeat("=", 60))
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}