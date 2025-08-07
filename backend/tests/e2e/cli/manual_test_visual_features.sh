#!/bin/bash

# Manual test script for CLI visual features
# This script runs various CLI commands to visually verify all features

set -e  # Exit on error

echo "======================================================================"
echo "                 CLI VISUAL FEATURES MANUAL TEST"
echo "======================================================================"
echo ""
echo "This script will run various CLI commands to demonstrate visual features."
echo "Please ensure the backend is running on localhost:8000"
echo ""
echo "Press Enter to continue or Ctrl+C to exit..."
read

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create temp directory for tests
TEST_DIR=$(mktemp -d)
echo -e "${CYAN}Created test directory: $TEST_DIR${NC}"
cd "$TEST_DIR"

# Function to create test images
create_test_images() {
    echo -e "\n${BLUE}Creating test images...${NC}"
    
    # Create small test images using Python
    python3 << EOF
from PIL import Image, ImageDraw, ImageFont
import os

# Create different test images
sizes = [(100, 100), (500, 500)]
colors = ['red', 'green', 'blue', 'yellow']

for i, color in enumerate(colors):
    for j, size in enumerate(sizes):
        img = Image.new('RGB', size, color)
        
        # Add some text to larger images
        if size[0] > 200:
            draw = ImageDraw.Draw(img)
            text = f"{color.upper()}\n{size[0]}x{size[1]}"
            draw.text((10, 10), text, fill='white')
        
        filename = f"test_{color}_{size[0]}.jpg"
        img.save(filename)
        print(f"Created: {filename}")

# Create gradient image
gradient = Image.new('RGB', (400, 300))
for x in range(400):
    for y in range(300):
        r = int(255 * (x / 400))
        g = int(255 * (y / 300))
        b = 128
        gradient.putpixel((x, y), (r, g, b))
gradient.save('gradient.png')
print("Created: gradient.png")

# Create transparent PNG
trans = Image.new('RGBA', (200, 200), (255, 0, 0, 128))
draw = ImageDraw.Draw(trans)
draw.ellipse([50, 50, 150, 150], fill=(0, 255, 0, 200))
trans.save('transparent.png')
print("Created: transparent.png")
EOF
    
    echo -e "${GREEN}Test images created successfully!${NC}"
}

# Function to pause between tests
pause_test() {
    echo -e "\n${YELLOW}Press Enter to continue to next test...${NC}"
    read
}

# Function to run test with header
run_test() {
    local test_name=$1
    local command=$2
    
    echo ""
    echo "======================================================================"
    echo -e "${CYAN}TEST: $test_name${NC}"
    echo "======================================================================"
    echo -e "Command: ${BLUE}$command${NC}"
    echo ""
    
    eval "$command" || true
    
    pause_test
}

# Create test images
create_test_images

# Test 1: Version with color output
run_test "Version Display with Colors" \
    "img --version"

# Test 2: Help with Rich formatting
run_test "Help Display with Rich Formatting" \
    "img --help"

# Test 3: Simple conversion with progress
run_test "Convert with Progress Bar and Themed Output" \
    "img convert file test_red_100.jpg -f webp --quality 85"

# Test 4: Verbose conversion to see more output
run_test "Verbose Conversion with Detailed Progress" \
    "img convert file test_blue_500.jpg -f avif --quality 75 --verbose"

# Test 5: List formats with table
run_test "Format List with Table Display" \
    "img formats list"

# Test 6: Config display
run_test "Configuration Display" \
    "img config show"

# Test 7: Theme listing
run_test "Available Themes" \
    "img config theme"

# Test 8: Set dark theme
run_test "Set Dark Theme" \
    "img config theme dark"

# Test 9: Convert with dark theme
run_test "Conversion with Dark Theme" \
    "img convert file test_green_100.jpg -f webp"

# Test 10: Set light theme
run_test "Set Light Theme" \
    "img config theme light"

# Test 11: Convert with light theme
run_test "Conversion with Light Theme" \
    "img convert file test_yellow_100.jpg -f webp"

# Test 12: Batch conversion
run_test "Batch Conversion with Progress" \
    "img batch create \"test_*_100.jpg\" -f webp --quality 80"

# Test 13: Test with NO_COLOR
run_test "Test NO_COLOR Environment" \
    "NO_COLOR=1 img convert file gradient.png -f jpeg"

# Test 14: Test with forced colors
run_test "Test FORCE_COLOR Environment" \
    "FORCE_COLOR=1 img convert file transparent.png -f webp"

# Test 15: Error handling display
run_test "Error Display Styling (Non-existent File)" \
    "img convert file nonexistent.jpg -f webp"

# Test 16: Large file handling
echo -e "\n${BLUE}Creating larger test file...${NC}"
python3 -c "
from PIL import Image
img = Image.new('RGB', (2000, 2000), 'purple')
img.save('large.jpg')
print('Created large.jpg (2000x2000)')
"

run_test "Large File Conversion with Progress" \
    "img convert file large.jpg -f webp --quality 70 --optimize"

# Test 17: Preview generation (if available)
run_test "ASCII Preview Generation" \
    "img analyze preview gradient.png --mode ascii --width 60 || echo 'Preview command not available'"

# Test 18: TUI launch test (will exit immediately)
echo ""
echo "======================================================================"
echo -e "${CYAN}TEST: Terminal UI Launch${NC}"
echo "======================================================================"
echo "The TUI will launch. Press 'q' to quit immediately."
echo -e "${YELLOW}Press Enter to launch TUI...${NC}"
read

echo "q" | img tui || echo "TUI test completed"

# Test 19: Test different terminal types
echo ""
echo "======================================================================"
echo -e "${CYAN}Terminal Compatibility Tests${NC}"
echo "======================================================================"

echo -e "\n${BLUE}Testing as CI environment:${NC}"
CI=true GITHUB_ACTIONS=true img convert file test_red_100.jpg -f webp

echo -e "\n${BLUE}Testing as dumb terminal:${NC}"
TERM=dumb img convert file test_green_100.jpg -f webp

echo -e "\n${BLUE}Testing as xterm-256color:${NC}"
TERM=xterm-256color COLORTERM=truecolor img convert file test_blue_100.jpg -f webp

# Final summary
echo ""
echo "======================================================================"
echo -e "${GREEN}                    TEST COMPLETE!${NC}"
echo "======================================================================"
echo ""
echo "Visual Features Tested:"
echo "  ✅ Themed console output (Dark/Light themes)"
echo "  ✅ ANSI color codes in output"
echo "  ✅ Progress bars and indicators"
echo "  ✅ Smart table formatting"
echo "  ✅ Rich help and version display"
echo "  ✅ Error message styling"
echo "  ✅ Terminal capability adaptation"
echo "  ✅ Batch processing with visual feedback"
echo "  ✅ Environment variable handling (NO_COLOR, FORCE_COLOR)"
echo "  ✅ TUI launch capability"
echo ""
echo -e "${CYAN}Test files saved in: $TEST_DIR${NC}"
echo ""
echo "To clean up test directory, run:"
echo "  rm -rf $TEST_DIR"
echo ""

# Option to clean up
echo -e "${YELLOW}Do you want to clean up the test directory? (y/n)${NC}"
read -n 1 cleanup
echo ""

if [ "$cleanup" = "y" ] || [ "$cleanup" = "Y" ]; then
    cd ..
    rm -rf "$TEST_DIR"
    echo -e "${GREEN}Test directory cleaned up.${NC}"
else
    echo -e "${CYAN}Test files preserved in: $TEST_DIR${NC}"
fi

echo ""
echo "======================================================================"
echo -e "${GREEN}All visual features have been demonstrated successfully!${NC}"
echo "======================================================================"