// Test script to verify batch completion notification fix
// Run this in browser console after loading the app

console.log('=== Batch Completion Notification Test ===');

// Function to monitor WebSocket messages
function monitorWebSocket() {
  console.log('\nMonitoring WebSocket messages...');
  
  // Store original WebSocket constructor
  const OriginalWebSocket = window.WebSocket;
  
  // Override WebSocket to intercept messages
  window.WebSocket = function(url) {
    console.log(`WebSocket connecting to: ${url}`);
    
    const ws = new OriginalWebSocket(url);
    
    // Log all messages
    ws.addEventListener('message', function(event) {
      try {
        const data = JSON.parse(event.data);
        console.log('WebSocket message received:', data);
        
        if (data.type === 'job_status' && (data.status === 'completed' || data.status === 'failed')) {
          console.log('🎉 Job completion notification received!', data);
        }
      } catch (e) {
        console.log('WebSocket raw message:', event.data);
      }
    });
    
    return ws;
  };
}

// Function to test batch processing
async function testBatchProcessing() {
  console.log('\nStarting batch processing test...');
  
  // Create test files
  const files = [];
  for (let i = 0; i < 2; i++) {
    const canvas = document.createElement('canvas');
    canvas.width = 100;
    canvas.height = 100;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = i === 0 ? 'red' : 'blue';
    ctx.fillRect(0, 0, 100, 100);
    
    await new Promise(resolve => {
      canvas.toBlob(blob => {
        const file = new File([blob], `test${i + 1}.png`, { type: 'image/png' });
        files.push(file);
        resolve();
      }, 'image/png');
    });
  }
  
  console.log(`Created ${files.length} test files`);
  
  // Trigger multiple file selection
  const dropzone = document.querySelector('.dropzone');
  if (dropzone && dropzone.__dropzone) {
    console.log('Triggering multiple file selection...');
    
    // Call the multiple files handler
    const dropzoneInstance = dropzone.__dropzone;
    if (dropzoneInstance.onMultipleFilesSelect) {
      dropzoneInstance.onMultipleFilesSelect(files);
      console.log('✅ Multiple files handler called');
      
      // Wait for UI to update
      setTimeout(() => {
        // Look for start button
        const startButton = Array.from(document.querySelectorAll('button')).find(
          btn => btn.textContent.includes('Start Batch Conversion')
        );
        
        if (startButton) {
          console.log('✅ Start button found');
          console.log('👉 Click the "Start Batch Conversion" button to test completion notification');
          
          // Highlight the button
          startButton.style.border = '3px solid red';
          startButton.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
          console.log('❌ Start button not found');
        }
      }, 500);
    } else {
      console.log('❌ Multiple files handler not found on dropzone');
    }
  } else {
    console.log('❌ Dropzone not found');
  }
}

// Function to check if summary modal appears
function checkForSummaryModal() {
  console.log('\nChecking for summary modal...');
  
  const checkInterval = setInterval(() => {
    const modal = document.querySelector('.batch-summary-modal');
    if (modal && modal.style.display !== 'none') {
      console.log('✅ SUCCESS! Batch summary modal appeared!');
      clearInterval(checkInterval);
      
      // Check for download button
      const downloadButton = modal.querySelector('button[class*="download"]');
      if (downloadButton) {
        console.log('✅ Download button found in summary modal');
        downloadButton.style.border = '3px solid green';
      }
    }
  }, 500);
  
  // Stop checking after 30 seconds
  setTimeout(() => {
    clearInterval(checkInterval);
  }, 30000);
}

// Run the test
console.log('Setting up WebSocket monitoring...');
monitorWebSocket();

console.log('\nInstructions:');
console.log('1. This will create 2 test files and show the batch UI');
console.log('2. Click "Start Batch Conversion" when it appears');
console.log('3. Watch the console for WebSocket messages');
console.log('4. The summary modal should appear when processing completes');
console.log('5. If successful, you\'ll see a download button\n');

// Start the test
testBatchProcessing();
checkForSummaryModal();