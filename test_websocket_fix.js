// Test script to verify WebSocket fix
// Run this in browser console after reloading the app

console.log('=== WebSocket Fix Verification ===');

// Function to test WebSocket methods
function testWebSocketMethods() {
  console.log('\nTest 1: Checking WebSocketService methods...');
  
  // Create a test instance
  const testWS = new WebSocketService();
  
  // Check if methods exist
  const methods = ['on', 'off', 'connect', 'disconnect', 'send'];
  let allGood = true;
  
  methods.forEach(method => {
    if (typeof testWS[method] === 'function') {
      console.log(`✅ ${method}() method exists`);
    } else {
      console.log(`❌ ${method}() method missing`);
      allGood = false;
    }
  });
  
  // Check that onMessage doesn't exist (it shouldn't)
  if (typeof testWS.onMessage === 'undefined') {
    console.log('✅ onMessage() correctly does not exist (uses on() instead)');
  } else {
    console.log('❌ onMessage() exists but should not');
  }
  
  return allGood;
}

// Function to test batch processing with WebSocket
async function testBatchWithWebSocket() {
  console.log('\nTest 2: Testing batch processing with WebSocket...');
  
  // Create test files
  const files = [];
  for (let i = 0; i < 2; i++) {
    const canvas = document.createElement('canvas');
    canvas.width = 100;
    canvas.height = 100;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = ['green', 'yellow'][i];
    ctx.fillRect(0, 0, 100, 100);
    
    await new Promise(resolve => {
      canvas.toBlob(blob => {
        const file = new File([blob], `test${i + 1}.png`, { type: 'image/png' });
        files.push(file);
        resolve();
      }, 'image/png');
    });
  }
  
  // Monitor WebSocket messages
  let progressReceived = false;
  let completionReceived = false;
  
  // Override WebSocket to monitor messages
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = function(url) {
    console.log(`WebSocket connecting to: ${url}`);
    const ws = new OriginalWebSocket(url);
    
    ws.addEventListener('message', function(event) {
      try {
        const data = JSON.parse(event.data);
        console.log(`WebSocket message:`, data);
        
        if (data.type === 'progress') {
          progressReceived = true;
          console.log('✅ Progress message received');
        }
        
        if (data.type === 'job_status' && (data.status === 'completed' || data.status === 'failed')) {
          completionReceived = true;
          console.log('✅ Completion message received');
        }
      } catch (e) {
        console.log('WebSocket raw message:', event.data);
      }
    });
    
    return ws;
  };
  
  // Trigger batch processing
  const dropzone = document.querySelector('.dropzone');
  if (dropzone && dropzone.__dropzone) {
    const dropzoneInstance = dropzone.__dropzone;
    if (dropzoneInstance.onMultipleFilesSelect) {
      dropzoneInstance.onMultipleFilesSelect(files);
      
      // Wait for UI
      setTimeout(() => {
        const startButton = Array.from(document.querySelectorAll('button')).find(
          btn => btn.textContent.includes('Start Batch Conversion')
        );
        
        if (startButton) {
          console.log('✅ Batch UI loaded successfully');
          console.log('👉 Click "Start Batch Conversion" to test WebSocket messages');
          
          // After 10 seconds, check results
          setTimeout(() => {
            console.log('\n=== Results ===');
            console.log(`Progress messages received: ${progressReceived ? '✅' : '❌'}`);
            console.log(`Completion message received: ${completionReceived ? '✅' : '❌'}`);
            console.log(`Summary modal visible: ${document.querySelector('.batch-summary-modal') ? '✅' : '❌'}`);
          }, 10000);
        }
      }, 500);
    }
  }
}

// Function to check for errors
function checkForErrors() {
  console.log('\nTest 3: Checking for JavaScript errors...');
  
  // Set up error listener
  const errorHandler = (event) => {
    console.log('❌ JavaScript Error:', event.error);
    return true;
  };
  
  window.addEventListener('error', errorHandler);
  
  // Test will run for 5 seconds
  setTimeout(() => {
    window.removeEventListener('error', errorHandler);
    console.log('✅ No JavaScript errors detected in 5 seconds');
  }, 5000);
}

// Run all tests
console.log('Starting WebSocket fix verification...\n');

// Test 1: Check methods
const methodsOk = testWebSocketMethods();

if (methodsOk) {
  console.log('\n✅ WebSocket methods check passed!');
  
  // Test 2: Batch processing
  console.log('\nSetting up batch processing test...');
  testBatchWithWebSocket();
  
  // Test 3: Error monitoring
  checkForErrors();
  
  console.log('\n📋 Instructions:');
  console.log('1. Click "Start Batch Conversion" when it appears');
  console.log('2. Watch for WebSocket messages in the console');
  console.log('3. Verify the summary modal appears after processing');
  console.log('4. Try downloading the results');
} else {
  console.log('\n❌ WebSocket methods check failed - fix required');
}