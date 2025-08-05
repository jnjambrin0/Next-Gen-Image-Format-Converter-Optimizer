// Test script to verify batch API fix
// Run this in browser console after loading the app

console.log('=== Batch API Fix Verification ===');

// Test 1: Check if batch API endpoint is accessible
async function testBatchEndpoint() {
  console.log('\nTest 1: Checking batch API endpoint...');
  
  // Create a simple test file
  const testBlob = new Blob(['test'], { type: 'image/jpeg' });
  const testFile = new File([testBlob], 'test.jpg', { type: 'image/jpeg' });
  
  const formData = new FormData();
  formData.append('files', testFile);
  formData.append('output_format', 'webp');
  
  try {
    const response = await fetch('/api/batch/', {
      method: 'POST',
      body: formData
    });
    
    console.log(`Status: ${response.status}`);
    
    if (response.status === 202) {
      console.log('✅ Batch endpoint is working! (202 Accepted)');
      const data = await response.json();
      console.log('Response:', data);
      return data.job_id;
    } else if (response.status === 404) {
      console.log('❌ Batch endpoint not found (404) - URL issue persists');
    } else {
      console.log(`⚠️ Unexpected status: ${response.status}`);
      const text = await response.text();
      console.log('Response:', text);
    }
  } catch (error) {
    console.error('❌ Error calling batch endpoint:', error);
  }
  
  return null;
}

// Test 2: Test with multiple files through UI
function testMultipleFileSelection() {
  console.log('\nTest 2: Multiple file selection test');
  console.log('Instructions:');
  console.log('1. Select 2 or more image files using the file picker');
  console.log('2. You should see the batch UI with file list and preset selector');
  console.log('3. Click "Start Batch Conversion"');
  console.log('4. Watch for progress updates');
  
  // Trigger file input click
  const fileInput = document.querySelector('input[type="file"][multiple]');
  if (fileInput) {
    console.log('File input found. Click it to select multiple files.');
    fileInput.click();
  } else {
    console.log('❌ Multiple file input not found!');
  }
}

// Test 3: Verify all batch endpoints
async function testAllEndpoints(jobId) {
  console.log('\nTest 3: Testing all batch endpoints...');
  
  if (!jobId) {
    console.log('Skipping - no job ID available');
    return;
  }
  
  const endpoints = [
    { name: 'Status', url: `/api/batch/${jobId}/status`, method: 'GET' },
    { name: 'Results', url: `/api/batch/${jobId}/results`, method: 'GET' },
    { name: 'WebSocket Token', url: `/api/batch/${jobId}/websocket-token`, method: 'POST' }
  ];
  
  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint.url, { method: endpoint.method });
      console.log(`${endpoint.name}: ${response.status} ${response.status === 200 || response.status === 202 ? '✅' : '⚠️'}`);
    } catch (error) {
      console.log(`${endpoint.name}: ❌ Error - ${error.message}`);
    }
  }
}

// Run tests
(async () => {
  console.log('Starting batch API verification...\n');
  
  // Test batch endpoint
  const jobId = await testBatchEndpoint();
  
  // Test all endpoints if we got a job ID
  if (jobId) {
    await testAllEndpoints(jobId);
  }
  
  // Provide manual test instructions
  console.log('\n=== Manual Tests ===');
  testMultipleFileSelection();
  
  console.log('\n=== Summary ===');
  console.log('If Test 1 shows ✅, the URL fix is working!');
  console.log('Complete the manual test to verify full functionality.');
})();