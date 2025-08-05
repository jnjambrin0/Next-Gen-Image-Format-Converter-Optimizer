// Test script to verify batch functionality
console.log('=== Batch Processing UI Test ===');

// Create test files to simulate multiple file selection
function createTestFile(name, size = 1024) {
  const blob = new Blob(['x'.repeat(size)], { type: 'image/jpeg' });
  return new File([blob], name, { type: 'image/jpeg' });
}

// Test cases
const testCases = [
  {
    name: 'Single file (should trigger immediate conversion)',
    files: [createTestFile('single.jpg')],
    expected: 'Should start conversion immediately'
  },
  {
    name: 'Multiple files (should show batch UI)',
    files: [
      createTestFile('image1.jpg'),
      createTestFile('image2.png'), 
      createTestFile('image3.webp')
    ],
    expected: 'Should show FileListPreview and BatchPresetSelector'
  },
  {
    name: 'Many files (stress test)',
    files: Array.from({length: 20}, (_, i) => createTestFile(`test${i}.jpg`)),
    expected: 'Should handle 20 files in batch UI'
  }
];

console.log('\nInstructions:');
console.log('1. Open http://localhost:5173 in your browser');
console.log('2. Open the browser console (F12)');
console.log('3. Paste this script in the console');
console.log('4. The script will simulate file selections');
console.log('\nTest cases to verify:');
testCases.forEach((tc, i) => {
  console.log(`${i + 1}. ${tc.name}: ${tc.expected}`);
});

// Export test function for manual execution
window.testBatchUI = function(testIndex = 1) {
  const testCase = testCases[testIndex];
  if (!testCase) {
    console.error('Invalid test index');
    return;
  }
  
  console.log(`\nRunning test: ${testCase.name}`);
  console.log(`Files: ${testCase.files.length}`);
  
  // Find dropzone and trigger file selection
  const dropzone = document.querySelector('#dropzone');
  if (!dropzone || !dropzone.__dropzoneInstance) {
    console.error('Dropzone not found or not initialized');
    return;
  }
  
  // Get the dropzone instance from the app
  const fileInput = document.querySelector('#fileInput');
  
  // Create a DataTransfer object to simulate file selection
  const dt = new DataTransfer();
  testCase.files.forEach(file => dt.items.add(file));
  
  // Update the file input
  fileInput.files = dt.files;
  
  // Trigger change event
  const event = new Event('change', { bubbles: true });
  fileInput.dispatchEvent(event);
  
  console.log('✓ File selection triggered');
  console.log(`Expected: ${testCase.expected}`);
};

console.log('\nTo run a test, execute: window.testBatchUI(1)');
console.log('Where 1 is the test case number (0-2)');