export function initializeApp() {
  const app = document.getElementById('app')
  
  app.innerHTML = `
    <div class="min-h-screen bg-gray-50">
      <header class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 class="text-2xl font-bold text-gray-900">Image Converter</h1>
          <p class="text-sm text-gray-600">Privacy-first local image processing</p>
        </div>
      </header>
      
      <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="card">
          <h2 class="text-lg font-semibold mb-4">Upload Images</h2>
          <div class="dropzone" id="dropzone">
            <p class="text-gray-600">Drag and drop images here, or click to select</p>
            <p class="text-sm text-gray-500 mt-2">Supported formats: JPEG, PNG, WebP, HEIF/HEIC, AVIF</p>
          </div>
        </div>
      </main>
    </div>
  `
  
  console.log('Image Converter app initialized')
}