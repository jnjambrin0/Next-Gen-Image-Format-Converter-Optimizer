Quick Start Guide
=================

Installation
-----------

Standard Installation
^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   pip install image-converter-sdk

Offline Installation
^^^^^^^^^^^^^^^^^^^

For air-gapped environments:

.. code-block:: bash

   # Download on connected machine
   pip download image-converter-sdk --dest ./offline
   
   # Install on offline machine
   pip install --no-index --find-links ./offline image-converter-sdk

Basic Usage
----------

Synchronous Client
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from image_converter import ImageConverterClient
   from image_converter.exceptions import ValidationError, NetworkSecurityError
   
   # Initialize client
   client = ImageConverterClient(
       host="localhost",
       port=8080
   )
   
   # Convert image
   try:
       with open('photo.jpg', 'rb') as f:
           image_data = f.read()
       
       result = client.convert_image(
           image_data,
           output_format='webp',
           quality=90,
           preserve_metadata=False  # Privacy: remove EXIF data
       )
       
       # Save converted image
       with open('photo.webp', 'wb') as f:
           f.write(result.data)
           
       print(f"Conversion successful!")
       print(f"Output format: {result.format}")
       print(f"Output size: {result.size} bytes")
       print(f"Dimensions: {result.width}x{result.height}")
       
   except ValidationError as e:
       print(f"Invalid input: {e.message}")
   except NetworkSecurityError as e:
       print(f"Security error: {e.message}")

Asynchronous Client
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   import asyncio
   from image_converter import AsyncImageConverterClient
   
   async def convert_images():
       async with AsyncImageConverterClient() as client:
           # Convert multiple images concurrently
           tasks = []
           for filename in ['photo1.jpg', 'photo2.png', 'photo3.bmp']:
               with open(filename, 'rb') as f:
                   task = client.convert_image(f.read(), 'avif')
                   tasks.append(task)
           
           results = await asyncio.gather(*tasks)
           
           for i, result in enumerate(results):
               output_name = f'output_{i}.avif'
               with open(output_name, 'wb') as f:
                   f.write(result.data)
               print(f"Saved {output_name}")
   
   # Run the async function
   asyncio.run(convert_images())

Batch Processing
---------------

.. code-block:: python

   from image_converter import ImageConverterClient
   import time
   
   client = ImageConverterClient()
   
   # Prepare batch
   files = []
   for i in range(10):
       with open(f'image_{i}.jpg', 'rb') as f:
           files.append(('files', (f'image_{i}.jpg', f.read(), 'image/jpeg')))
   
   # Start batch conversion
   batch = client.create_batch(
       files,
       output_format='webp',
       quality=85
   )
   
   print(f"Batch job started: {batch.job_id}")
   
   # Monitor progress
   while batch.status != 'completed':
       time.sleep(2)
       batch = client.get_batch_status(batch.job_id)
       print(f"Progress: {batch.progress_percentage}%")
   
   # Download results
   zip_data = client.download_batch_results(batch.job_id)
   with open('results.zip', 'wb') as f:
       f.write(zip_data)
   
   print("Batch conversion complete!")

API Key Management
-----------------

Secure Storage
^^^^^^^^^^^^^^

.. code-block:: python

   from image_converter.auth import SecureAPIKeyManager
   
   # Store API key securely in OS keychain
   manager = SecureAPIKeyManager()
   manager.store_api_key(
       profile="production",
       api_key="ic_live_abc123..."
   )
   
   # Retrieve API key
   api_key = manager.get_api_key("production")
   
   # Use with client
   client = ImageConverterClient(api_key=api_key)

Environment Variables
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   export IMAGE_CONVERTER_API_KEY="ic_live_abc123..."

.. code-block:: python

   import os
   from image_converter import ImageConverterClient
   
   # Client will automatically use environment variable
   client = ImageConverterClient()

Error Handling
-------------

.. code-block:: python

   from image_converter import ImageConverterClient
   from image_converter.exceptions import (
       NetworkSecurityError,
       RateLimitError,
       ValidationError,
       ConversionError,
       APIError
   )
   
   client = ImageConverterClient()
   
   try:
       result = client.convert_image(image_data, 'webp')
   except NetworkSecurityError:
       # Attempted to connect to non-localhost
       print("Security: Only localhost connections allowed")
   except RateLimitError as e:
       # Too many requests
       retry_after = e.details.get('retry_after', 60)
       print(f"Rate limited. Retry after {retry_after} seconds")
   except ValidationError:
       # Invalid input parameters
       print("Invalid image or parameters")
   except ConversionError:
       # Conversion failed
       print("Failed to convert image")
   except APIError:
       # General API error
       print("API error occurred")

Advanced Options
---------------

Content Detection
^^^^^^^^^^^^^^^^^

.. code-block:: python

   # Analyze image content for optimization
   analysis = client.analyze_image(image_data)
   
   print(f"Content type: {analysis.content_type}")
   print(f"Has text: {analysis.has_text}")
   print(f"Has faces: {analysis.has_faces}")
   print(f"Recommended format: {analysis.recommended_format}")
   
   # Use recommendations for conversion
   result = client.convert_image(
       image_data,
       output_format=analysis.recommended_format,
       **analysis.recommended_settings
   )

Custom Timeout
^^^^^^^^^^^^^^

.. code-block:: python

   # Increase timeout for large files
   client = ImageConverterClient(
       timeout=30.0  # 30 seconds
   )
   
   # Or per-request timeout
   result = client.convert_image(
       large_image_data,
       'avif',
       timeout=60.0  # 60 seconds for this request
   )

Connection Pooling
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   # Async client with connection pooling
   async with AsyncImageConverterClient(
       max_connections=20,
       keepalive_expiry=30
   ) as client:
       # Reuses connections for multiple requests
       tasks = [client.convert_image(data, 'webp') for data in images]
       results = await asyncio.gather(*tasks)