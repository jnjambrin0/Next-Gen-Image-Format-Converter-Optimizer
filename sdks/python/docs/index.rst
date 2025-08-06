.. Image Converter SDK documentation master file

Image Converter Python SDK Documentation
=========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   api
   examples
   security
   changelog

Overview
--------

The Image Converter Python SDK provides a secure, privacy-focused interface to the local Image Converter API.
All processing happens on your local machine with no external network connections.

Key Features
^^^^^^^^^^^^

* **Privacy-First**: All processing is local, no data leaves your machine
* **Secure**: Localhost-only connections enforced by default
* **Type-Safe**: Full type hints for better IDE support
* **Async Support**: Both synchronous and asynchronous clients
* **Batch Processing**: Efficient batch conversion with progress tracking

Installation
^^^^^^^^^^^^

.. code-block:: bash

   pip install image-converter-sdk

Quick Example
^^^^^^^^^^^^^

.. code-block:: python

   from image_converter import ImageConverterClient
   
   # Initialize client (connects to localhost:8080 by default)
   client = ImageConverterClient()
   
   # Convert a single image
   with open('input.jpg', 'rb') as f:
       result = client.convert_image(f.read(), 'webp', quality=85)
   
   # Save the converted image
   with open('output.webp', 'wb') as f:
       f.write(result.data)
   
   print(f"Converted to {result.format}, size: {result.size} bytes")

Security Notice
^^^^^^^^^^^^^^^

This SDK enforces localhost-only connections by default for security.
Attempting to connect to external hosts will raise a `NetworkSecurityError`.

For more information, see the :doc:`security` section.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`