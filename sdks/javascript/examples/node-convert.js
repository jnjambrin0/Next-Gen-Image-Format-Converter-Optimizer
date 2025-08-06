#!/usr/bin/env node

/**
 * Node.js CLI example for Image Converter SDK
 * Demonstrates secure local-only image conversion with batch support
 */

const { ImageConverterClient } = require('@image-converter/sdk');
const fs = require('fs').promises;
const path = require('path');
const { program } = require('commander');

// Configure CLI
program
  .name('image-converter')
  .description('Local-only image conversion CLI')
  .version('1.0.0');

program
  .command('convert <input> <output-format>')
  .description('Convert a single image')
  .option('-q, --quality <number>', 'Quality (1-100)', '85')
  .option('-s, --strip-metadata', 'Remove metadata', true)
  .option('-k, --api-key <key>', 'API key')
  .option('-p, --port <number>', 'API server port', '8080')
  .action(async (input, outputFormat, options) => {
    await convertSingle(input, outputFormat, options);
  });

program
  .command('batch <directory> <output-format>')
  .description('Convert all images in a directory')
  .option('-q, --quality <number>', 'Quality (1-100)', '85')
  .option('-s, --strip-metadata', 'Remove metadata', true)
  .option('-c, --concurrent <number>', 'Max concurrent conversions', '5')
  .option('-k, --api-key <key>', 'API key')
  .option('-p, --port <number>', 'API server port', '8080')
  .action(async (directory, outputFormat, options) => {
    await convertBatch(directory, outputFormat, options);
  });

program
  .command('analyze <input>')
  .description('Analyze image content using ML')
  .option('-d, --debug', 'Include debug information')
  .option('-p, --port <number>', 'API server port', '8080')
  .action(async (input, options) => {
    await analyzeImage(input, options);
  });

program
  .command('store-key <name> <api-key>')
  .description('Store API key securely')
  .action(async (name, apiKey) => {
    await storeApiKey(name, apiKey);
  });

// Single image conversion
async function convertSingle(inputPath, outputFormat, options) {
  console.log(`🔄 Converting ${inputPath} to ${outputFormat}...`);
  
  try {
    const client = new ImageConverterClient({
      port: parseInt(options.port),
      apiKey: options.apiKey,
    });
    
    const { data, metadata } = await client.convertImage(
      inputPath,
      outputFormat,
      {
        quality: parseInt(options.quality),
        stripMetadata: options.stripMetadata,
      }
    );
    
    // Generate output filename
    const parsedPath = path.parse(inputPath);
    const outputPath = path.join(
      parsedPath.dir,
      `${parsedPath.name}.converted.${outputFormat}`
    );
    
    // Save converted image
    await fs.writeFile(outputPath, data);
    
    console.log(`✅ Conversion successful!`);
    console.log(`📁 Output: ${outputPath}`);
    console.log(`📊 Statistics:`);
    console.log(`   Processing time: ${metadata.processingTime.toFixed(3)}s`);
    console.log(`   Input format: ${metadata.inputFormat}`);
    console.log(`   Input size: ${(metadata.inputSize / 1024).toFixed(1)} KB`);
    console.log(`   Output size: ${(metadata.outputSize / 1024).toFixed(1)} KB`);
    console.log(`   Compression: ${(metadata.compressionRatio * 100).toFixed(1)}%`);
    console.log(`   Metadata removed: ${metadata.metadataRemoved}`);
    
  } catch (error) {
    console.error(`❌ Conversion failed: ${error.message}`);
    process.exit(1);
  }
}

// Batch conversion
async function convertBatch(directory, outputFormat, options) {
  console.log(`📦 Batch converting images in ${directory} to ${outputFormat}...`);
  
  try {
    // Find all image files
    const files = await fs.readdir(directory);
    const imageFiles = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ['.jpg', '.jpeg', '.png', '.webp', '.heic', '.heif', '.bmp', '.tiff'].includes(ext);
    });
    
    if (imageFiles.length === 0) {
      console.log('No image files found in directory');
      return;
    }
    
    console.log(`Found ${imageFiles.length} images to convert`);
    
    const client = new ImageConverterClient({
      port: parseInt(options.port),
      apiKey: options.apiKey,
    });
    
    // Create batch job
    const imagePaths = imageFiles.map(file => path.join(directory, file));
    const batchStatus = await client.createBatch(
      imagePaths,
      outputFormat,
      {
        quality: parseInt(options.quality),
        stripMetadata: options.stripMetadata,
        maxConcurrent: parseInt(options.concurrent),
      }
    );
    
    console.log(`✅ Batch job created: ${batchStatus.jobId}`);
    
    // Monitor progress
    let status = batchStatus;
    const startTime = Date.now();
    
    while (!['completed', 'failed', 'cancelled'].includes(status.status)) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      status = await client.getBatchStatus(batchStatus.jobId);
      
      // Show progress bar
      const completed = Math.floor(status.progressPercentage / 2);
      const remaining = 50 - completed;
      const progressBar = '█'.repeat(completed) + '░'.repeat(remaining);
      
      process.stdout.write(
        `\r[${progressBar}] ${status.progressPercentage.toFixed(0)}% ` +
        `(${status.completedFiles}/${status.totalFiles} files)`
      );
    }
    
    const elapsedTime = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log('\n');
    
    if (status.status === 'completed') {
      console.log(`✅ Batch conversion completed in ${elapsedTime}s`);
      console.log(`📊 Results:`);
      console.log(`   Completed: ${status.completedFiles} files`);
      console.log(`   Failed: ${status.failedFiles} files`);
      
      if (status.failedFiles > 0 && status.errors.length > 0) {
        console.log(`\n⚠️ Errors:`);
        status.errors.slice(0, 5).forEach(error => {
          console.log(`   - ${error.message || 'Unknown error'}`);
        });
      }
    } else {
      console.log(`❌ Batch conversion ${status.status}`);
      if (status.errors.length > 0) {
        console.log('Errors:');
        status.errors.forEach(error => {
          console.log(`   - ${error.message || 'Unknown error'}`);
        });
      }
    }
    
  } catch (error) {
    console.error(`❌ Batch conversion failed: ${error.message}`);
    process.exit(1);
  }
}

// Image analysis
async function analyzeImage(inputPath, options) {
  console.log(`🔍 Analyzing ${inputPath}...`);
  
  try {
    const client = new ImageConverterClient({
      port: parseInt(options.port),
    });
    
    const classification = await client.analyzeImage(
      inputPath,
      options.debug
    );
    
    console.log(`\n📊 Analysis Results:`);
    console.log(`   Content type: ${classification.contentType}`);
    console.log(`   Confidence: ${(classification.confidence * 100).toFixed(1)}%`);
    console.log(`   Processing time: ${classification.processingTimeMs.toFixed(1)}ms`);
    
    if (classification.faceRegions.length > 0) {
      console.log(`   Faces detected: ${classification.faceRegions.length}`);
      if (options.debug) {
        classification.faceRegions.forEach((face, i) => {
          console.log(`     Face ${i + 1}: [${face.x},${face.y} ${face.width}x${face.height}]`);
        });
      }
    }
    
    if (classification.textRegions.length > 0) {
      console.log(`   Text regions: ${classification.textRegions.length}`);
      if (options.debug) {
        classification.textRegions.forEach((text, i) => {
          console.log(`     Text ${i + 1}: [${text.x},${text.y} ${text.width}x${text.height}]`);
        });
      }
    }
    
    if (options.debug && classification.metadata) {
      console.log(`\n🔧 Debug Metadata:`);
      console.log(JSON.stringify(classification.metadata, null, 2));
    }
    
  } catch (error) {
    console.error(`❌ Analysis failed: ${error.message}`);
    process.exit(1);
  }
}

// Store API key securely
async function storeApiKey(name, apiKey) {
  try {
    const { SecureAPIKeyManager } = require('@image-converter/sdk');
    const keyManager = new SecureAPIKeyManager();
    
    const success = await keyManager.store(name, apiKey);
    
    if (success) {
      console.log(`✅ API key stored securely as '${name}'`);
      console.log(`🔒 The key is encrypted and stored in your OS keychain`);
    } else {
      console.log(`❌ Failed to store API key`);
    }
  } catch (error) {
    console.error(`❌ Error storing key: ${error.message}`);
    process.exit(1);
  }
}

// Parse arguments and run
program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}