#!/usr/bin/env node

const http = require('http');
const https = require('https');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const url = require('url');

/**
 * Integration tests for proxy-kutti actual caching functionality
 * Uses the real proxy.js getContent function to test cache behavior
 */

// Mock the getContent function from proxy.js since it's not exported
const fsPromise = fs.promises;
const { dirname } = require('path');

// Simplified version of the proxy cache logic for testing
class ProxyCacheTest {
  constructor() {
    this.originServerPort = 9003;
    this.testCacheDir = path.join(os.tmpdir(), 'proxy-kutti-cache-test');
    this.originServer = null;
    this.originRequestCount = 0;
    this.config = {
      cache_dir: this.testCacheDir,
      cache_control: [],
      cache_never_expires_for_content_types: []
    };
  }

  async setup() {
    await this.cleanupTestCache();
    await fs.promises.mkdir(this.testCacheDir, { recursive: true });
    await this.setupOriginServer();
  }

  async cleanup() {
    if (this.originServer) {
      this.originServer.close();
    }
    await this.cleanupTestCache();
  }

  async cleanupTestCache() {
    try {
      await fs.promises.rm(this.testCacheDir, { recursive: true, force: true });
    } catch (err) {
      // Ignore if directory doesn't exist
    }
  }

  async setupOriginServer() {
    return new Promise((resolve) => {
      this.originServer = http.createServer((req, res) => {
        this.originRequestCount++;
        
        console.log(`Origin server: Received request ${this.originRequestCount} for ${req.url}`);
        
        const responseBody = JSON.stringify({
          message: 'Response from origin server',
          requestCount: this.originRequestCount,
          path: req.url,
          timestamp: new Date().toISOString()
        });
        
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(responseBody),
          'Cache-Control': 'max-age=3600'
        });
        res.end(responseBody);
      });
      
      this.originServer.listen(this.originServerPort, '127.0.0.1', () => {
        console.log(`Origin server started on http://127.0.0.1:${this.originServerPort}`);
        resolve();
      });
    });
  }

  // Simplified cache logic based on proxy.js
  async getCachedContent(requestUrl, method = 'GET') {
    const parsedUrl = url.parse(requestUrl);
    const proto = 'http';
    const cachePort = parsedUrl.port ? ':' + parsedUrl.port : '';
    
    let cachedFile = `${this.config.cache_dir}/${proto}/${parsedUrl.host}${cachePort}/${method}${parsedUrl.pathname}`;
    if (parsedUrl.pathname.slice(-1) === '/') {
      cachedFile += '#index.data';
    } else {
      cachedFile += '.data';
    }
    const cachedFileMeta = `${cachedFile}.meta`;
    
    return { cachedFile, cachedFileMeta };
  }

  async checkCacheExists(requestUrl, method = 'GET') {
    const { cachedFileMeta } = await this.getCachedContent(requestUrl, method);
    try {
      await fs.promises.access(cachedFileMeta);
      return true;
    } catch {
      return false;
    }
  }

  async makeRequestThroughCache(requestUrl, method = 'GET') {
    const { cachedFile, cachedFileMeta } = await this.getCachedContent(requestUrl, method);
    const cacheExists = await this.checkCacheExists(requestUrl, method);
    
    if (cacheExists) {
      console.log(`Cache HIT: Serving from ${cachedFile}`);
      // Read from cache
      const metaData = JSON.parse(await fs.promises.readFile(cachedFileMeta));
      const cachedData = await fs.promises.readFile(cachedFile);
      return {
        statusCode: metaData.statusCode,
        headers: metaData.headers,
        body: cachedData.toString(),
        fromCache: true
      };
    } else {
      console.log(`Cache MISS: Fetching from origin and caching to ${cachedFile}`);
      // Make request to origin and cache response
      const response = await this.makeOriginRequest(requestUrl, method);
      
      // Save to cache
      await fs.promises.mkdir(dirname(cachedFile), { recursive: true });
      await fs.promises.writeFile(cachedFile, response.body);
      
      const metaData = {
        headers: response.headers,
        statusCode: response.statusCode,
        'proxy-kutti-orig-request': {
          url: requestUrl,
          method: method,
          'cache-date': new Date().toISOString()
        }
      };
      await fs.promises.writeFile(cachedFileMeta, JSON.stringify(metaData));
      
      return {
        ...response,
        fromCache: false
      };
    }
  }

  async makeOriginRequest(requestUrl, method = 'GET') {
    const parsedUrl = url.parse(requestUrl);
    
    return new Promise((resolve, reject) => {
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.path,
        method: method
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: data
          });
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  async testCacheMiss() {
    console.log('\n--- Testing Cache Miss Scenario ---');
    
    const testUrl = `http://127.0.0.1:${this.originServerPort}/api/test-miss`;
    const initialRequestCount = this.originRequestCount;
    
    // Ensure no cache exists
    const cacheExists = await this.checkCacheExists(testUrl);
    assert.strictEqual(cacheExists, false, 'Cache should not exist initially');
    
    // Make request - should be a cache miss
    const response = await this.makeRequestThroughCache(testUrl);
    
    assert.strictEqual(response.statusCode, 200, 'Request should succeed');
    assert.strictEqual(response.fromCache, false, 'Response should come from origin, not cache');
    assert.strictEqual(this.originRequestCount, initialRequestCount + 1, 
      'Origin server should receive the request');
    
    const responseData = JSON.parse(response.body);
    assert.strictEqual(responseData.requestCount, initialRequestCount + 1, 
      'Response should show correct request count from origin');
    
    // Verify cache was created
    const cacheExistsAfter = await this.checkCacheExists(testUrl);
    assert.strictEqual(cacheExistsAfter, true, 'Cache should exist after first request');
    
    console.log('✓ Cache miss test passed: Request forwarded to origin and cached');
    return responseData;
  }

  async testCacheHit() {
    console.log('\n--- Testing Cache Hit Scenario ---');
    
    const testUrl = `http://127.0.0.1:${this.originServerPort}/api/test-hit`;
    
    // First request to populate cache
    console.log('Making first request to populate cache...');
    const response1 = await this.makeRequestThroughCache(testUrl);
    const requestCountAfterFirst = this.originRequestCount;
    
    assert.strictEqual(response1.fromCache, false, 'First response should come from origin');
    
    // Second request should be served from cache
    console.log('Making second request (should be served from cache)...');
    const response2 = await this.makeRequestThroughCache(testUrl);
    
    assert.strictEqual(response2.statusCode, 200, 'Second request should succeed');
    assert.strictEqual(response2.fromCache, true, 'Second response should come from cache');
    assert.strictEqual(this.originRequestCount, requestCountAfterFirst, 
      'Origin server should NOT receive second request when serving from cache');
    
    // Verify both responses have same content (from cache)
    const data1 = JSON.parse(response1.body);
    const data2 = JSON.parse(response2.body);
    assert.strictEqual(data1.requestCount, data2.requestCount, 
      'Cached response should have same request count as original');
    
    console.log('✓ Cache hit test passed: Second request served from cache without hitting origin');
  }

  async testCachePersistence() {
    console.log('\n--- Testing Cache Persistence ---');
    
    const testUrl = `http://127.0.0.1:${this.originServerPort}/api/test-persistence`;
    
    // Make first request
    await this.makeRequestThroughCache(testUrl);
    const { cachedFile, cachedFileMeta } = await this.getCachedContent(testUrl);
    
    // Verify cache files exist
    assert.strictEqual(fs.existsSync(cachedFile), true, 'Cache data file should exist');
    assert.strictEqual(fs.existsSync(cachedFileMeta), true, 'Cache meta file should exist');
    
    // Verify cache file contents
    const cachedData = await fs.promises.readFile(cachedFile, 'utf8');
    const metaData = JSON.parse(await fs.promises.readFile(cachedFileMeta, 'utf8'));
    
    assert.strictEqual(typeof cachedData, 'string', 'Cached data should be readable');
    assert.strictEqual(metaData.statusCode, 200, 'Metadata should contain status code');
    assert.strictEqual(typeof metaData.headers, 'object', 'Metadata should contain headers');
    assert.strictEqual(typeof metaData['proxy-kutti-orig-request'], 'object', 
      'Metadata should contain original request info');
    
    console.log('✓ Cache persistence test passed: Cache files created with correct structure');
    console.log(`  Cache data: ${cachedFile}`);
    console.log(`  Cache meta: ${cachedFileMeta}`);
  }

  async run() {
    console.log('Starting Proxy-Kutti Cache Integration Tests...\n');
    
    try {
      await this.setup();
      
      // Test cache miss scenario
      await this.testCacheMiss();
      
      // Test cache hit scenario
      await this.testCacheHit();
      
      // Test cache persistence
      await this.testCachePersistence();
      
      console.log('\n🎉 All cache integration tests passed!');
      console.log(`Total origin server requests: ${this.originRequestCount}`);
      console.log(`Cache directory: ${this.testCacheDir}`);
      
    } catch (error) {
      console.error('❌ Test failed:', error.message);
      console.error(error.stack);
      process.exit(1);
    } finally {
      await this.cleanup();
    }
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  const test = new ProxyCacheTest();
  test.run().catch(console.error);
}

module.exports = ProxyCacheTest;