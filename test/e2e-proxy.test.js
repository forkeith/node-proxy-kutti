#!/usr/bin/env node

const http = require('http');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

/**
 * End-to-end integration tests for proxy-kutti
 * Tests the actual proxy server with real HTTP requests
 */

class E2EProxyTest {
  constructor() {
    this.originServerPort = 9004;
    this.proxyPort = 9005;
    this.testCacheDir = path.join(os.tmpdir(), 'proxy-kutti-e2e-test');
    this.originServer = null;
    this.proxyProcess = null;
    this.originRequestCount = 0;
  }

  async setup() {
    await this.cleanupTestCache();
    await fs.promises.mkdir(this.testCacheDir, { recursive: true });
    await this.setupOriginServer();
    await this.setupProxyServer();
    // Give proxy server time to start
    await this.sleep(2000);
  }

  async cleanup() {
    if (this.originServer) {
      this.originServer.close();
    }
    if (this.proxyProcess) {
      this.proxyProcess.kill();
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

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
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
          'Content-Length': Buffer.byteLength(responseBody)
        });
        res.end(responseBody);
      });
      
      this.originServer.listen(this.originServerPort, '127.0.0.1', () => {
        console.log(`Origin server started on http://127.0.0.1:${this.originServerPort}`);
        resolve();
      });
    });
  }

  async setupProxyServer() {
    return new Promise((resolve) => {
      // Start proxy-kutti with custom configuration
      const env = {
        ...process.env,
        PROXY_KUTTI_port: this.proxyPort.toString(),
        PROXY_KUTTI_host: '127.0.0.1',
        PROXY_KUTTI_cache_dir: this.testCacheDir
      };

      this.proxyProcess = spawn('node', ['proxy.js'], {
        cwd: '/home/runner/work/node-proxy-kutti/node-proxy-kutti',
        env: env,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      this.proxyProcess.stdout.on('data', (data) => {
        const output = data.toString();
        console.log('Proxy output:', output);
        if (output.includes('Proxy-kutti is running')) {
          resolve();
        }
      });

      this.proxyProcess.stderr.on('data', (data) => {
        console.error('Proxy error:', data.toString());
      });

      this.proxyProcess.on('close', (code) => {
        console.log(`Proxy process exited with code ${code}`);
      });
    });
  }

  async makeRequestThroughProxy(path = '/test') {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: '127.0.0.1',
        port: this.proxyPort,
        path: `http://127.0.0.1:${this.originServerPort}${path}`,
        method: 'GET'
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

  async getCacheFilePath(path) {
    const host = `127.0.0.1:${this.originServerPort}`;
    return `${this.testCacheDir}/http/${host}/GET${path}.data`;
  }

  async getCacheMetaPath(path) {
    return `${await this.getCacheFilePath(path)}.meta`;
  }

  async cacheExists(path) {
    try {
      await fs.promises.access(await this.getCacheMetaPath(path));
      return true;
    } catch {
      return false;
    }
  }

  async testE2ECacheMiss() {
    console.log('\n--- Testing E2E Cache Miss Scenario ---');
    
    const testPath = '/api/e2e-miss';
    const initialRequestCount = this.originRequestCount;
    
    // Ensure no cache exists
    const cacheExists = await this.cacheExists(testPath);
    assert.strictEqual(cacheExists, false, 'Cache should not exist initially');
    
    // Make request through proxy - should be a cache miss
    const response = await this.makeRequestThroughProxy(testPath);
    
    assert.strictEqual(response.statusCode, 200, 'Request should succeed');
    assert.strictEqual(this.originRequestCount, initialRequestCount + 1, 
      'Origin server should receive the request');
    
    const responseData = JSON.parse(response.body);
    assert.strictEqual(responseData.requestCount, initialRequestCount + 1, 
      'Response should show correct request count from origin');
    
    // Verify cache was created
    await this.sleep(100); // Give cache time to be written
    const cacheExistsAfter = await this.cacheExists(testPath);
    assert.strictEqual(cacheExistsAfter, true, 'Cache should exist after first request');
    
    console.log('✓ E2E Cache miss test passed: Request forwarded to origin via proxy and cached');
    return responseData;
  }

  async testE2ECacheHit() {
    console.log('\n--- Testing E2E Cache Hit Scenario ---');
    
    const testPath = '/api/e2e-hit';
    
    // First request to populate cache
    console.log('Making first request to populate cache...');
    const response1 = await this.makeRequestThroughProxy(testPath);
    const requestCountAfterFirst = this.originRequestCount;
    
    assert.strictEqual(response1.statusCode, 200, 'First request should succeed');
    
    // Wait for cache to be written
    await this.sleep(100);
    
    // Second request should be served from cache
    console.log('Making second request (should be served from cache)...');
    const response2 = await this.makeRequestThroughProxy(testPath);
    
    assert.strictEqual(response2.statusCode, 200, 'Second request should succeed');
    assert.strictEqual(this.originRequestCount, requestCountAfterFirst, 
      'Origin server should NOT receive second request when serving from cache');
    
    // Verify both responses have same content (from cache)
    const data1 = JSON.parse(response1.body);
    const data2 = JSON.parse(response2.body);
    assert.strictEqual(data1.requestCount, data2.requestCount, 
      'Cached response should have same request count as original');
    
    console.log('✓ E2E Cache hit test passed: Second request served from cache via proxy without hitting origin');
  }

  async testE2ECacheStructure() {
    console.log('\n--- Testing E2E Cache File Structure ---');
    
    const testPath = '/api/structure-test';
    
    // Make request to create cache
    await this.makeRequestThroughProxy(testPath);
    await this.sleep(100);
    
    const cacheFile = await this.getCacheFilePath(testPath);
    const cacheMetaFile = await this.getCacheMetaPath(testPath);
    
    // Verify cache files exist
    assert.strictEqual(fs.existsSync(cacheFile), true, 'Cache data file should exist');
    assert.strictEqual(fs.existsSync(cacheMetaFile), true, 'Cache meta file should exist');
    
    // Verify cache file contents
    const cachedData = await fs.promises.readFile(cacheFile, 'utf8');
    const metaData = JSON.parse(await fs.promises.readFile(cacheMetaFile, 'utf8'));
    
    const parsedData = JSON.parse(cachedData);
    assert.strictEqual(parsedData.path, testPath, 'Cached data should contain correct path');
    assert.strictEqual(metaData.statusCode, 200, 'Metadata should contain status code');
    assert.strictEqual(typeof metaData.headers, 'object', 'Metadata should contain headers');
    assert.strictEqual(typeof metaData['proxy-kutti-orig-request'], 'object', 
      'Metadata should contain original request info');
    
    console.log('✓ E2E Cache structure test passed: Cache files created with correct proxy-kutti structure');
    console.log(`  Cache data: ${cacheFile}`);
    console.log(`  Cache meta: ${cacheMetaFile}`);
  }

  async run() {
    console.log('Starting Proxy-Kutti E2E Integration Tests...\n');
    
    try {
      await this.setup();
      
      // Test cache miss scenario
      await this.testE2ECacheMiss();
      
      // Test cache hit scenario
      await this.testE2ECacheHit();
      
      // Test cache file structure
      await this.testE2ECacheStructure();
      
      console.log('\n🎉 All E2E integration tests passed!');
      console.log(`Total origin server requests: ${this.originRequestCount}`);
      console.log(`Cache directory: ${this.testCacheDir}`);
      
    } catch (error) {
      console.error('❌ E2E Test failed:', error.message);
      console.error(error.stack);
      process.exit(1);
    } finally {
      await this.cleanup();
    }
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  const test = new E2EProxyTest();
  test.run().catch(console.error);
}

module.exports = E2EProxyTest;