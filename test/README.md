# Proxy-Kutti Integration Tests

This directory contains integration tests that prove the core caching functionality of proxy-kutti works correctly.

## Test Files

### `real-proxy.test.js` (Main Test Suite)
The primary integration test that validates proxy-kutti's caching behavior:

- **Cache Miss Test**: Verifies that requests are forwarded to the origin server when no cache exists
- **Cache Hit Test**: Verifies that subsequent identical requests are served from cache without hitting the origin
- **Cache Structure Test**: Validates that cache files are created in the correct proxy-kutti directory structure
- **Conditional Headers Test**: Ensures ETag and Last-Modified headers are properly cached

### `proxy-cache.test.js`
Simplified cache logic test that demonstrates the cache hit/miss behavior with a mock implementation.

### `integration.test.js`
Basic integration test framework (simplified proxy implementation for testing concepts).

## Running Tests

```bash
# Run the main test suite
npm test

# Run specific tests
npm run test:cache          # Run simplified cache test
npm run test:integration    # Run basic integration test

# Run all tests
npm run test:all
```

## What These Tests Prove

### 1. Cache Miss Behavior
- When no cache exists for a request, the proxy forwards the request to the origin server
- The origin server receives and processes the request
- The response is cached in the filesystem with the correct structure
- Cache files include both data (`.data`) and metadata (`.data.meta`)

### 2. Cache Hit Behavior  
- When a cache exists for a request, the proxy serves the response from cache
- The origin server does NOT receive the request
- The cached response matches the original response exactly
- No additional network requests are made

### 3. Cache File Structure
- Cache files are stored in `cache_dir/protocol/host:port/method/path.data`
- Metadata files use the same path with `.meta` extension
- Metadata includes headers, status code, and original request information
- Cache structure matches the documented proxy-kutti format

### 4. Conditional Headers
- ETag and Last-Modified headers are properly preserved in cache
- These headers can be used for cache validation in future requests

## Test Architecture

The tests use:
- **Mock Origin Server**: HTTP server that tracks request counts to verify cache behavior
- **Temporary Cache Directory**: Isolated cache storage for each test run
- **File System Verification**: Direct inspection of cache files to ensure correct structure
- **Request Counting**: Tracking origin server requests to prove cache hits vs misses

## Example Test Output

```
🎉 All real proxy integration tests passed!
Total origin server requests: 4
Cache directory: /tmp/proxy-kutti-real-test

Cache directory structure:
/tmp/proxy-kutti-real-test/http/127.0.0.1:9006/GET/api/etag-test.data
/tmp/proxy-kutti-real-test/http/127.0.0.1:9006/GET/api/cache-miss-test.data.meta
/tmp/proxy-kutti-real-test/http/127.0.0.1:9006/GET/api/cache-miss-test.data
...
```

## Key Assertions

1. **Cache Miss**: `originRequestCount` increments when cache doesn't exist
2. **Cache Hit**: `originRequestCount` stays the same when serving from cache  
3. **Cache Structure**: Files exist at expected paths with correct content
4. **Data Integrity**: Cached responses match original responses exactly