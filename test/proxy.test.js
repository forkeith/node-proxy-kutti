// Make sure the user's real config file and cache dir are not picked up when proxy.js is required.
// These must be set before the require below, since config is resolved at module load time.
process.env.PROXY_KUTTI_CONFIG = '/nonexistent/proxy-kutti-test-config';
const os = require('os');
const fs = require('fs');
const path = require('path');
const http = require('http');
const net = require('net');
const { spawn } = require('child_process');
const tmpCacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-kutti-test-'));
process.env.PROXY_KUTTI_cache_dir = tmpCacheDir;

const { describe, it, after } = require('node:test');
const assert = require('node:assert');

const {
  config,
  parseUrlMappings,
  mapUrl,
  cyrb53,
  computeCacheDetails,
  cacheHit,
  isCacheHitStillValid,
  addHoursToDate,
  guessContentType,
  importIntoCache,
} = require('../proxy.js');

after(() => fs.rmSync(tmpCacheDir, { recursive: true, force: true }));

const hoursAgo = hours => new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

const getFreePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });

describe('parseUrlMappings', () => {
  it('parses a sed-style pattern into search regex and replacement', () => {
    const mappings = parseUrlMappings('#https://foo/#https://bar/#');
    assert.strictEqual(mappings.length, 1);
    assert.strictEqual('https://foo/x'.replace(mappings[0].search, mappings[0].replace), 'https://bar/x');
  });

  it('skips empty patterns caused by consecutive spaces', () => {
    const mappings = parseUrlMappings('#a#b#  #c#d#');
    assert.strictEqual(mappings.length, 2);
  });

  it('throws on a pattern whose first and last characters differ', () => {
    assert.throws(() => parseUrlMappings('#a#b'), /Invalid url_rewrite/);
  });
});

describe('mapUrl', () => {
  it('applies all mappings in order', () => {
    const mappings = parseUrlMappings('#one#two# #two-x#three#');
    assert.strictEqual(mapUrl(mappings, 'http://one-x/'), 'http://three/');
  });

  it('returns the url unchanged when nothing matches', () => {
    const mappings = parseUrlMappings('#foo#bar#');
    assert.strictEqual(mapUrl(mappings, 'http://example.com/'), 'http://example.com/');
  });
});

describe('cyrb53', () => {
  it('is deterministic and stable across versions', () => {
    // cache file names depend on this exact value: changing the hash invalidates existing caches
    assert.strictEqual(cyrb53('?a=1&b=2'), 2659796404897999);
  });

  it('differs for different inputs', () => {
    assert.notStrictEqual(cyrb53('?a=1'), cyrb53('?a=2'));
  });
});

describe('computeCacheDetails', () => {
  it('derives the cache file path from proto, host, method and path', () => {
    const { cachedFile } = computeCacheDetails('https', 'GET', 'https://example.com/some/path.txt');
    assert.strictEqual(cachedFile, `${config.cache_dir}/https/example.com/GET/some/path.txt.data`);
  });

  it('stores trailing-slash urls as #index.data', () => {
    const { cachedFile } = computeCacheDetails('https', 'GET', 'https://example.com/dir/');
    assert.strictEqual(cachedFile, `${config.cache_dir}/https/example.com/GET/dir/#index.data`);
  });

  it('hashes query strings into the file name', () => {
    const { cachedFile } = computeCacheDetails('http', 'GET', 'http://example.com/q?a=1&b=2');
    assert.strictEqual(cachedFile, `${config.cache_dir}/http/example.com/GET/q${cyrb53('?a=1&b=2')}.data`);
  });

  it('includes a non-default port in the cache path', () => {
    const { cachedFile } = computeCacheDetails('http', 'GET', 'http://example.com:8081/x');
    assert.strictEqual(cachedFile, `${config.cache_dir}/http/example.com:8081/GET/x.data`);
  });

  it('normalises differently-signed github release asset urls to the same cache file', () => {
    const signed = token =>
      'https://objects.githubusercontent.com/github-production-release-asset-2e65be/123456' +
      `?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${token}` +
      '&response-content-disposition=attachment%3B%20filename%3Dfoo-1.2.3.zip' +
      '&response-content-type=application%2Foctet-stream';
    const a = computeCacheDetails('https', 'GET', signed('tokenA')).cachedFile;
    const b = computeCacheDetails('https', 'GET', signed('tokenB')).cachedFile;
    assert.strictEqual(a, b);
    assert.strictEqual(
      a,
      `${config.cache_dir}/https/objects.githubusercontent.com/GET/github-production-release-asset-kutticache/2e65be/123456/foo-1.2.3.zip.data`
    );
  });
});

describe('isCacheHitStillValid', () => {
  const metaWith = (contentType, cacheDate) => ({
    headers: { 'content-type': contentType },
    statusCode: 200,
    'proxy-kutti-orig-request': { 'cache-date': cacheDate },
  });
  // matches the default registry.npmjs.org /\w+$ rule (24 hour cache_duration)
  const npmMetadataRequest = { host: 'registry.npmjs.org', path: '/lodash' };
  // falls through to the registry.npmjs.org /.* rule (48 hour cache_duration)
  const npmTarballRequest = { host: 'registry.npmjs.org', path: '/lodash/-/lodash-4.17.21.tgz' };

  it('never expires for content types listed in cache_never_expires_for_content_types', () => {
    // regression test: the content type lives under metaData.headers, not at the top level
    const result = isCacheHitStillValid(metaWith('application/zip', hoursAgo(24 * 30)), npmMetadataRequest);
    assert.strictEqual(result.expired, false);
    assert.strictEqual(result.reason, 'never expires for content type');
  });

  it('expires entries older than the matching cache_control rule allows', () => {
    const result = isCacheHitStillValid(metaWith('text/html', hoursAgo(25)), npmMetadataRequest);
    assert.strictEqual(result.expired, true);
    assert.strictEqual(result.reason, 'stale');
  });

  it('keeps entries younger than the matching cache_control rule allows', () => {
    const result = isCacheHitStillValid(metaWith('text/html', hoursAgo(23)), npmMetadataRequest);
    assert.strictEqual(result.expired, false);
    assert.strictEqual(result.reason, 'cache not expired yet');
  });

  it('uses the first matching rule (rule order matters)', () => {
    // 25h old: expired under the 24h /\w+$ rule, but tarball paths skip it and hit the 48h /.* rule
    const result = isCacheHitStillValid(metaWith('text/html', hoursAgo(25)), npmTarballRequest);
    assert.strictEqual(result.expired, false);
    assert.strictEqual(result.reason, 'cache not expired yet');
  });

  it('propagates force_refresh from the matching rule', () => {
    const result = isCacheHitStillValid(
      metaWith('text/html', hoursAgo(48)),
      { host: 'deb.debian.org', path: '/debian/dists/bookworm/InRelease' }
    );
    assert.strictEqual(result.expired, true);
    assert.strictEqual(result.force_refresh, true);
  });

  it('never expires when no cache_control rule matches', () => {
    const result = isCacheHitStillValid(
      metaWith('text/html', hoursAgo(24 * 365)),
      { host: 'example.com', path: '/anything' }
    );
    assert.strictEqual(result.expired, false);
    assert.strictEqual(result.reason, 'no-cache-control');
  });

  it('tolerates meta files without a headers object', () => {
    const result = isCacheHitStillValid(
      { 'proxy-kutti-orig-request': { 'cache-date': hoursAgo(1) } },
      { host: 'example.com', path: '/anything' }
    );
    assert.strictEqual(result.expired, false);
  });
});

describe('addHoursToDate', () => {
  it('adds the given number of hours', () => {
    const date = new Date('2026-01-01T00:00:00Z');
    assert.strictEqual(addHoursToDate(date, 25).toISOString(), '2026-01-02T01:00:00.000Z');
  });
});

describe('cacheHit', () => {
  it('returns null for stale entries that match cache_control', async () => {
    const cachedFile = path.join(tmpCacheDir, 'stale-hit.data');
    const cachedFileMeta = `${cachedFile}.meta`;
    fs.writeFileSync(cachedFile, 'stale-content');
    fs.writeFileSync(
      cachedFileMeta,
      JSON.stringify({
        headers: { 'content-type': 'text/plain' },
        statusCode: 200,
        'proxy-kutti-orig-request': { 'cache-date': hoursAgo(25) },
      })
    );

    const result = await cacheHit({
      host: 'registry.npmjs.org',
      path: '/lodash',
      method: 'GET',
      headers: {},
      state: { cachedFile, cachedFileMeta },
    });
    assert.strictEqual(result, null);
  });

  it('returns an empty body stream for HEAD cache hits', async () => {
    const cachedFile = path.join(tmpCacheDir, 'head-hit.data');
    const cachedFileMeta = `${cachedFile}.meta`;
    fs.writeFileSync(cachedFile, 'should-not-be-read-for-head');
    fs.writeFileSync(
      cachedFileMeta,
      JSON.stringify({
        headers: { 'content-type': 'application/octet-stream' },
        statusCode: 204,
        'proxy-kutti-orig-request': { 'cache-date': hoursAgo(1) },
      })
    );

    const proxyRes = await cacheHit({
      host: 'example.com',
      path: '/head',
      method: 'HEAD',
      headers: {},
      state: { cachedFile, cachedFileMeta },
    });
    assert.notStrictEqual(proxyRes, null);
    assert.strictEqual(proxyRes.statusCode, 204);
    let body = '';
    for await (const chunk of proxyRes) body += chunk;
    assert.strictEqual(body, '');
  });
});

describe('guessContentType', () => {
  it('maps known extensions case-insensitively', () => {
    assert.strictEqual(guessContentType('foo-1.2.3.zip'), 'application/zip');
    assert.strictEqual(guessContentType('FOO.ZIP'), 'application/zip');
    assert.strictEqual(guessContentType('module.tgz'), 'application/gzip');
    assert.strictEqual(guessContentType('index.json'), 'application/json');
  });

  it('falls back to application/octet-stream', () => {
    assert.strictEqual(guessContentType('setup.exe'), 'application/octet-stream');
  });
});

describe('importIntoCache', () => {
  it('rejects with usage info when arguments are missing', async () => {
    await assert.rejects(importIntoCache([]), /Usage: proxy\.js import/);
  });

  it('rejects relative or non-http urls', async () => {
    await assert.rejects(importIntoCache(['/just/a/path', '/tmp/file']), /absolute http\(s\) URL/);
  });

  it('copies the file into the cache and writes a meta file that produces a cache hit', async () => {
    const srcFile = path.join(tmpCacheDir, 'src-asset.zip');
    const body = 'pretend this is a huge release asset';
    fs.writeFileSync(srcFile, body);

    const importUrl = 'https://example.com/releases/download/v1.2.3/src-asset.zip';
    await importIntoCache([importUrl, srcFile]);

    const { cachedFile } = computeCacheDetails('https', 'GET', importUrl);
    assert.strictEqual(fs.readFileSync(cachedFile, 'utf8'), body);

    const metaData = JSON.parse(fs.readFileSync(`${cachedFile}.meta`, 'utf8'));
    assert.strictEqual(metaData.statusCode, 200);
    assert.strictEqual(metaData.headers['content-type'], 'application/zip');
    assert.strictEqual(metaData.headers['content-length'], String(body.length));
    assert.strictEqual(metaData['proxy-kutti-orig-request']['proxy-kutti-imported-from'], srcFile);
    assert.ok(metaData['proxy-kutti-orig-request']['cache-date']);

    // and the proxy's own cacheHit logic must serve it
    const requestDetails = {
      host: 'example.com',
      path: '/releases/download/v1.2.3/src-asset.zip',
      method: 'GET',
      headers: {},
      state: { cachedFile, cachedFileMeta: `${cachedFile}.meta` },
    };
    const proxyRes = await cacheHit(requestDetails);
    assert.notStrictEqual(proxyRes, null);
    assert.strictEqual(proxyRes.statusCode, 200);
    let served = '';
    for await (const chunk of proxyRes) served += chunk;
    assert.strictEqual(served, body);
  });

  it('honours an explicit --content-type override', async () => {
    const srcFile = path.join(tmpCacheDir, 'src-asset.bin');
    fs.writeFileSync(srcFile, 'binary stuff');

    const importUrl = 'https://example.com/downloads/asset.bin';
    await importIntoCache([importUrl, srcFile, '--content-type', 'application/x-mystery']);

    const { cachedFile } = computeCacheDetails('https', 'GET', importUrl);
    const metaData = JSON.parse(fs.readFileSync(`${cachedFile}.meta`, 'utf8'));
    assert.strictEqual(metaData.headers['content-type'], 'application/x-mystery');
  });

  it('supports --content-type=<mime-type> syntax', async () => {
    const srcFile = path.join(tmpCacheDir, 'src-asset-equals.bin');
    fs.writeFileSync(srcFile, 'binary stuff');

    const importUrl = 'https://example.com/downloads/asset-equals.bin';
    await importIntoCache([importUrl, srcFile, '--content-type=application/x-equals']);

    const { cachedFile } = computeCacheDetails('https', 'GET', importUrl);
    const metaData = JSON.parse(fs.readFileSync(`${cachedFile}.meta`, 'utf8'));
    assert.strictEqual(metaData.headers['content-type'], 'application/x-equals');
  });
});

describe('proxy integration cache behavior', () => {
  it('serves identical second request from cache without hitting origin again', { timeout: 15000 }, async () => {
    const integrationCacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-kutti-e2e-'));
    const originPort = await getFreePort();
    const proxyPort = await getFreePort();
    let originRequestCount = 0;
    const originServer = http.createServer((req, res) => {
      originRequestCount++;
      const body = JSON.stringify({ requestCount: originRequestCount, path: req.url });
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
      });
      res.end(body);
    });
    await new Promise(resolve => originServer.listen(originPort, '127.0.0.1', resolve));

    const proxyProcess = spawn('node', ['/tmp/workspace/forkeith/node-proxy-kutti/proxy.js'], {
      cwd: '/tmp/workspace/forkeith/node-proxy-kutti',
      env: {
        ...process.env,
        PROXY_KUTTI_CONFIG: '/nonexistent/proxy-kutti-e2e-config',
        PROXY_KUTTI_host: '127.0.0.1',
        PROXY_KUTTI_port: String(proxyPort),
        PROXY_KUTTI_cache_dir: integrationCacheDir,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const waitForProxyReady = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timed out waiting for proxy to start')), 5000);
      proxyProcess.stdout.on('data', data => {
        if (data.toString().includes('Proxy-kutti is running')) {
          clearTimeout(timeout);
          resolve();
        }
      });
      proxyProcess.on('exit', code => {
        clearTimeout(timeout);
        reject(new Error(`Proxy exited early with code ${code}`));
      });
    });

    const requestViaProxy = pathName =>
      new Promise((resolve, reject) => {
        const req = http.request(
          {
            hostname: '127.0.0.1',
            port: proxyPort,
            method: 'GET',
            path: `http://127.0.0.1:${originPort}${pathName}`,
          },
          res => {
            let body = '';
            res.on('data', chunk => (body += chunk));
            res.on('end', () => resolve({ statusCode: res.statusCode, body }));
          }
        );
        req.setTimeout(3000, () => req.destroy(new Error('Timed out waiting for proxy response')));
        req.on('error', reject);
        req.end();
      });

    try {
      await waitForProxyReady;
      const first = await requestViaProxy('/api/e2e-cache-hit');
      const countAfterFirst = originRequestCount;
      const second = await requestViaProxy('/api/e2e-cache-hit');

      assert.strictEqual(first.statusCode, 200);
      assert.strictEqual(second.statusCode, 200);
      assert.strictEqual(originRequestCount, countAfterFirst);
      assert.strictEqual(
        JSON.parse(first.body).requestCount,
        JSON.parse(second.body).requestCount
      );

      const cachedFile = `${integrationCacheDir}/http/127.0.0.1:${originPort}/GET/api/e2e-cache-hit.data`;
      assert.ok(fs.existsSync(cachedFile));
      assert.ok(fs.existsSync(`${cachedFile}.meta`));
    } finally {
      await new Promise(resolve => originServer.close(resolve));
      const proxyExit = new Promise(resolve => proxyProcess.once('exit', resolve));
      if (proxyProcess.exitCode === null) {
        proxyProcess.kill('SIGTERM');
      }
      await Promise.race([proxyExit, wait(1000)]);
      if (proxyProcess.exitCode === null) {
        proxyProcess.kill('SIGKILL');
        await proxyExit;
      }
      fs.rmSync(integrationCacheDir, { recursive: true, force: true });
    }
  });
});
