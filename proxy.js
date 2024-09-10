#!/usr/bin/env node
/*
 * ഓം ബ്രഹ്മാർപ്പണം
 * proxy.js
 * Created: Sat Mar 21 2020 02:04:37 GMT+0530 (GMT+05:30)
 * Copyright 2020 Harish Karumuthil<harish2704@gmail.com>
 */

const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const util = require('util');
const fsPromise = fs.promises;
const { dirname } = require('path');
const forge = require('node-forge');
const pki = forge.pki;
const tls = require('tls');
const generateKeyPair = util.promisify(require('crypto').generateKeyPair);
const net = require('net');
const os = require('os');
const { Readable } = require('stream')

const hours_in_day = 24;

const log = console.log.bind(console);
const httpsPort = 3110;
const configHome = os.homedir() + '/.config/proxy-kutti';
const configFile = process.env.PROXY_KUTTI_CONFIG || configHome + '/config';
const config = {
  port: 8080,
  host: '127.0.0.1',
  cache_dir: os.homedir() + '/.cache/proxy-kutti',
  root_ca_key: configHome + '/rootCA.key',
  root_ca_cert: configHome + '/rootCA.pem',
  url_rewrites: '#https://pecl.php.nethttps://pecl.php.net/get/#https://pecl.php.net/get/#',
  cache_rewrites: '#https?://(.*)/7.7.1908/#http://mirrors.centos/7.7.1908/# ' +
                  '#https?://(.*)epel/7/x86_64/#http://mirror.epel/7/x86_64/# ' +
                  '#https://objects.githubusercontent.com/github-production-release-asset-(\\w+/\\d+).*&response-content-disposition=attachment%3B%20filename%3D(.*)&response-content-type=application%2Foctet-stream#https://objects.githubusercontent.com/github-production-release-asset-kutticache/$1/$2# ' +
                  '#(https://codeload.github.com/[^/]+/[^/]+/legacy.zip/\w+)?token=\w+#$1# ', // remove token from codeload url for cache
  cache_control: [
    {
      host: 'deb.debian.org',
      path: new RegExp('/debian/dists/.*/InRelease'),
      cache_duration: 1 * hours_in_day,
      force_refresh: true, // server returns 304 not modified despite the content having an expiry date
    }
  ],
  cache_never_expires_for_content_types: [
    "application/vnd.oci.image.index.v1+json",
    "application/zip",
  ],
};

// NOTE: things to check:
// - does it support keep alive? both from clients connecting to the proxy and for outgoing requests?
// - why is it a HTTP 1.0 proxy? does it matter?
// - see other TODO comments

try {
  Object.assign(config, require(configFile));
} catch (e) {}
Object.keys(config).forEach(function(k) {
  config[k] = process.env['PROXY_KUTTI_' + k] || config[k];
});

const urlMappings = parseUrlMappings(config.url_rewrites);
const urlCacheMappings = parseUrlMappings(config.cache_rewrites);

function parseUrlMappings(mappings) {
  return mappings.split(' ').map(function(pattern) {
    if (pattern === '') return null; // skip empty patterns
    if (pattern[0] === pattern.slice(-1)) {
      const [search, replace] = pattern.slice(1, -1).split(pattern[0]);
      return { search: new RegExp(search), replace };
    }
    throw new Error(`Invalid url_rewrite "${pattern}"`);
  }).filter(urlMapping => urlMapping != null);
}


function mapUrl(urlMappings, origUrl) {
  let out = origUrl;

  let i = 0,
    l = urlMappings.length,
    mapping;
  while (i < l) {
    urlMap = urlMappings[i];
    out = out.replace(urlMap.search, urlMap.replace);
    i++;
  }
  return out;
}

const runnninRequests = {};
function untillRequestFinished( cachedFile ){
  return new Promise(res => runnninRequests[ cachedFile ].on('close', res ));
}
function startNewRequest( cachedFile ){
  const stream = fs.createWriteStream( cachedFile );
  runnninRequests[cachedFile] = stream;
  stream.on('close', () => delete runnninRequests[cachedFile] );
  return stream;
}

// https://stackoverflow.com/a/52171480/4473405
const cyrb53 = (str, seed = 0) => {
  let h1 = 0xdeadbeef ^ seed,
    h2 = 0x41c6ce57 ^ seed;
  for (let i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

async function getContent(httpModule, origReq, origRes) {
  const origUrl = url.parse(origReq.url);
  const mappedUrlStr = mapUrl(urlMappings, origReq.url);
  const mappedUrl = url.parse(mappedUrlStr);
  const cacheUrlStr = mapUrl(urlCacheMappings, origReq.url);
  const cacheUrl = url.parse(cacheUrlStr);
  const cachePort = cacheUrl.port ? ':' + cacheUrl.port : '';
  const method = origReq.method;
  const proto = httpModule === http ? 'http':'https';

  // TODO: currently no option to cache separately based on request headers like Accept etc.
  const safe_filepath = cacheUrl.pathname + (cacheUrl.search ? cyrb53(cacheUrl.search) : ''); // TODO: deal with relative paths going up further than they should?
  let cachedFile = `${config.cache_dir}/${proto}/${cacheUrl.host}${cachePort}/${method}${safe_filepath}`;
  if( mappedUrl.path.slice(-1) === '/' ){
    cachedFile += '#index.data';
  } else {
    cachedFile += '.data';
  }
  let proxyRes = null;
  let isHit = '';

  const requestDetails = {
    host: mappedUrl.host ?? origUrl.host,
    port: mappedUrl.port ?? origUrl.port,
    path: mappedUrl.path ?? origUrl.path,
    username: origUrl.username,
    password: origUrl.password,
    method,
    headers: origReq.headers,
    timeout: 1000 * 60 * 30,
    state: {
      cachedFile: cachedFile,
      cachedFileMeta: `${cachedFile}.meta`,
      other: mappedUrlStr,
      origUrl: origReq.url,
    },
  };
  //console.log(requestDetails);


  if( cachedFile in runnninRequests ){
    await untillRequestFinished( cachedFile );
  }
  if (false !== (await fsPromise.access(requestDetails.state.cachedFileMeta).catch(() => false))) {
    proxyRes = await cacheHit(requestDetails);
    if (proxyRes != null) {
      isHit = "Hit!";
    } else {
      isHit = "stale";
    }
  }
  if (proxyRes === null) {
    if (isHit === '')
      isHit = "Miss";
    proxyRes = await cacheMiss(origReq, requestDetails, httpModule, origRes);
  }

  // color ansi escapes https://stackoverflow.com/a/41407246/4473405
  const ansiResetColor = '\x1b[0m';
  const ansiColorRed = '\x1b[31m';
  const ansiColorGreen = '\x1b[32m';
  const ansiColorYellow = '\x1b[33m';
  // TODO: option to show in local time instead of UTC
  // TODO: color hit and miss as well
  let statusText = (proxyRes.statusCode < 300 ? ansiColorGreen : ansiColorRed) + proxyRes.statusCode.toString() + ansiResetColor;
  let cacheText = (isHit == "stale" ? ansiColorYellow : isHit == "Miss" ? ansiColorRed : ansiColorGreen) + isHit + ansiResetColor;
  console.log(`${new Date().toISOString()} ${cacheText} ${method} ${origReq.url} => ${cachedFile.substr(config.cache_dir.length + 1)} (${statusText} ${proxyRes.headers['content-length'] ? (proxyRes.headers['content-length'] / 1024).toFixed(2).toString() + ' KiB' : ''})`);

  origRes.writeHead(proxyRes.statusCode, proxyRes.headers);
  proxyRes.pipe(origRes, {end: true}); // end writer when reader ends
  /**
   *  Don't let download to continue if client closes the connection before it is finished
   */
  origRes.on('close', () => proxyRes.destroy() );
  //origRes.on('close', () => { /*proxyRes.destroy();*/ console.log('client closed connection for ' + origUrl.path); } );

  return proxyRes;
}

async function cacheHit(requestDetails) {
  let proxyRes = requestDetails.method === 'HEAD' ? Readable.from('') : fs.createReadStream(requestDetails.state.cachedFile);
  let metaData = JSON.parse(await fsPromise.readFile(requestDetails.state.cachedFileMeta));
  Object.assign( proxyRes, metaData );

  if (!proxyRes['proxy-kutti-orig-request']) {
    // TODO: remove me. This on only temporary to include request details of previously fulfilled requests before this was tracked
    fsPromise.writeFile(requestDetails.state.cachedFileMeta, JSON.stringify({ ...metaData, 'proxy-kutti-orig-request': { ...requestDetails, 'state': null, 'cache-date': new Date().toISOString(), } } ));
  } else {
    // TODO: update cache access date
    let cache_info = isCacheHitStillValid(metaData, requestDetails);
    if (cache_info.expired) {
      if (!cache_info.force_refresh) {
        // add ETag from previously cached response to request headers
        if (metaData['headers']['etag'] && !requestDetails.headers['if-none-match']) {
          requestDetails.headers['if-none-match'] = metaData['headers']['etag']
        }
        if (metaData['headers']['last-modified'] && !requestDetails.headers['if-modified-since']) {
          requestDetails.headers['if-modified-since'] = metaData['headers']['last-modified']
        }
      }
      return null;
    }

    delete proxyRes['proxy-kutti-orig-request'];
  }
  return proxyRes;
}

function isCacheHitStillValid(metaData, requestDetails) {
  // assume all zip files etc are unchanged
  // TODO: - for the above, check if the url contains a version or not...
  if (config.cache_never_expires_for_content_types.indexOf(metaData["content-type"]) > -1) {
    return {
      expired: false,
      reason: "never expires for content type",
    };
  }

  let now = null;
  for (const item of config.cache_control) {
    if (item.host === requestDetails.host) {
      if (item.path.test(requestDetails.path)) {
        if (!now) {
          now = new Date();
        }
        let cacheDateIsoString = metaData['proxy-kutti-orig-request']['cache-date'];

        let cacheDate = new Date(Date.parse(cacheDateIsoString));
        let expireDate = addHoursToDate(cacheDate, item.cache_duration);
        if (expireDate < now) {
          return {
            expired: true,
            force_refresh: item.force_refresh,
            reason: "stale",
          };
        } else {
          return {
            expired: false,
            force_refresh: item.force_refresh,
            reason: "cache not expired yet",
          }
        }
      }
    }
  }

  return {
    expired: false,
    reason: "no-cache-control",
  };
}

// const parseDate = dateString => {
//   const b = dateString.split(/\D+/);
//   const offsetMult = dateString.indexOf('+') !== -1 ? -1 : 1;
//   const hrOffset = offsetMult * (+b[7] || 0);
//   const minOffset = offsetMult * (+b[8] || 0);  
//   return new Date(Date.UTC(+b[0], +b[1] - 1, +b[2], +b[3] + hrOffset, +b[4] + minOffset, +b[5], +b[6] || 0));
// };

function addHoursToDate(date, hours) {
  return new Date(new Date(date).setHours(date.getHours() + hours));
}

async function cacheMiss(origReq, requestDetails, httpModule, origRes) {
  let proxyRes = await new Promise(res => {
    const proxyReq = httpModule.request(
      requestDetails,
      res
    );
    origReq.pipe( proxyReq );
  });
  await fsPromise.mkdir(dirname(requestDetails.state.cachedFile), { recursive: true });

  /**
   *  write metadata only if the request completed successfully
   *  Otherwise, partial & invalid cached content will be served next time
   */
  origRes.on('finish', () => {
    if (proxyRes.statusCode < 400 && proxyRes.statusCode !== 302 && proxyRes.statusCode !== 307) {// && proxyRes.statusCode != 301) {
      if (proxyRes.statusCode == 304) {
        // not modified...
        // TODO: update cache date
      } else {
        // probably we don't want to cache mutating effects
        // theoretically we could if we wanted to even invalidate the HEAD/GET at the same path...
        if (requestDetails.method != 'POST' && requestDetails.method != 'PUT') {
          writeMetaData(requestDetails, proxyRes);
        }
      }
    }
  });
  // don't update file on disk if we receive a not modified response
  if (proxyRes.statusCode !== 304) {
    proxyRes.pipe( startNewRequest(requestDetails.state.cachedFile));
  }
  // attempt to title-case Location header for PHP Pear
  if (proxyRes.statusCode === 301) {
    proxyRes.headers['Location'] = proxyRes.headers['location'];
    delete proxyRes.headers['location'];
  }

  return proxyRes;
}

function writeMetaData(requestDetails, proxyRes) {
  fsPromise.writeFile(requestDetails.state.cachedFileMeta, JSON.stringify({
    headers: proxyRes.headers,
    statusCode: proxyRes.statusCode,
    'proxy-kutti-orig-request':
      { ...requestDetails, 'cache-date': new Date().toISOString(), 'state': null, 'password': null /* TODO: mask password if wasn't blank for easier debugging */ }
  }));
}


function createFakeCertificateByDomain(caKey, caCert, domain) {
  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;

  cert.serialNumber = new Date().getTime() + '';
  cert.validity.notBefore = new Date();
  cert.validity.notBefore.setFullYear(
    cert.validity.notBefore.getFullYear() - 1
  );
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
  var attrs = [
    {
      name: 'commonName',
      value: domain,
    },
    {
      name: 'organizationName',
      value: 'Proxy-kutti',
    },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(caCert.subject.attributes);

  cert.setExtensions([
    {
      name: 'subjectAltName',
      altNames: [
        {
          type: 2,
          value: domain,
        },
      ],
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
    },
  ]);
  cert.sign(caKey, forge.md.sha256.create());

  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
}


function initHttpsMitmProxy() {
  const caCertPath = config.root_ca_cert;
  const caKeyPath = config.root_ca_key;
  const caCertPem = fs.readFileSync(caCertPath);
  const caKeyPem = fs.readFileSync(caKeyPath);
  const caCert = forge.pki.certificateFromPem(caCertPem);
  const caKey = forge.pki.decryptRsaPrivateKey(caKeyPem, 'secret');
  const fakeCertObj = createFakeCertificateByDomain(caKey, caCert, 'localhost');

  debugger;
  const https_opts = {
    key: fakeCertObj.key,
    cert: fakeCertObj.cert,
    SNICallback: (hostname, done) => {
      let certObj = createFakeCertificateByDomain(caKey, caCert, hostname);
      done(
        null,
        tls.createSecureContext({
          key: certObj.key,
          cert: certObj.cert,
        })
      );
    },
  };


  const httpsProxy = https.createServer(https_opts, (req, res) => {
    req.url = `https://${req.headers.host}${req.url}`;
    getContent(https, req, res);
  });

  httpsProxy.listen( httpsPort, '127.0.0.1');
}


function main() {
  const httpProxy = http.createServer(getContent.bind(null, http));

  const isHttpMitmEnabled =
    fs.existsSync(config.root_ca_cert) && fs.existsSync(config.root_ca_key);
  let httpsMsg = '';
  if (isHttpMitmEnabled === false) {
    httpsMsg = `https requests are not cached since it is not configured.
  Make sure that the files
    ${config.root_ca_cert}
    ${config.root_ca_key}
  exists and accessible to the process.
  Refer documentation more details.\n`;
  } else {
    initHttpsMitmProxy();
  }

  const util = require('util');
  httpProxy.on('connect', function(req, res) {
    res.write(
      // TODO: why HTTP/1.0 here?
      'HTTP/1.0 200 Connection established\r\nProxy-agent: proxy-kutti\r\n\r\n'
    );
    const [host, port] = isHttpMitmEnabled
      ? ['127.0.0.1',  httpsPort]
      : req.url.split(':');
    var httpsProxyConnection = net.createConnection(port, host);
    res.on('close', () => res.unpipe( httpsProxyConnection ));
    res.on('error', () => res.unpipe( httpsProxyConnection ));
    res.pipe(httpsProxyConnection);
    httpsProxyConnection.pipe(res);
  });

  httpProxy.listen(config.port, config.host, function() {
    log(`Proxy-kutti is running...

Using env variables
  PROXY_KUTTI_CONFIG=${configFile}

Current Configuration ( edit ${configFile}.(json|js)  or set env variable PROXY_KUTTI_<config-key>=<value> to change )
${JSON.stringify(config, null, 2).slice(2, -2)}

${httpsMsg}
Run the following command shell to start using this proxy
  export http_proxy=http://${config.host}:${config.port}
  ${isHttpMitmEnabled? 'export https_proxy=http://'+config.host+':'+httpsPort: ''}

  `);
  });
}

if (require.main === module) {
  main();
  process.on('uncaughtException', function (err) {
    log(err);
  })
}
