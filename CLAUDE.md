# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Proxy-kutti is a caching forward proxy server (fork of harish2704/node-proxy-kutti) used to speed up package-manager downloads (npm, NuGet, composer, apt, pecl, golang modules, GitHub release assets, etc.), especially during container builds. The entire application is a single file: `proxy.js`. The only runtime dependency is `node-forge` (for generating fake certificates for HTTPS MITM).

## Commands

```sh
npm install                                      # or yarn install
NODE_TLS_REJECT_UNAUTHORIZED=0 node proxy.js     # run locally
node proxy.js import <url> <file> [--content-type <mime>]  # manually add a downloaded file to the cache
npm test                                         # run tests (node:test, no dependencies)
```

The `import` subcommand exists for downloads that time out through the proxy (huge GitHub release assets during docker builds): download the file out-of-band, then import it using the URL from the `Miss` log line. It derives the cache path via the same `computeCacheDetails`/`cache_rewrites` logic as the live proxy and synthesizes the `.meta` file so the next request is a cache hit.

Tests use the built-in `node:test` runner (no extra dependencies), live in `test/`, and run with `npm test`. They require `proxy.js` as a module (exports at the bottom of the file) and must set `PROXY_KUTTI_CONFIG` and `PROXY_KUTTI_cache_dir` env vars *before* the require, since config is resolved at module load time. There is no linter and no build step. Prettier config exists (`.prettierrc.js`: 2-space indent, single quotes, semicolons, es5 trailing commas).

Configuration is loaded from `~/.config/proxy-kutti/config` (overridable via `PROXY_KUTTI_CONFIG`), and any individual config key can be overridden with a `PROXY_KUTTI_<key>` env var. Defaults live in the `config` object at the top of `proxy.js`.

## Architecture

Two servers run side by side:

- **HTTP proxy** on `config.port` (default 8080): a plain `http.createServer` whose handler is `getContent`. Its `connect` event handler tunnels CONNECT requests — to the local MITM server when root CA files exist, otherwise straight through to the origin (uncached).
- **HTTPS MITM server** on port 3110 (hardcoded `httpsPort`, localhost only): an `https.createServer` that mints per-hostname fake certificates on the fly via `SNICallback` (`createFakeCertificateByDomain`), signed by the root CA at `config.root_ca_cert`/`config.root_ca_key`. The CA private key is decrypted with the hardcoded passphrase `'secret'`. HTTPS caching is only enabled if both CA files exist at startup.

### Request flow (`getContent`)

1. The request URL is run through two independent rewrite pipelines (`parseUrlMappings` / `mapUrl`, sed-style `#search#replace#` patterns, space-separated):
   - `url_rewrites` — changes where the upstream request is actually sent.
   - `cache_rewrites` — changes only the cache key (e.g. stripping auth tokens, signatures, and random query params from GitHub/NuGet/golang URLs so equivalent downloads share a cache entry).
2. The cache file path is derived from the (cache-rewritten) URL: `<cache_dir>/<proto>/<host>/<METHOD><path>.data`, with query strings hashed via `cyrb53` and trailing-slash URLs stored as `#index.data`. Each `.data` file has a sibling `.meta` JSON file holding response headers, status code, and the original request + cache date.
3. Concurrent requests for the same cache file are serialized via the `runnninRequests` map — later requests wait for the in-flight download's write stream to close.
4. `cacheHit` serves from disk if a `.meta` file exists and `isCacheHitStillValid` says the entry hasn't expired; otherwise it returns `null` and `cacheMiss` forwards the request upstream, streams the response to the client and to the cache file simultaneously, and writes `.meta` only when the response completed successfully (status < 400, not a 302/307 redirect, not POST/PUT). A 304 response just refreshes the cache date in `.meta` without rewriting the data file.

### Cache expiry

By default the cache never expires. Expiry is opt-in through `config.cache_control`: an ordered list of `{host, path-regex, cache_duration (hours), force_refresh}` rules — first match wins. `cache_never_expires_for_content_types` short-circuits expiry entirely for listed content types (zips, OCI image indexes). Log lines show `Hit!` (green), `stale` (yellow, expired entry being refetched), or `Miss` (red).

## Notes

- HTTPS MITM requires a root CA — see README for openssl generation/renewal steps and trust-store installation.
- `proxifier profile.ppx` is a Proxifier profile for routing Windows client traffic through the proxy; profiles live in `C:\Users\KeithDavidHall\AppData\Roaming\Proxifier4\Profiles`.
- Known open questions are tracked in the `NOTE`/`TODO` comments in `proxy.js` (keep-alive support, HTTP/1.0 CONNECT response, ETag/If-None-Match reconciliation on stale hits).
