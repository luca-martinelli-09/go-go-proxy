# 🚀 Go Go Proxy | API Proxy with Caching, Logging, JWT Authorization, and Browser Checks

[![Docker Hub](https://img.shields.io/docker/pulls/lucamartinelli9/go-go-proxy.svg)](https://hub.docker.com/r/lucamartinelli9/go-go-proxy)

A secure, rate-limited, and cache-aware HTTP reverse proxy for APIs, written in Go. Supports Redis caching, advanced access control (API keys, JWT, origin/browsers checks), and pluggable logging.

---

## Features

- 🔑 **API Key Authentication:** Each request must include a valid API Key name in a header.
- 🏷️ **Flexible API Key Placement:** Add your API key as a query param or custom header per request (see below).
- 🔒 **Optional JWT Authentication:** Protect your proxy endpoint with JWT, with support for custom issuer regex.
- ⏳ **Rate Limiting:** Prevent abuse by limiting requests per minute per API key.
- 💾 **Redis Caching:** Responses from target APIs can be cached in Redis using a unique key per combination of request.
- ⚡ **Detailed Logging:** Rotating log files with contextual emojis for different event types.
- 🌍 **Origin Restriction:** Restrict allowed origins via regular expression.
- 🛡️ **Browser/Heuristic Checks:** Make sure only real browsers can use the proxy (optional).
- 🧩 **Configurable via .env:** All settings and secrets are environment-based.

---

## How it Works

1. **Incoming Client Request:**
   - Client sends `/proxy?url=<target_url>` with a `X-Proxy-Api-Key-Name` header (and optionally custom API-key-placement headers).
2. **(Optional) JWT Authorization:**
   - If enabled, requests must supply a signed JWT in the `X-Proxy-Authorization` header.
3. **Origin & Browser Checks:**
   - Origin header gets validated against a regex.
   - Optionally, browser headers are checked (e.g., User-Agent).
4. **Rate Limiting (Redis):**
   - Each API key is ratelimited using Redis; abusive IPs get `429 Too Many Requests`.
5. **Caching (Redis):**
   - For eligible requests (GET or as configured), results are cached based on method+url+body+apikey.
   - If enabled, next call will hit Redis cache (fast!)
6. **Proxying:**
   - The original request is sent to the upstream API, passing appropriate headers and API key (as header or query).
   - The response is forwarded to the client (and optionally cached).
7. **Logging:**
   - All steps are logged with contextual emojis to both stdout and file (with rotation).

---

## Configuration

Use `.env` and environment variables.

### Sample `.env`

```ini
# API KEYS (required)
API_KEY_SERVICE_A=your_actual_api_key
API_KEY_SERVICE_B=your_actual_api_key

# JWT AUTH (optional)
JWT_SECRET=your_jwt_secret_here
# Optional JWT issuer regex (ex. trusted_issuer|my-org.*)
JWT_ISSUER_REGEX=trusted_issuer

# Redis config
REDIS_ENABLED=true
REDIS_ADDR=redis:6379
REDIS_PASSWORD=
REDIS_DB=0

# Caching
CACHE_TTL_SECONDS=300

# Rate limit per key
RATE_LIMIT_PER_MINUTE=10

# Origin security (regex)
ALLOWED_ORIGINS_REGEX=^https?:\/\/(localhost(:[0-9]+)?|([a-zA-Z0-9-]+\.)?example\.com)$

# Logging
LOG_FILE_PATH=./logs/access.log
LOG_MAX_SIZE_MB=100
LOG_MAX_BACKUPS=3
LOG_MAX_AGE_DAYS=28

# Browser/heuristics
ENFORCE_BROWSER_CHECK=false
STRICT_USER_AGENT_CHECK=true

# Server
SERVER_PORT=8080
TIMEOUT_SECONDS=30
```

---

## CORS Configuration

You can control allowed CORS origins using environment variables:

- **ALLOWED_ORIGINS**: A comma-separated list of allowed hostnames (for example: `localhost`, `example.com`). This global setting applies if no service-specific variable is provided.
- **ALLOWED_ORIGINS_<SERVICE_HOST>**: A comma-separated list of hostnames for a specific upstream service, where `<SERVICE_HOST>` is the target hostname with dots replaced by underscores and uppercase. For example:
  ```
  ALLOWED_ORIGINS_COMUNE_SONA_VR_IT=localhost,comune.sona.vr.it
  ```
  This service-specific variable takes precedence over `ALLOWED_ORIGINS`.
- If neither `ALLOWED_ORIGINS_<SERVICE_HOST>` nor `ALLOWED_ORIGINS` is set, the proxy will default to `*` (allow all origins).

The proxy uses this configuration in its CORS middleware to set the `Access-Control-Allow-Origin` header on all `/proxy` responses.

### CORS Middleware Logging

The CORS middleware emits detailed log messages at various stages to help diagnose origin-allow rules:

- 🌐 `CORS start | Origin: <origin> | APIKeyName: <key>`: when CORS handling begins for a request.
- 🔑 `CORS service-specific var ALLOWED_ORIGINS_<SERVICE>=<value>`: when a service-specific env var is read.
- 🌍 `CORS global var ALLOWED_ORIGINS=<value>`: when falling back to the global origins list.
- 🌍 `CORS fallback to wildcard '*'`: when defaulting to allow all origins.
- ✅ `CORS allow all origins (*)`: when wildcard (`*`) is set.
- ✅ `CORS origin allowed: <origin> (host <host>) in <list>`: when a specific origin matches the allowed list.
- ⚠️ `CORS origin denied: <origin> not in allowed list <list>`: when a specific origin is not permitted.

## Usage

### 🐳 Run with Docker Hub Image

You can run `Go Go Proxy` without building from source, using the official image:

```bash
docker run --rm \
    -p 8080:8080 \
    -v $PWD/.env:/app/.env \
    -v $PWD/logs:/app/logs \
    lucamartinelli9/go-go-proxy
```

- Make sure to have your `.env` file in the current directory with all required keys.
- The `logs` directory will be created if it doesn't exist, and log files are rotated in there.

### 🚦 Or Start with Docker Compose (recommended for production/dev)

```bash
docker-compose up --build
```

- Builds and runs as `appuser` (security best-practices)
- Exposes the port (default 8080)
- Starts Redis for caching/rate-limiting
- Logs are persisted at `./logs`

### 🛠️ Manual Local Run

> Make sure you have Redis running if you enable cache/rate-limit!

```bash
go build -o proxy-server .
./proxy-server
```

---

## API Usage Example

**Endpoint:** `POST/GET /proxy?url=<target_api_url>`

**Mandatory Headers:**
  - `X-Proxy-Api-Key-Name: <your_api_key_name>`

**Optional headers for advanced features:**
  - `X-Proxy-Authorization: Bearer <jwt>` &mdash; for JWT-authenticated endpoints (enabled with `JWT_SECRET`)
  - `X-Proxy-Use-Cache: false` &mdash; disables cache for this request
  - `X-Proxy-Api-Query: <queryparam>` &mdash; **places API key as query parameter** (`?{queryparam}=your_key`)
  - `X-Proxy-Api-Header: <header_name>` &mdash; **places API key as a custom request header**
      - By default, will use value: `Authorization`
  - `X-Proxy-Api-Header-Type: <prefix>` &mdash; (default void) set a value prefix; e.g., `Bearer <key>`, `Token <key>` or just key.

**Examples:**

- _Default (API key as bearer header):_
    ```bash
    curl -H "X-Proxy-Api-Key-Name: SERVICE_A" \
         "http://localhost:8080/proxy?url=https://api.example.com/endpoint"
    ```
- _API key as custom query:_
    ```bash
    curl -H "X-Proxy-Api-Key-Name: SERVICE_A" \
         -H "X-Proxy-Api-Query: apikey" \
         "http://localhost:8080/proxy?url=https://api.example.com/endpoint"
    # → results in .../endpoint?apikey=your_actual_key
    ```
- _API key as custom header with custom prefix:_
    ```bash
    curl -H "X-Proxy-Api-Key-Name: SERVICE_B" \
         -H "X-Proxy-Api-Header: X-My-Service-Api-Token" \
         -H "X-Proxy-Api-Header-Type: Token" \
         "http://localhost:8080/proxy?url=https://api.example.com/endpoint"
    # → header sent: X-My-Service-Api-Token: Token your_actual_key
    ```
- _JWT protected usage:_
    ```bash
    curl -H "X-Proxy-Api-Key-Name: SERVICE_B" \
         -H "X-Proxy-Authorization: Bearer <JWT>" \
         "http://localhost:8080/proxy?url=https://api.example.com/endpoint"
    # (requires valid JWT if configured)
    ```

**Response:**
- Returns proxied API response, with original headers (except for a few hop-by-hop).

---

## JWT Authorization

Enable JWT protection for the `/proxy` endpoint by specifying:

- `JWT_SECRET` in your `.env` (HS256, base64/hex/random string recommended)
- Optionally, `JWT_ISSUER_REGEX` to restrict `iss` claim

**Requests must then include:**

- `X-Proxy-Authorization: Bearer <jwt>`

JWTs are validated via `HS256`, checked for expiry/not-before, and (optionally) checked against issuer regex and user claims.

---

## Logging

- All INFO logs use beautiful context-specific emojis:
  - 🚀: Startup, ready
  - 🔑: API key loading
  - 🟢: Health checks, Redis OK
  - ⚙️: Configuration events
  - 📥: Incoming request
  - 📤: Outgoing response
  - 💾: Cache hit
  - 📭: Cache miss
  - 📝: Cache write
  - 📂: Directory created
  - 🧩: Fallback/defaults
  - 🛡️: Security module
- WARNING: ⚠️
- ERROR: 🛑

Logs go to stdout **and** a rotating file at the configured location; see the `logs/` directory.

---

## Environment Setup Advice

- **Ensure `logs/` directory is writable by your Docker user.**
  - On Linux: `mkdir -p logs && chmod 777 logs`
- **If you use Docker,** the user `appuser` must match volume permissions. See FAQ/troubleshooting below.

---

## Advanced Options

- **Browser-Checking:** Set `ENFORCE_BROWSER_CHECK=true` to allow only real browsers.
- **Origin Restriction:** Regex allows you to lock requests to only authorized client domains.
- **Toggle Caching per Request:** Use `X-Proxy-Use-Cache: false` header to skip cache.
- **Flexible API Key Placement:**
    - Place API key as a query with `X-Proxy-Api-Query: <param>`
    - Or as a custom header with `X-Proxy-Api-Header` and prefix `X-Proxy-Api-Header-Type`
    - Defaults to `Authorization: Bearer ...` if not overridden.
- **JWT Authorization:** Protect proxy endpoint; see section above.

---

## Troubleshooting

**Logs not created in Docker**
- Check `logs` volume is mapped and user permissions allow `appuser` to write.
- See `docker-compose.yml` for `user:` override if needed.

**Rate limit not working**
- Ensure Redis is running and available under the configured network/hostname.

**JWT issues**
- Ensure correct `JWT_SECRET` is set and HS256 tokens are used; check issuer patterns if needed.

**Upstream errors**
- The proxy returns `502 Bad Gateway` if the target API does not respond. Check target URL and your API keys.

---

## Security Notes

- Never commit real API keys to source code. Use `.env` files and secrets management.
- The browser and origin checks help prevent unwanted abuse from unapproved scripts or servers.
- Do not expose your proxy to the Internet without proper CORS and security configuration!
- With JWT enabled, the proxy only accepts requests from correct JWT holders—recommended for B2B or in-house APIs.

---

## Contributing

Pull requests are welcome! Feel free to open [issues](https://github.com/luca-martinelli-09/go-go-proxy/issues) or suggest features.

---

## License

MIT

---

**Happy proxying!** 🚀
