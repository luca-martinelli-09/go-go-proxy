# 🚀 Go API Proxy with Caching, Logging, and Browser Checks

A secure, rate-limited, and cache-aware HTTP reverse proxy for APIs, written in Go. Supports Redis caching, advanced access control (API keys, origin/browsers checks), and pluggable logging.

---

## Features

- 🔑 **API Key Authentication:** Each request must include a valid API Key name in a header.
- ⏳ **Rate Limiting:** Prevent abuse by limiting requests per minute per API key.
- 💾 **Redis Caching:** Responses from target APIs can be cached in Redis using a unique key per combination of request.
- ⚡ **Detailed Logging:** Rotating log files with contextual emojis for different event types.
- 🌍 **Origin Restriction:** Restrict allowed origins via regular expression.
- 🛡️ **Browser/Heuristic Checks:** Make sure only real browsers can use the proxy (optional).
- 🧩 **Configurable via .env:** All settings and secrets are environment-based.

---

## How it Works

1. **Incoming Client Request:**  
   - Client sends `/proxy?url=<target_url>` with a `X-Api-Key-Name` header.
2. **Origin & Browser Checks:**  
   - Origin header gets validated against a regex.
   - Optionally, browser headers are checked (e.g., User-Agent).
3. **Rate Limiting (Redis):**  
   - Each API key is ratelimited using Redis; abusive IPs get `429 Too Many Requests`.
4. **Caching (Redis):**  
   - For eligible requests (GET or as configured), results are cached based on method+url+body+apikey.
   - If enabled, next call will hit Redis cache (fast!)
5. **Proxying:**  
   - The original request is sent to the upstream API, passing appropriate headers and API key.
   - The response is forwarded to the client (and optionally cached).
6. **Logging:**  
   - All steps are logged with contextual emojis to both stdout and file (with rotation).

---

## Configuration

Use the provided `.env` file (see below) and/or environment variables.

### Sample `.env`

```ini
# API KEYS (required)
API_KEY_SERVICE_A=your_actual_api_key
API_KEY_SERVICE_B=your_actual_api_key

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

## Usage

### 🚦 Start with Docker Compose (recommended)

```bash
docker-compose up --build
```

This will:
- Build and run the proxy as `appuser` for security
- Expose the port (default 8080)
- Start Redis for caching/rate-limiting
- Persist logs to the `./logs` directory on your host

### 🛠️ Manual Local Run

> Make sure you have Redis running if you enable cache/rate-limit!

```bash
go build -o proxy-server .
./proxy-server
```

---

## API Usage Example

**Endpoint:** `POST/GET /proxy?url=<target_api_url>`

**Headers:**
  - `X-Api-Key-Name: <your_api_key_name>`
  - _(Optional)_ `X-Proxy-Use-Cache: false` to bypass cache for this request

**Example cURL:**
```bash
curl -H "X-Api-Key-Name: SERVICE_A" \
     "http://localhost:8080/proxy?url=https://api.example.com/endpoint"
```

**Response:**
- Returns proxied API response, with original headers (except for a few hop-by-hop).

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

---

## Troubleshooting

**Logs not created in Docker**
- Check `logs` volume is mapped and user permissions allow `appuser` to write.
- See `docker-compose.yml` for `user:` override if needed.

**Rate limit not working**
- Ensure Redis is running and available under the configured network/hostname.

**Upstream errors**
- The proxy returns `502 Bad Gateway` if the target API does not respond. Check target URL and your API keys.

---

## Security Notes

- Never commit real API keys to source code. Use `.env` files and secrets management.
- The browser and origin checks help prevent unwanted abuse from unapproved scripts or servers.
- Do not expose your proxy to the Internet without proper CORS and security configuration!

---

## Contributing

Pull requests are welcome! Feel free to open [issues](https://github.com/yourusername/yourrepo/issues) or suggest features.

---

## License

MIT

---

**Happy proxying!** 🚀