package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Config struct {
	ServerPort           string
	APITokens            map[string]string
	RedisEnabled         bool
	RedisAddr            string
	RedisPassword        string
	RedisDB              int
	CacheTTL             time.Duration
	RateLimitPerMinute   int64
	AllowedOriginsRegex  *regexp.Regexp
	LogFilePath          string
	LogMaxSizeMB         int
	LogMaxBackups        int
	LogMaxAgeDays        int
	LogCompress          bool
	EnforceBrowserCheck  bool
	StrictUserAgentCheck bool
	Timeout              time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
}

type CachedResponse struct {
	StatusCode int                 `json:"statusCode"`
	Body       []byte              `json:"body"`
	Headers    map[string][]string `json:"headers"`
}

const (
	LogInfo    = "INFO"
	LogWarning = "WARNING"
	LogError   = "ERROR"

	HeaderApiKeyName    = "X-Api-Key-Name"
	QueryParamTargetURL = "url"
	HeaderProxyUseCache = "X-Proxy-Use-Cache"
)

var (
	appConfig *Config
	rdb       *redis.Client
	logger    *log.Logger
	once      sync.Once
)

// logMsg logs a formatted message with a specified log level and emoji.
// It uses the global logger if initialized, otherwise it defaults to the standard
// log package. The message is constructed by formatting the input string with
// the provided arguments.
//
// Parameters:
//   - level: The log level (e.g., INFO, WARNING, ERROR).
//   - emoji: An emoji symbol to be prefixed to the log message.
//   - format: A format string for the log message.
//   - args: Additional arguments to format the message string.

func logMsg(level, emoji string, format string, args ...interface{}) {
	msg := fmt.Sprintf("%s %s | %s", emoji, level, fmt.Sprintf(format, args...))
	if logger == nil {
		log.Printf(msg)
	} else {
		logger.Output(3, msg)
	}
}

// loadConfig initializes the application configuration based on environment
// variables. It loads the API keys from environment variables starting with
// API_KEY_, and sets up Redis connection details and the logger based on the
// configuration. It also sets the allowed origins regex if specified. If Redis
// is enabled, it sets the Redis DB number and logs the Redis connection details.
// If API keys are not found, it logs a warning. If the allowed origins regex is
// not set, it logs a warning. It also logs the configuration details, such as
// the server port, Redis connection details, logger settings, and rate limits.
func loadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Printf("🛑 ERROR | Failed to load .env file")
	}

	appConfig = &Config{
		ServerPort:           getEnv("SERVER_PORT", "8080"),
		APITokens:            make(map[string]string),
		RedisEnabled:         getEnvAsBool("REDIS_ENABLED", true),
		RedisAddr:            getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:        getEnv("REDIS_PASSWORD", ""),
		CacheTTL:             time.Duration(getEnvAsInt("CACHE_TTL_SECONDS", 300)) * time.Second,
		RateLimitPerMinute:   getEnvAsInt64("RATE_LIMIT_PER_MINUTE", 60),
		LogFilePath:          getEnv("LOG_FILE_PATH", "./logs/access.log"),
		LogMaxSizeMB:         getEnvAsInt("LOG_MAX_SIZE_MB", 100),
		LogMaxBackups:        getEnvAsInt("LOG_MAX_BACKUPS", 3),
		LogMaxAgeDays:        getEnvAsInt("LOG_MAX_AGE_DAYS", 28),
		LogCompress:          getEnvAsBool("LOG_COMPRESS", true),
		EnforceBrowserCheck:  getEnvAsBool("ENFORCE_BROWSER_CHECK", false),
		StrictUserAgentCheck: getEnvAsBool("STRICT_USER_AGENT_CHECK", true),
		Timeout:              time.Duration(getEnvAsInt("TIMEOUT_SECONDS", 30)) * time.Second,
		ReadTimeout:          time.Duration(getEnvAsInt("READ_TIMEOUT_SECONDS", 14)) * time.Second,
		WriteTimeout:         time.Duration(getEnvAsInt("WRITE_TIMEOUT_SECONDS", 45)) * time.Second,
		IdleTimeout:          time.Duration(getEnvAsInt("IDLE_TIMEOUT_SECONDS", 120)) * time.Second,
	}

	if appConfig.RedisEnabled {
		log.Printf("🟢 INFO | Redis is enabled")
		redisDB, err := strconv.Atoi(getEnv("REDIS_DB", "0"))
		if err != nil {
			log.Printf("🛑 ERROR | Invalid REDIS_DB: %v", err)
			os.Exit(1)
		}
		appConfig.RedisDB = redisDB
	} else {
		log.Printf("🟢 INFO | Redis is disabled")
	}

	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if strings.HasPrefix(pair[0], "API_KEY_") {
			keyName := strings.TrimPrefix(pair[0], "API_KEY_")
			appConfig.APITokens[keyName] = pair[1]
			log.Printf("🔑 INFO | Loaded API key for %s", keyName)
		}
	}
	if len(appConfig.APITokens) == 0 {
		log.Printf("⚠️ WARNING | No API keys found in environment")
	}

	regexStr := getEnv("ALLOWED_ORIGINS_REGEX", "")
	if regexStr != "" {
		var err error
		appConfig.AllowedOriginsRegex, err = regexp.Compile(regexStr)
		if err != nil {
			log.Printf("🛑 ERROR | Invalid regular expression for ALLOWED_ORIGINS_REGEX: %v", err)
			os.Exit(1)
		}
		log.Printf("⚙️ INFO | Compiled allowed origins regex: %s", regexStr)
	} else {
		log.Printf("⚠️ WARNING | ALLOWED_ORIGINS_REGEX not set")
	}

	if appConfig.EnforceBrowserCheck {
		log.Printf("🛡️ INFO | Heuristic browser check ENABLED")
		if appConfig.StrictUserAgentCheck {
			log.Printf("🛡️ INFO | Strict User-Agent verification ENABLED")
		}
	} else {
		log.Printf("🛡️ INFO | Heuristic browser check DISABLED")
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if value, err := strconv.Atoi(getEnv(key, "")); err == nil {
		return value
	}
	return fallback
}

func getEnvAsInt64(key string, fallback int64) int64 {
	if value, err := strconv.ParseInt(getEnv(key, ""), 10, 64); err == nil {
		return value
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	valStr := strings.ToLower(getEnv(key, ""))
	if valStr == "true" || valStr == "1" {
		return true
	}
	if valStr == "false" || valStr == "0" {
		return false
	}
	return fallback
}

// initLogger sets up the logger and enables logging to a file.
// It will create the log directory if it does not exist, and
// configure the logger to rotate the log file based on the
// configured maximum size, maximum number of backups, and
// maximum age. It also sets up a multi-writer to log to both
// stdout and the file.
func initLogger() {
	logDir := filepath.Dir(appConfig.LogFilePath)
	if logDir != "" && logDir != "." {
		if _, err := os.Stat(logDir); os.IsNotExist(err) {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				log.Fatalf("🛑 ERROR | Cannot create log directory: %v", err)
			} else {
				log.Printf("📂 INFO | Created log directory: %s", logDir)
			}
		}
	}
	lj := &lumberjack.Logger{
		Filename:   appConfig.LogFilePath,
		MaxSize:    appConfig.LogMaxSizeMB,
		MaxBackups: appConfig.LogMaxBackups,
		MaxAge:     appConfig.LogMaxAgeDays,
		Compress:   appConfig.LogCompress,
		LocalTime:  true,
	}
	mw := io.MultiWriter(os.Stdout, lj)
	logger = log.New(mw, "", log.LstdFlags)
	log.SetOutput(mw)
	logMsg(LogInfo, "⚙️", "Logger initialized at path %s", appConfig.LogFilePath)
}

// initRedis initializes a Redis client connection based on the configuration.
// It returns a non-nil error if the connection cannot be established.
func initRedis() {
	if !appConfig.RedisEnabled {
		rdb = nil
		return
	}
	rdb = redis.NewClient(&redis.Options{Addr: appConfig.RedisAddr, Password: appConfig.RedisPassword, DB: appConfig.RedisDB})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		logMsg(LogError, "🛑", "Cannot connect to Redis: %v", err)
		rdb = nil
	} else {
		logMsg(LogInfo, "🟢", "Connected to Redis")
	}
}

// getClientIP returns the client's IP address as a string.
//
// First, it tries to get the IP from the X-Forwarded-For header. If the header is not present,
// it tries to get the IP from the X-Real-IP header. If both headers are not present, it falls
// back to the RemoteAddr field of the http.Request.
func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return strings.TrimSpace(ip)
	}
	ipOnly, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ipOnly
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.bytesWritten += n
	return n, err
}

// loggingMiddleware is a middleware function that logs the start and end of every
// request, along with important request metadata such as the target URL, API
// key name, and use cache header. The log messages are formatted as
// "REQ_INIT" and "REQ_DONE" respectively, with fields separated by '|'.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		clientIP := getClientIP(r)
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		targetURLForLog := r.URL.Query().Get(QueryParamTargetURL)
		apiKeyNameForLog := r.Header.Get(HeaderApiKeyName)
		useCacheForLog := r.Header.Get(HeaderProxyUseCache)

		logMsg(LogInfo, "📥", "REQ_INIT | %s | ClientIP: %s | Method: %s | Path: %s | TargetURL: %s | APIKeyName: %s | UseCacheHdr: [%s] | UserAgent: %s",
			startTime.Format(time.RFC3339), clientIP, r.Method, r.URL.Path, targetURLForLog, apiKeyNameForLog, useCacheForLog, r.UserAgent(),
		)

		next.ServeHTTP(lrw, r)

		duration := time.Since(startTime)
		requestHeadersJSON, _ := json.Marshal(r.Header)
		logMsg(LogInfo, "📤", "REQ_DONE | %s | ClientIP: %s | Method: %s | Path: %s | TargetURL: %s | APIKeyName: %s | UseCacheHdr: [%s] | Status: %d | Duration: %s | RespBytes: %d | UserAgent: %s | RequestHeaders: %s",
			startTime.Format(time.RFC3339), clientIP, r.Method, r.URL.Path, targetURLForLog, apiKeyNameForLog, useCacheForLog,
			lrw.statusCode, duration, lrw.bytesWritten, r.UserAgent(), string(requestHeadersJSON),
		)
	})
}

// originValidationMiddleware is a middleware function that validates the
// Origin header of incoming HTTP requests against a configured list of allowed
// origins. If the Origin header is empty or does not match the allowed origins
// regex, it logs a warning and responds with a 403 Forbidden status. If the
// allowed origins regex is not set in the configuration, it allows all origins.
// This middleware is useful for enforcing CORS policies by ensuring that only
// requests from specified origins are processed by the server.
func originValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if appConfig.AllowedOriginsRegex != nil {
			if origin == "" || !appConfig.AllowedOriginsRegex.MatchString(origin) {
				logMsg(LogWarning, "⚠️", "Origin not allowed: %s (ClientIP: %s)", origin, getClientIP(r))
				http.Error(w, fmt.Sprintf("Origin %s is not permitted", origin), http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// browserCheckMiddleware is a middleware function that checks if the request is
// likely to originate from a real web browser. It performs the following checks:
//   - Checks if the User-Agent header is present and does not contain known bot
//     or tool signatures.
//   - Checks if the User-Agent header appears to be a real browser, if the
//     `StrictUserAgentCheck` config option is enabled.
//   - Checks if the Accept and Accept-Language headers are present.
//   - Checks if the Sec-Fetch-Site header is present if the request has an
//     Origin header, if the `AllowedOriginsRegex` config option is set.
//
// If any of the checks fail, it returns a 403 Forbidden response.
func browserCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !appConfig.EnforceBrowserCheck {
			next.ServeHTTP(w, r)
			return
		}

		userAgent := r.Header.Get("User-Agent")
		acceptHeader := r.Header.Get("Accept")
		acceptLangHeader := r.Header.Get("Accept-Language")
		secFetchSite := r.Header.Get("Sec-Fetch-Site")

		if userAgent == "" {
			logMsg(LogWarning, "⚠️", "BrowserCheck: missing User-Agent (ClientIP: %s)", getClientIP(r))
			http.Error(w, "Forbidden: missing User-Agent", http.StatusForbidden)
			return
		}
		knownBotsOrTools := []string{"curl/", "PostmanRuntime/", "python-requests", "Java/", "Apache-HttpClient/", "Go-http-client", "Wget"}
		for _, botString := range knownBotsOrTools {
			if strings.HasPrefix(userAgent, botString) {
				logMsg(LogWarning, "⚠️", "BrowserCheck: suspicious User-Agent (%s) (ClientIP: %s)", userAgent, getClientIP(r))
				http.Error(w, "Forbidden: unsupported client", http.StatusForbidden)
				return
			}
		}
		if appConfig.StrictUserAgentCheck {
			isLikelyBrowser := strings.Contains(userAgent, "Mozilla/") || strings.Contains(userAgent, "AppleWebKit/") ||
				strings.Contains(userAgent, "Chrome/") || strings.Contains(userAgent, "Safari/") ||
				strings.Contains(userAgent, "Firefox/") || strings.Contains(userAgent, "Edge/")
			if !isLikelyBrowser {
				logMsg(LogWarning, "⚠️", "BrowserCheck: invalid User-Agent (%s) (ClientIP: %s)", userAgent, getClientIP(r))
				http.Error(w, "Forbidden: unsupported client", http.StatusForbidden)
				return
			}
		}
		if acceptHeader == "" || acceptLangHeader == "" {
			logMsg(LogWarning, "⚠️", "BrowserCheck: missing Accept or Accept-Language (User-Agent: %s | ClientIP: %s)", userAgent, getClientIP(r))
			http.Error(w, "Forbidden: missing browser headers", http.StatusForbidden)
			return
		}
		if appConfig.AllowedOriginsRegex != nil && r.Header.Get("Origin") != "" && secFetchSite == "" {
			logMsg(LogWarning, "⚠️", "BrowserCheck: missing Sec-Fetch-Site header (User-Agent: %s | ClientIP: %s)", userAgent, getClientIP(r))
			http.Error(w, "Forbidden: missing security header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitingMiddleware is a middleware function that enforces a rate limit
// based on the API key name specified in the "X-Api-Key-Name" header. It
// increments a Redis counter for each request and checks if the counter is
// above the configured rate limit. If it is, it returns a 429 Too Many Requests
// response with a Retry-After header set to 60 seconds. If Redis is not
// enabled, it will not enforce any rate limit.
func rateLimitingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !appConfig.RedisEnabled || rdb == nil {
			next.ServeHTTP(w, r)
			return
		}
		apiKeyName := r.Header.Get(HeaderApiKeyName)
		if apiKeyName == "" {
			logMsg(LogWarning, "⚠️", "Missing %s header (ClientIP: %s)", HeaderApiKeyName, getClientIP(r))
			next.ServeHTTP(w, r)
			return
		}
		actualAPIKey, exists := appConfig.APITokens[apiKeyName]
		if !exists {
			next.ServeHTTP(w, r)
			return
		}
		rateLimitKey := fmt.Sprintf("ratelimit:%s", actualAPIKey)
		ctx := context.Background()
		currentCount, err := rdb.Incr(ctx, rateLimitKey).Result()
		if err != nil {
			logMsg(LogError, "🛑", "Failed to increment rate-limit for API Key %s: %v", rateLimitKey, err)
			next.ServeHTTP(w, r)
			return
		}
		if currentCount == 1 {
			rdb.Expire(ctx, rateLimitKey, 1*time.Minute)
		}
		if currentCount > appConfig.RateLimitPerMinute {
			logMsg(LogWarning, "⚠️", "Rate limit exceeded for API Key Name: %s (ClientIP: %s, Count: %d)", apiKeyName, getClientIP(r), currentCount)
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// proxyHandler handles incoming HTTP requests to the /proxy endpoint, forwarding
// them to the target URL specified in the query parameters. It also manages API
// key validation, caching, and response handling.
//
// It performs the following operations:
//   - Validates the presence of the 'targetURL' query parameter and 'X-Api-Key-Name' header.
//   - Checks if the API key is valid and exists in the configuration.
//   - Reads the request body and constructs a cache key if caching is enabled.
//   - Attempts to retrieve a cached response from Redis if caching is enabled and
//     the 'X-Proxy-Use-Cache' header is set to true.
//   - If no cached response is found, it forwards the request to the target URL,
//     appending the API key as a query parameter.
//   - Sets appropriate headers and status code in the response.
//   - Caches the response in Redis if caching is enabled and the response status
//     code is in the 2xx range.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURLStr := r.URL.Query().Get(QueryParamTargetURL)
	apiKeyName := r.Header.Get(HeaderApiKeyName)
	requestMethod := r.Method
	useCacheHeaderValue := strings.ToLower(r.Header.Get(HeaderProxyUseCache))

	shouldUseCacheFromHeader := true
	if useCacheHeaderValue == "false" {
		shouldUseCacheFromHeader = false
		logMsg(LogInfo, "🧩", "Cache disabled by %s header", HeaderProxyUseCache)
	}

	if targetURLStr == "" {
		http.Error(w, fmt.Sprintf("Missing required query param '%s'", QueryParamTargetURL), http.StatusBadRequest)
		return
	}

	if apiKeyName == "" {
		http.Error(w, fmt.Sprintf("Missing required header '%s'", HeaderApiKeyName), http.StatusBadRequest)
		return
	}

	actualAPIKey, apiKeyExists := appConfig.APITokens[apiKeyName]
	if !apiKeyExists {
		logMsg(LogWarning, "⚠️", "Invalid API Key Name: %s (ClientIP: %s)", apiKeyName, getClientIP(r))
		http.Error(w, "API Key Name not found", http.StatusUnauthorized)
		return
	}

	requestBodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		logMsg(LogError, "🛑", "Failed to read request body: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	cacheKey := ""
	ctx := context.Background()

	if shouldUseCacheFromHeader && appConfig.RedisEnabled && rdb != nil && appConfig.CacheTTL > 0 {
		hash := sha256.New()
		hash.Write([]byte(strings.ToUpper(requestMethod)))
		hash.Write([]byte(targetURLStr))
		if len(requestBodyBytes) > 0 {
			hash.Write(requestBodyBytes)
		}
		hash.Write([]byte(apiKeyName))
		cacheKey = fmt.Sprintf("cache:%s", hex.EncodeToString(hash.Sum(nil)))

		cachedVal, err := rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			var cachedResp CachedResponse
			if err := json.Unmarshal([]byte(cachedVal), &cachedResp); err == nil {
				logMsg(LogInfo, "💾", "Cache hit (Redis) for %s %s (API Key Name: %s, CacheKey: %s)", requestMethod, targetURLStr, apiKeyName, cacheKey)
				for key, values := range cachedResp.Headers {
					lowerKey := strings.ToLower(key)
					if lowerKey == "content-length" || lowerKey == "connection" || lowerKey == "transfer-encoding" || lowerKey == "keep-alive" {
						continue
					}
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.WriteHeader(cachedResp.StatusCode)
				w.Write(cachedResp.Body)
				return
			}
			logMsg(LogError, "🛑", "Failed to unmarshal cache for %s: %v", cacheKey, err)
		} else if err != redis.Nil {
			logMsg(LogError, "🛑", "Failed to get cache from Redis for %s: %v", cacheKey, err)
		} else {
			logMsg(LogInfo, "📭", "Cache miss (Redis) for %s %s (API Key Name: %s, CacheKey: %s)", requestMethod, targetURLStr, apiKeyName, cacheKey)
		}
	} else if appConfig.RedisEnabled && rdb != nil && appConfig.CacheTTL > 0 && !shouldUseCacheFromHeader {
		logMsg(LogInfo, "🧩", "Cache is disabled by header (%s) for %s %s", HeaderProxyUseCache, requestMethod, targetURLStr)
	}

	parsedTargetURL, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "Invalid URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	query := parsedTargetURL.Query()
	query.Set("key", actualAPIKey)
	parsedTargetURL.RawQuery = query.Encode()
	finalTargetURL := parsedTargetURL.String()

	var reqBodyReader io.Reader
	if len(requestBodyBytes) > 0 {
		reqBodyReader = bytes.NewBuffer(requestBodyBytes)
	}

	outReq, err := http.NewRequest(strings.ToUpper(requestMethod), finalTargetURL, reqBodyReader)
	if err != nil {
		logMsg(LogError, "🛑", "Cannot create request for %s: %v", finalTargetURL, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	for k, v := range r.Header {
		lowerK := strings.ToLower(k)
		if lowerK == strings.ToLower(HeaderApiKeyName) ||
			lowerK == strings.ToLower(HeaderProxyUseCache) ||
			lowerK == "connection" ||
			lowerK == "proxy-connection" ||
			lowerK == "proxy-authenticate" ||
			lowerK == "proxy-authorization" ||
			lowerK == "te" ||
			lowerK == "trailers" ||
			lowerK == "transfer-encoding" ||
			lowerK == "upgrade" {
			continue
		}
		if len(v) > 0 {
			outReq.Header.Set(k, v[0])
		}
	}
	outReq.Header.Set("Authorization", actualAPIKey)
	if outReq.Header.Get("Host") == "" && parsedTargetURL.Host != "" {
		outReq.Host = parsedTargetURL.Host
	}

	httpClient := &http.Client{Timeout: appConfig.Timeout}
	resp, err := httpClient.Do(outReq)
	if err != nil {
		logMsg(LogError, "🛑", "Error while calling target %s: %v", finalTargetURL, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logMsg(LogError, "🛑", "Failed to read response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		if lowerKey == "connection" || lowerKey == "content-length" ||
			lowerKey == "transfer-encoding" || lowerKey == "keep-alive" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else if len(respBody) > 0 {
		trimmedBody := bytes.TrimSpace(respBody)
		if (len(trimmedBody) > 1) && ((trimmedBody[0] == '{' && trimmedBody[len(trimmedBody)-1] == '}') || (trimmedBody[0] == '[' && trimmedBody[len(trimmedBody)-1] == ']')) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	if shouldUseCacheFromHeader && appConfig.RedisEnabled && rdb != nil && appConfig.CacheTTL > 0 && cacheKey != "" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		responseToCache := CachedResponse{
			StatusCode: resp.StatusCode,
			Body:       respBody,
			Headers:    resp.Header,
		}
		cachedJSON, err := json.Marshal(responseToCache)
		if err != nil {
			logMsg(LogError, "🛑", "Failed to marshal cache for Redis (key: %s): %v", cacheKey, err)
		} else {
			err = rdb.Set(ctx, cacheKey, cachedJSON, appConfig.CacheTTL).Err()
			if err != nil {
				logMsg(LogError, "🛑", "Failed to set cache in Redis (key: %s): %v", cacheKey, err)
			} else {
				logMsg(LogInfo, "📝", "Set cache for %s %s (API Key Name: %s, CacheKey: %s) with TTL %s", requestMethod, targetURLStr, apiKeyName, cacheKey, appConfig.CacheTTL)
			}
		}
	} else if appConfig.RedisEnabled && rdb != nil && appConfig.CacheTTL > 0 && cacheKey != "" && !shouldUseCacheFromHeader {
		logMsg(LogInfo, "🧩", "Cache intentionally ignored due to %s header set to false for %s %s", HeaderProxyUseCache, requestMethod, targetURLStr)
	}
}

// main initializes the application configuration, sets up the logger and Redis
// connection if enabled, and starts the HTTP server on the configured port.
// The server listens for incoming requests to the /proxy endpoint, and applies
// the rate limiting, browser check, origin validation, and logging middleware
// in sequence.
func main() {
	once.Do(func() {
		loadConfig()
		initLogger()
		initRedis()
	})

	mux := http.NewServeMux()
	var currentHandler http.Handler = http.HandlerFunc(proxyHandler)
	currentHandler = rateLimitingMiddleware(http.HandlerFunc(currentHandler.(http.HandlerFunc)))
	if appConfig.EnforceBrowserCheck {
		currentHandler = browserCheckMiddleware(currentHandler)
	}
	currentHandler = originValidationMiddleware(currentHandler)
	currentHandler = loggingMiddleware(currentHandler)
	mux.Handle("/proxy", currentHandler)

	logMsg(LogInfo, "🚀", "Application started on port %s. Endpoint: /proxy", appConfig.ServerPort)
	server := &http.Server{
		Addr:         ":" + appConfig.ServerPort,
		Handler:      mux,
		ReadTimeout:  appConfig.ReadTimeout,
		WriteTimeout: appConfig.WriteTimeout,
		IdleTimeout:  appConfig.IdleTimeout,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logMsg(LogError, "🛑", "Failed to start server on port %s: %v", appConfig.ServerPort, err)
		os.Exit(1)
	}
}
