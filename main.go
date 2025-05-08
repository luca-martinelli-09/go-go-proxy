package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/golang-jwt/jwt/v5"
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
	JWTSecret            string
	JWTIssuerRegex       string
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

	HeaderApiKeyName         = "X-Proxy-Api-Key-Name"
	HeaderProxyApiQuery      = "X-Proxy-Api-Query"
	HeaderProxyApiHeader     = "X-Proxy-Api-Header"
	HeaderProxyApiHeaderType = "X-Proxy-Api-Header-Type"
	HeaderProxyUseCache      = "X-Proxy-Use-Cache"

	QueryParamTargetURL = "url"
)

var (
	appConfig      *Config
	rdb            *redis.Client
	logger         *log.Logger
	once           sync.Once
	jwtIssuerRegex *regexp.Regexp
)

// logMsg logs a formatted message with a specified log level and emoji.
// It formats the message using the provided format string and arguments.
// If a logger is set, it outputs the message using the logger; otherwise, it logs to the standard log.
// The log message includes the emoji and log level for context.
//
// Parameters:
//   - level: The log level (e.g., INFO, WARNING, ERROR).
//   - emoji: A contextual emoji representing the log event.
//   - format: A format string for the log message.
//   - args: Additional arguments to format into the message.
func logMsg(level, emoji string, format string, args ...interface{}) {
	msg := fmt.Sprintf("%s %s | %s", emoji, level, fmt.Sprintf(format, args...))
	if logger == nil {
		log.Printf(msg)
	} else {
		logger.Output(3, msg)
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

// loadConfig reads configuration from the environment and sets up the global appConfig
// instance. It also compiles regular expressions for allowed origins and JWT issuers.
// Environment variables can be set in a .env file in the current working directory.
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
		JWTSecret:            getEnv("JWT_SECRET", ""),
		JWTIssuerRegex:       getEnv("JWT_ISSUER_REGEX", ""),
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

	// Compile JWT issuer regex ONCE at startup!
	if appConfig.JWTIssuerRegex != "" {
		var err error
		jwtIssuerRegex, err = regexp.Compile(appConfig.JWTIssuerRegex)
		if err != nil {
			log.Printf("🛑 ERROR | Invalid JWT issuer regex: %v", err)
			os.Exit(1)
		} else {
			log.Printf("⚙️ INFO | Compiled JWT issuer regex: %s", appConfig.JWTIssuerRegex)
		}
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

// initLogger sets up a logger for the application, creating the log directory if needed, and
// sets up a lumberjack.Logger to rotate the log files. The logger is also set to output to
// both stdout and the log file.
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

// initRedis sets up a Redis connection and pings it to test the connection.
// If the connection cannot be established, rdb is set to nil and an error is logged.
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

// getClientIP extracts the client's IP address from the HTTP request.
// It first checks the "X-Forwarded-For" header for an IP list, returning the first IP.
// If not present, it looks for the "X-Real-IP" header.
// If both headers are absent or empty, it falls back to using the remote address from the request.
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

// loggingMiddleware logs the start and end of each request, including the client IP,
// target URL, API key name, and other relevant details. It also logs the duration and
// response bytes of each request. The request headers are logged as a JSON object.
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

// originValidationMiddleware checks the Origin header of the incoming request against
// the AllowedOriginsRegex in the configuration. If the regex is not set, it allows all
// origins. If the regex is set, it only allows requests with an Origin header that
// matches the regex. If the Origin header is empty, it falls back to the Referer header.
// If the request does not match the regex, it returns a 403 Forbidden response.
func originValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = r.Header.Get("Referer")
		}
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

// browserCheckMiddleware is a middleware that blocks requests from known bots and tools,
// and also requires specific headers to be present in order to prevent abuse.
// It is enabled by setting EnforceBrowserCheck to true in the configuration.
// Note that this middleware does not provide any real security benefits, but can
// help to reduce the amount of abuse and unwanted traffic.
// It is not recommended to use this middleware in production without further
// customization and testing.
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

// copyHeaders copies headers from src to dst, excluding headers in the exclude list
// (case-insensitive).
func copyHeaders(dst, src http.Header, exclude ...string) {
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, h := range exclude {
		excludeSet[strings.ToLower(h)] = struct{}{}
	}
	for k, v := range src {
		if _, skip := excludeSet[strings.ToLower(k)]; skip {
			continue
		}
		for _, vv := range v {
			dst.Add(k, vv)
		}
	}
}

// redactAPIKeyInBodyAndHeaders takes an API key, a redaction string, a byte slice for the request body,
// and a http.Header, and returns the redacted byte slice and http.Header.
// It replaces the API key in the body and headers with the redaction string.
func redactAPIKeyInBodyAndHeaders(apiKey string, redaction string, body []byte, headers http.Header) ([]byte, http.Header) {
	redacted := body
	if len(apiKey) > 0 && len(body) > 0 && bytes.Contains(body, []byte(apiKey)) {
		redacted = bytes.ReplaceAll(body, []byte(apiKey), []byte(redaction))
	}
	// Redact in headers
	newHeaders := headers.Clone()
	for k, vals := range newHeaders {
		for i, val := range vals {
			if strings.Contains(val, apiKey) {
				newHeaders[k][i] = strings.ReplaceAll(val, apiKey, redaction)
			}
		}
	}
	return redacted, newHeaders
}

// rateLimitingMiddleware adds rate limiting to a request handler.
// It expects a Redis client to be set up and the RateLimitPerMinute to be set.
// It increments the rate limit counter for the API Key Name in the X-Proxy-Api-Key-Name header.
// If the counter exceeds the rate limit, a 429 Too Many Requests response is sent.
// If Redis is not enabled or the API Key Name is not set, the request is passed through to the wrapped handler.
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
		_, exists := appConfig.APITokens[apiKeyName]
		if !exists {
			next.ServeHTTP(w, r)
			return
		}
		rateLimitKey := fmt.Sprintf("ratelimit:%s", apiKeyName)
		ctx := r.Context()
		currentCount, err := rdb.Incr(ctx, rateLimitKey).Result()
		if err != nil {
			logMsg(LogError, "🛑", "Failed to increment rate-limit for API Key Name %s: %v", rateLimitKey, err)
			next.ServeHTTP(w, r)
			return
		}
		if currentCount == 1 {
			_ = rdb.Expire(ctx, rateLimitKey, 1*time.Minute)
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

// jwtAuthMiddleware adds JWT authentication to a request handler.
// It expects a JWT in the X-Proxy-Authorization header with Bearer prefix.
// The JWT is verified with the configured JWT secret.
// If the JWT is invalid, expired, or not yet valid, a 401 Unauthorized response is sent.
// If the JWT is valid, the request is passed through to the wrapped handler.
// The JWT claims are stored in the request context under the "jwt_claims" key.
func jwtAuthMiddleware(next http.Handler) http.Handler {
	const HeaderProxyJWT = "X-Proxy-Authorization"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		if appConfig.JWTSecret == "" {
			logMsg(LogInfo, "ℹ️", "JWT authentication is disabled (JWTSecret is empty). Passing request through.")
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get(HeaderProxyJWT)
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			logMsg(LogWarning, "⚠️", "Missing or malformed JWT in %s header (ClientIP: %s)", HeaderProxyJWT, clientIP)
			http.Error(w, "Unauthorized: JWT required in "+HeaderProxyJWT+" header", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, bearerPrefix)
		token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				actualAlg := "unknown"
				if algHeader, ok := token.Header["alg"].(string); ok {
					actualAlg = algHeader
				}
				return nil, errors.New("unexpected signing method: expected HS256, got " + actualAlg)
			}
			return []byte(appConfig.JWTSecret), nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				logMsg(LogWarning, "⚠️", "JWT expired (ClientIP: %s): %v", clientIP, err)
				http.Error(w, "Unauthorized: JWT expired", http.StatusUnauthorized)
			} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
				logMsg(LogWarning, "⚠️", "JWT not yet valid (ClientIP: %s): %v", clientIP, err)
				http.Error(w, "Unauthorized: JWT not yet valid", http.StatusUnauthorized)
			} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
				logMsg(LogWarning, "⚠️", "JWT signature invalid (ClientIP: %s): %v", clientIP, err)
				http.Error(w, "Unauthorized: JWT signature invalid", http.StatusUnauthorized)
			} else {
				logMsg(LogWarning, "⚠️", "JWT parsing/validation error (ClientIP: %s): %v", clientIP, err)
				http.Error(w, "Unauthorized: Invalid JWT", http.StatusUnauthorized)
			}
			return
		}

		if !token.Valid {
			logMsg(LogWarning, "⚠️", "JWT token is invalid (ClientIP: %s)", clientIP)
			http.Error(w, "Unauthorized: Invalid JWT token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			logMsg(LogError, "🛑", "Could not cast JWT claims to MapClaims (ClientIP: %s)", clientIP)
			http.Error(w, "Internal Server Error: processing JWT claims", http.StatusInternalServerError)
			return
		}

		if jwtIssuerRegex != nil {
			issClaim, issOk := claims["iss"].(string)
			if !issOk {
				logMsg(LogWarning, "⚠️", "JWT 'iss' claim missing or not a string (ClientIP: %s)", clientIP)
				http.Error(w, "Unauthorized: JWT 'iss' claim invalid", http.StatusUnauthorized)
				return
			}

			if !jwtIssuerRegex.MatchString(issClaim) {
				logMsg(LogWarning, "⚠️", "JWT 'iss' claim '%s' does not match configured regex (ClientIP: %s)", issClaim, clientIP)
				http.Error(w, "Unauthorized: JWT issuer not permitted", http.StatusUnauthorized)
				return
			}
		}

		subClaim, subOk := claims["sub"].(string)
		if !subOk || subClaim == "" {
			logMsg(LogWarning, "⚠️", "JWT 'sub' claim missing, not a string, or empty (ClientIP: %s)", clientIP)
			http.Error(w, "Unauthorized: JWT 'sub' claim invalid", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "jwt_claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// proxyHandler is the main request handler for the proxy.
// It expects the TargetURL parameter to be set in the query string.
// It also expects the ApiKeyName header to be set.
// If the request body is not empty, it's passed through to the target.
// If the HeaderProxyUseCache header is set to "true", it will cache the response
// in Redis for CacheTTL seconds. The cache key is a SHA-256 hash of the request
// method, target URL, request body, and API key name.
// If the HeaderProxyApiQuery parameter is set, it will pass the API key as a query
// parameter with that name instead of using the Authorization header.
// If the HeaderProxyApiHeader parameter is set, it will pass the API key as a
// header with that name instead of using the Authorization header.
// If the HeaderProxyApiHeaderType parameter is set, it will use that type
// instead of "Bearer" for the API key header.
// The TargetURL parameter is not validated, so be careful when using this.
// The API key is redacted from the response body and headers before being
// sent to the client.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURLStr := r.URL.Query().Get(QueryParamTargetURL)
	apiKeyName := r.Header.Get(HeaderApiKeyName)
	requestMethod := r.Method
	useCacheHeaderValue := strings.ToLower(r.Header.Get(HeaderProxyUseCache))
	shouldUseCacheFromHeader := useCacheHeaderValue != "false"

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
	r.Body.Close()
	if err != nil {
		logMsg(LogError, "🛑", "Failed to read request body: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	cacheKey := ""
	ctx := r.Context()
	redactionString := "***"

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
				copyHeaders(w.Header(), http.Header(cachedResp.Headers), "content-length", "connection", "transfer-encoding", "keep-alive")
				w.WriteHeader(cachedResp.StatusCode)
				if _, err := w.Write(cachedResp.Body); err != nil {
					logMsg(LogError, "🛑", "Error writing cached response: %v", err)
				}
				return
			}
			logMsg(LogError, "🛑", "Failed to unmarshal cache for %s: %v", cacheKey, err)
		} else if err != redis.Nil {
			logMsg(LogError, "🛑", "Failed to get cache from Redis for %s: %v", cacheKey, err)
		} else {
			logMsg(LogInfo, "📭", "Cache miss (Redis) for %s %s (API Key Name: %s, CacheKey: %s)", requestMethod, targetURLStr, apiKeyName, cacheKey)
		}
	}

	parsedTargetURL, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "Invalid URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	proxyApiQueryParam := r.Header.Get(HeaderProxyApiQuery)
	proxyApiHeaderName := r.Header.Get(HeaderProxyApiHeader)
	proxyApiHeaderType := r.Header.Get(HeaderProxyApiHeaderType)
	if proxyApiHeaderType == "" {
		proxyApiHeaderType = "Bearer"
	}

	finalTargetURL := parsedTargetURL.String()
	if proxyApiQueryParam != "" {
		q := parsedTargetURL.Query()
		q.Set(proxyApiQueryParam, actualAPIKey)
		parsedTargetURL.RawQuery = q.Encode()
		finalTargetURL = parsedTargetURL.String()
	}

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

	outReq = outReq.WithContext(ctx)
	copyHeaders(outReq.Header, r.Header, HeaderApiKeyName, HeaderProxyUseCache,
		HeaderProxyApiQuery, HeaderProxyApiHeader, HeaderProxyApiHeaderType,
		"connection", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te",
		"trailers", "transfer-encoding", "upgrade")

	if proxyApiHeaderName != "" {
		outReq.Header.Set(proxyApiHeaderName, fmt.Sprintf("%s %s", proxyApiHeaderType, actualAPIKey))
	} else if proxyApiQueryParam == "" {
		outReq.Header.Set("Authorization", "Bearer "+actualAPIKey)
	}

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

	respBody, resp.Header = redactAPIKeyInBodyAndHeaders(actualAPIKey, redactionString, respBody, resp.Header)
	copyHeaders(w.Header(), resp.Header, "connection", "content-length", "transfer-encoding", "keep-alive")

	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else if len(respBody) > 0 {
		trimmedBody := bytes.TrimSpace(respBody)
		if (len(trimmedBody) > 1) && ((trimmedBody[0] == '{' && trimmedBody[len(trimmedBody)-1] == '}') || (trimmedBody[0] == '[' && trimmedBody[len(trimmedBody)-1] == ']')) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(respBody); err != nil {
		logMsg(LogError, "🛑", "Error writing response body: %v", err)
	}

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
	}
}

// main initializes the application by loading configuration, setting up logging and
// Redis, and starting an HTTP server to handle proxy requests. It sets up a chain of
// middleware for authentication, rate limiting, browser checks, origin validation, and
// logging. The server listens on the configured port and uses the /proxy endpoint.
func main() {
	once.Do(func() {
		loadConfig()
		initLogger()
		initRedis()
	})

	mux := http.NewServeMux()
	var currentHandler http.Handler = http.HandlerFunc(proxyHandler)
	currentHandler = jwtAuthMiddleware(currentHandler)
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
