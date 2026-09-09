// Package main wires together the HTTP server, database store, and middleware.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/PaulBabatuyi/Double-Entry-Bank-Go/docs"
	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/api"
	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/db"
	"github.com/PaulBabatuyi/Double-Entry-Bank-Go/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"
)

func initLogger() {
	// Use millisecond precision in logs so request timing is easy to follow in demos.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()
	zlog.Info().Msg("Logger initialized")
}

// @title           Double-Entry Bank Ledger API
// @version         1.0
// @description     Production-grade double-entry accounting ledger
// @host            localhost:8080
// @BasePath        /
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token

func parseAllowedOrigins() []string {
	// Allow explicit runtime configuration; defaults are safe for hosted frontend + local dev.
	origins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if strings.TrimSpace(origins) == "" {
		return []string{
			"https://golangbank.app",
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:5173",
			"http://127.0.0.1:5173",
		}
	}

	parts := strings.Split(origins, ",")
	allowed := make([]string, 0, len(parts))
	for _, origin := range parts {
		// Normalize each origin to avoid accidental whitespace mismatches.
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			allowed = append(allowed, trimmed)
		}
	}

	if len(allowed) == 0 {
		return []string{
			"https://golangbank.app",
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:5173",
			"http://127.0.0.1:5173",
		}
	}

	return allowed
}

func resolveDBURL() string {
	// Prefer DB_URL, but support platform-specific fallbacks for easier deployment.
	connStr := strings.TrimSpace(os.Getenv("DB_URL"))

	fallbackVars := []string{"INTERNAL_DATABASE_URL", "RENDER_DATABASE_URL", "DATABASE_URL"}

	if connStr == "" {
		// If DB_URL is absent, try common provider-specific environment variables.
		for _, envVar := range fallbackVars {
			if value := strings.TrimSpace(os.Getenv(envVar)); value != "" {
				return value
			}
		}

		if os.Getenv("RENDER") == "true" {
			zlog.Fatal().Msg(
				"DB_URL is not configured. " +
					"Fix: Render dashboard → your web service → Environment → add DB_URL " +
					"set to the Internal Connection String from your PostgreSQL service.",
			)
		}

		// Default connection string for local development only.
		return "postgresql://root:secret@localhost:5432/simple_ledger?sslmode=disable" // #nosec G101 - Local development default
	}

	lower := strings.ToLower(connStr)
	// Localhost DB URLs are invalid in cloud runtimes; attempt safe fallback automatically.
	isLocalHostURL := strings.Contains(lower, "@localhost:") || strings.Contains(lower, "@127.0.0.1:") || strings.Contains(lower, "@[::1]:")
	if isLocalHostURL {
		for _, envVar := range fallbackVars {
			if value := strings.TrimSpace(os.Getenv(envVar)); value != "" {
				return value
			}
		}
		if os.Getenv("RENDER") == "true" {
			zlog.Fatal().Msg(
				"DB_URL resolves to localhost, which is not valid on Render. " +
					"Fix: Render dashboard → your web service → Environment → update DB_URL " +
					"to the Internal Connection String from your PostgreSQL service.",
			)
		}
	}

	return connStr
}

func main() {
	// Capture startup time so health endpoint can report uptime.
	startTime := time.Now()

	initLogger()

	if err := godotenv.Load(); err != nil {
		zlog.Warn().Err(err).Msg("No .env file found – using system env")
	}

	if err := api.InitTokenAuthFromEnv(); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to initialize JWT auth")
	}

	// Build DB connection string and validate connectivity before serving traffic.
	connStr := resolveDBURL()
	if strings.Contains(connStr, "@localhost:") || strings.Contains(connStr, "@127.0.0.1:") || strings.Contains(connStr, "@[::1]:") {
		zlog.Warn().Msg("Using localhost DB_URL; this is only valid for local development")
	}
	dbConn, err := sql.Open("postgres", connStr)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to open DB connection")
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer pingCancel()
	if err := dbConn.PingContext(pingCtx); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to connect to DB")
	}
	zlog.Info().Msg("Database connectivity verified")

	defer func() {
		if closeErr := dbConn.Close(); closeErr != nil {
			zlog.Error().Err(closeErr).Msg("Failed to close DB connection")
		}
	}()

	store := db.NewStore(dbConn)
	ledgerSvc := service.NewLedgerService(store)

	// Wire HTTP handlers with service and persistence dependencies.
	h := api.NewHandler(ledgerSvc, store)

	r := newRouter(h, startTime)

	port := os.Getenv("PORT")
	if port == "" {
		// Default port for local development when PORT is not injected.
		port = "8080"
	}

	// Configure HTTP server with timeouts for security
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	zlog.Info().Str("port", port).Msg("Starting server")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		zlog.Fatal().Err(err).Msg("Server failed to start")
	}
}

// requestIDKey is where the per-request identifier is kept for the log middleware.
const requestIDKey = "request_id"

// requestID reuses an inbound X-Request-Id when the caller supplies one and
// mints a fresh identifier otherwise. It is kept off the response, as before.
func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := c.GetHeader("X-Request-Id")
		if reqID == "" {
			reqID = uuid.NewString()
		}
		c.Set(requestIDKey, reqID)
		c.Next()
	}
}

// newRouter builds the HTTP router: middleware chain, public routes, the Swagger
// UI mount and the JWT-protected business endpoints.
func newRouter(h *api.Handler, startTime time.Time) *gin.Engine {
	r := gin.New()

	// The previous router neither redirected trailing slashes nor guessed at a
	// near-miss path, and it answered 405 when a known path was reached with an
	// unregistered method. Gin defaults differ on all three, so pin them.
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = true

	// Unmatched paths get net/http's own 404; an unregistered method gets a bare
	// 405 carrying one Allow header per permitted method.
	r.NoRoute(func(c *gin.Context) {
		http.NotFound(c.Writer, c.Request)
	})
	r.NoMethod(func(c *gin.Context) {
		header := c.Writer.Header()
		if allow := header.Get("Allow"); allow != "" {
			header.Del("Allow")
			for _, method := range strings.Split(allow, ", ") {
				header.Add("Allow", method)
			}
		}
		c.Status(http.StatusMethodNotAllowed)
		c.Writer.WriteHeaderNow()
	})

	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(requestID())

	// CORS middleware for separate frontend deployments and local development.
	r.Use(api.CORS(api.CORSOptions{
		AllowedOrigins:   parseAllowedOrigins(),
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(func(c *gin.Context) {
		// Attach request metadata to logs for traceability during debugging.
		reqID := c.GetString(requestIDKey)
		zlog.Info().Str("request_id", reqID).Str("path", c.Request.URL.Path).Msg("Request received")
		c.Next()
	})

	// Public routes
	r.POST("/register", h.Register)
	r.POST("/login", h.Login)
	r.GET("/health", func(c *gin.Context) {
		// Health returns service liveness plus lightweight runtime metadata.
		zlog.Info().Msg("Health check requested")
		c.Header("Content-Type", "application/json")
		c.Status(http.StatusOK)
		if err := json.NewEncoder(c.Writer).Encode(map[string]string{
			"status":  "healthy",
			"version": "0.1.0",
			"uptime":  time.Since(startTime).String(),
		}); err != nil {
			zlog.Error().Err(err).Msg("Failed to encode health check response")
		}
	})

	// Serve the Swagger UI through swaggo/http-swagger (the adapter the pre-migration
	// Chi service used) rather than swaggo/gin-swagger: the two adapters vendor
	// different UI shells, and reusing the upstream package keeps the rendered
	// /swagger/index.html byte-identical to the original service. gin.WrapH adapts
	// the net/http handler to Gin's router; the handler derives its own prefix from
	// the request URI, so it keeps serving doc.json and the static assets as before.
	r.GET("/swagger/*any", gin.WrapH(httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
		httpSwagger.DeepLinking(true),
	)))
	// Protected routes
	protected := r.Group("")
	{
		// Apply JWT verification only to protected business endpoints.
		protected.Use(api.Verifier(api.TokenAuth))
		protected.Use(api.Authenticator())

		protected.POST("/accounts", h.CreateAccount)
		protected.GET("/accounts", h.ListAccounts)
		protected.GET("/accounts/:id", h.GetAccount)
		protected.POST("/accounts/:id/deposit", h.Deposit)
		protected.POST("/accounts/:id/withdraw", h.Withdraw)
		protected.POST("/transfers", h.Transfer)
		protected.GET("/accounts/:id/entries", h.GetEntries)
		protected.GET("/accounts/:id/reconcile", h.ReconcileAccount)
		protected.GET("/transactions/:id", h.GetTransactions)
	}

	return r
}
