// cmd/app/main.go
package main

import (
	"context"
	"errors"
	"log/slog" // Import slog
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"

	app_service "github.com/mohamedhabas11/ddd-crud/internal/application/service"
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/persistence"
	repo_gorm "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/persistence/gorm"
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/security"
	web_handler "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/web/handler"
	web_router "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/web/router"
)

const (
	// Default config values
	defaultAppName         = "DDD-CRUD App"
	defaultServerPort      = ":8080"
	defaultLogLevel        = "info" // slog levels: debug, info, warn, error
	defaultDBDriver        = "postgres"
	defaultDBLogLevel      = "warn" // gorm levels: silent, error, warn, info
	defaultBodyLimit       = 4      // MB
	defaultReadTimeoutSec  = 15
	defaultWriteTimeoutSec = 15
	defaultJWTExpiryMin    = 60
)

func main() {
	// --- Logger Setup (slog) ---
	logLevel := slog.LevelInfo                                // Default level
	switch strings.ToLower(viper.GetString("logger.level")) { // Read level early if possible, or after viper setup
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	// Choose JSONHandler for production, TextHandler for local dev is fine too
	opts := &slog.HandlerOptions{Level: logLevel}
	// handler := slog.NewTextHandler(os.Stdout, opts) // Or TextHandler
	handler := slog.NewJSONHandler(os.Stdout, opts)
	appLogger := slog.New(handler)
	slog.SetDefault(appLogger) // Make it the default logger for the application if desired

	appLogger.Info("Application starting...")

	// --- Configuration Setup (Viper) ---
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	viper.SetDefault("app.name", defaultAppName)
	viper.SetDefault("server.port", defaultServerPort)
	viper.SetDefault("server.body_limit_mb", defaultBodyLimit)
	viper.SetDefault("server.read_timeout_sec", defaultReadTimeoutSec)
	viper.SetDefault("server.write_timeout_sec", defaultWriteTimeoutSec)
	viper.SetDefault("logger.level", defaultLogLevel) // Set default for viper reading
	viper.SetDefault("database.driver", defaultDBDriver)
	viper.SetDefault("database.log_level", defaultDBLogLevel)
	viper.SetDefault("database.max_idle_conns", 10)
	viper.SetDefault("database.max_open_conns", 50)
	viper.SetDefault("database.conn_max_lifetime_minutes", 60)
	viper.SetDefault("jwt.secret", "") // No default for secret - MUST be set
	viper.SetDefault("jwt.expiry_minutes", defaultJWTExpiryMin)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			appLogger.Info("Config file not found, using defaults and environment variables.")
		} else {
			appLogger.Warn("Error reading config file", "error", err)
		}
	} else {
		appLogger.Info("Loaded configuration from file", "path", viper.ConfigFileUsed())
	}

	// Re-read log level after loading config if necessary (if not done before)
	// ... update logLevel and create new logger if needed ...

	// --- Populate Config Structs ---
	dbConfig := persistence.DBConfig{
		Driver:          viper.GetString("database.driver"),
		DSN:             viper.GetString("database.dsn"),
		MaxIdleConns:    viper.GetInt("database.max_idle_conns"),
		MaxOpenConns:    viper.GetInt("database.max_open_conns"),
		ConnMaxLifeTime: viper.GetDuration("database.conn_max_lifetime_minutes") * time.Minute,
		LogLevel:        viper.GetString("database.log_level"),
	}
	if dbConfig.DSN == "" {
		appLogger.Error("Database DSN is not configured. Set DATABASE_DSN env var or database.dsn in config.")
		os.Exit(1) // Use os.Exit for fatal errors outside log.Fatal
	}
	appLogger.Info("Database configuration loaded", "driver", dbConfig.Driver)

	routerConfig := web_router.FiberRouterConfig{
		AppName:      viper.GetString("app.name"),
		BodyLimit:    viper.GetInt("server.body_limit_mb"),
		ReadTimeout:  viper.GetDuration("server.read_timeout_sec") * time.Second,
		WriteTimeout: viper.GetDuration("server.write_timeout_sec") * time.Second,
	}
	serverPort := viper.GetString("server.port")

	// JWT Config
	jwtSecret := viper.GetString("jwt.secret")
	if jwtSecret == "" {
		appLogger.Error("JWT Secret is not configured. Set JWT_SECRET env var or jwt.secret in config.")
		os.Exit(1)
	}
	jwtExpiry := viper.GetInt("jwt.expiry_minutes")

	// --- Dependency Injection (Manual Wiring) ---
	appLogger.Info("Initializing dependencies...")

	// Infrastructure Layer: Database
	// Pass slog.Logger to NewConnection (update NewConnection signature)
	db, err := persistence.NewConnection(dbConfig, appLogger)
	if err != nil {
		appLogger.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	appLogger.Info("Database connection successful.")
	// Pass slog.Logger to Migrate (update Migrate signature)
	if err := persistence.Migrate(db, appLogger); err != nil {
		appLogger.Error("Database migration failed", "error", err)
		os.Exit(1)
	}

	// Infrastructure Layer: Security
	jwtSvc, err := security.NewJWTService(jwtSecret, jwtExpiry)
	if err != nil {
		appLogger.Error("Failed to initialize JWT Service", "error", err)
		os.Exit(1)
	}
	appLogger.Info("JWT Service initialized.")

	// Infrastructure Layer: Repositories
	// Pass slog.Logger to NewGormUserRepository (update signature)
	userRepo := repo_gorm.NewGormUserRepository(db, appLogger)

	// Application Layer: Services
	// Pass slog.Logger to NewUserService (update signature)
	userService := app_service.NewUserService(userRepo, appLogger)

	// Infrastructure Layer: Web/HTTP Handlers
	// Pass slog.Logger to NewUserHandler (update signature)
	userHandler := web_handler.NewUserHandler(userService, jwtSvc, appLogger)

	// Infrastructure Layer: Web/HTTP Router (Fiber)
	// Pass slog.Logger to NewFiberRouter (update signature)
	fiberApp := web_router.NewFiberRouter(routerConfig, userHandler, jwtSvc, appLogger /*, other handlers */)

	appLogger.Info("Dependencies initialized.")

	// --- Start HTTP Server (Fiber) ---
	go func() {
		appLogger.Info("Starting HTTP server", "port", serverPort)
		if err := fiberApp.Listen(serverPort); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Log error but don't Fatalf, graceful shutdown will handle termination
			appLogger.Error("Failed to start HTTP server", "error", err)
		}
	}()

	// --- Graceful Shutdown ---
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	appLogger.Info("Termination signal received. Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := fiberApp.ShutdownWithContext(shutdownCtx); err != nil {
		appLogger.Error("Fiber server shutdown failed", "error", err)
	} else {
		appLogger.Info("Fiber server gracefully stopped.")
	}

	// Cleanup: Close DB connection pool
	sqlDB, err := db.DB()
	if err != nil {
		// Log error if getting the underlying DB fails
		appLogger.Error("Could not get underlying sql.DB to close", "error", err)
	} else if sqlDB != nil {
		appLogger.Info("Closing database connection pool...")
		if err := sqlDB.Close(); err != nil {
			appLogger.Error("Error closing database connection", "error", err)
		} else {
			appLogger.Info("Database connection pool closed.")
		}
	}

	appLogger.Info("Application finished.")
}
