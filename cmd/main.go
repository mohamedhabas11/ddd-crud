// cmd/app/main.go
package main

import (
	"context"
	"errors" // Import errors for server shutdown check
	"log"
	"net/http" // Import net/http for ErrServerClosed
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"

	app_service "github.com/mohamedhabas11/ddd-crud/internal/application/service"
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/persistence"
	repo_gorm "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/persistence/gorm"
	"github.com/mohamedhabas11/ddd-crud/internal/infrastructure/security" // Import security
	web_handler "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/web/handler"
	web_router "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/web/router"
)

const (
	// Default config values
	defaultAppName         = "DDD-CRUD App"
	defaultServerPort      = ":8080"
	defaultLogLevel        = "info"
	defaultDBDriver        = "postgres"
	defaultDBLogLevel      = "warn"
	defaultBodyLimit       = 4 // MB
	defaultReadTimeoutSec  = 15
	defaultWriteTimeoutSec = 15
	defaultJWTExpiryMin    = 60
)

func main() {
	// --- Logger Setup ---
	appLogger := log.New(os.Stdout, "APP : ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	appLogger.Println("INFO: Application starting...")

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
	viper.SetDefault("logger.level", defaultLogLevel)
	viper.SetDefault("database.driver", defaultDBDriver)
	viper.SetDefault("database.log_level", defaultDBLogLevel)
	viper.SetDefault("database.max_idle_conns", 10)
	viper.SetDefault("database.max_open_conns", 50)
	viper.SetDefault("database.conn_max_lifetime_minutes", 60)
	viper.SetDefault("jwt.secret", "") // No default for secret - MUST be set
	viper.SetDefault("jwt.expiry_minutes", defaultJWTExpiryMin)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			appLogger.Println("INFO: Config file not found, using defaults and environment variables.")
		} else {
			appLogger.Printf("WARN: Error reading config file: %v", err)
		}
	} else {
		appLogger.Printf("INFO: Loaded configuration from file: %s", viper.ConfigFileUsed())
	}

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
		appLogger.Fatal("FATAL: Database DSN is not configured (set DATABASE_DSN env var or database.dsn in config)")
	}
	appLogger.Printf("INFO: Database configuration loaded (Driver: %s)", dbConfig.Driver)

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
		appLogger.Fatal("FATAL: JWT Secret is not configured (set JWT_SECRET env var or jwt.secret in config)")
	}
	jwtExpiry := viper.GetInt("jwt.expiry_minutes")

	// --- Dependency Injection (Manual Wiring) ---
	appLogger.Println("INFO: Initializing dependencies...")

	// Infrastructure Layer: Database
	db, err := persistence.NewConnection(dbConfig, appLogger)
	if err != nil {
		appLogger.Fatalf("FATAL: Failed to connect to database: %v", err)
	}
	appLogger.Println("INFO: Database connection successful.")
	if err := persistence.Migrate(db, appLogger); err != nil {
		appLogger.Fatalf("FATAL: Database migration failed: %v", err)
	}

	// Infrastructure Layer: Security
	jwtSvc, err := security.NewJWTService(jwtSecret, jwtExpiry)
	if err != nil {
		appLogger.Fatalf("FATAL: Failed to initialize JWT Service: %v", err)
	}
	appLogger.Println("INFO: JWT Service initialized.")

	// Infrastructure Layer: Repositories
	userRepo := repo_gorm.NewGormUserRepository(db, appLogger)

	// Application Layer: Services
	userService := app_service.NewUserService(userRepo, appLogger)

	// Infrastructure Layer: Web/HTTP Handlers
	userHandler := web_handler.NewUserHandler(userService, jwtSvc, appLogger) // Inject jwtSvc

	// Infrastructure Layer: Web/HTTP Router (Fiber)
	fiberApp := web_router.NewFiberRouter(routerConfig, userHandler, jwtSvc, appLogger /*, other handlers */) // Inject jwtSvc

	appLogger.Println("INFO: Dependencies initialized.")

	// --- Start HTTP Server (Fiber) ---
	go func() {
		appLogger.Printf("INFO: Starting HTTP server on port %s", serverPort)
		if err := fiberApp.Listen(serverPort); err != nil {
			// Check if the error is due to server closing gracefully
			// Note: Fiber's Shutdown might not return http.ErrServerClosed directly.
			// If graceful shutdown logs errors, adjust this check based on observed behavior.
			if !errors.Is(err, http.ErrServerClosed) {
				appLogger.Fatalf("FATAL: Failed to start HTTP server: %v", err)
			}
		}
	}()

	// --- Graceful Shutdown ---
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	appLogger.Println("INFO: Termination signal received. Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := fiberApp.ShutdownWithContext(shutdownCtx); err != nil {
		appLogger.Printf("ERROR: Fiber server shutdown failed: %v", err)
	} else {
		appLogger.Println("INFO: Fiber server gracefully stopped.")
	}

	// Cleanup: Close DB connection pool
	sqlDB, err := db.DB()
	if err == nil && sqlDB != nil {
		appLogger.Println("INFO: Closing database connection pool...")
		if err := sqlDB.Close(); err != nil {
			appLogger.Printf("ERROR: Error closing database connection: %v", err)
		}
	} else if err != nil {
		appLogger.Printf("ERROR: Could not get underlying sql.DB to close: %v", err)
	}

	appLogger.Println("INFO: Application finished.")
}
