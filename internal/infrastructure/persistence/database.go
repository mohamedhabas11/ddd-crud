// internal/infrastructure/persistence/database.go
package persistence

import (
	"fmt"
	"log/slog" // <--- CHANGE THIS IMPORT
	"time"

	// GORM drivers
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger" // GORM's logger interface

	// Import GORM models defined in this package
	gorm_models "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/persistence/gorm"
)

// DBConfig holds database configuration parameters.
type DBConfig struct {
	Driver          string // e.g., "postgres", "mysql"
	DSN             string // Data Source Name (connection string)
	MaxIdleConns    int
	MaxOpenConns    int
	ConnMaxLifeTime time.Duration
	LogLevel        string // GORM log level: "info", "warn", "error", "silent"
}

// NewConnection establishes a new database connection based on the config.
// CHANGE the appLogger parameter type:
func NewConnection(config DBConfig, appLogger *slog.Logger) (*gorm.DB, error) {
	var dialector gorm.Dialector

	// Choose the appropriate GORM dialector based on the driver config
	switch config.Driver {
	case "postgres":
		// Use slog Info
		appLogger.Info("Configuring PostgreSQL driver", "dsn_provided", config.DSN != "") // Log DSN carefully in production
		dialector = postgres.Open(config.DSN)
	case "mysql": // MariaDB uses the MySQL driver
		// Use slog Info
		appLogger.Info("Configuring MySQL/MariaDB driver", "dsn_provided", config.DSN != "") // Log DSN carefully in production
		dialector = mysql.Open(config.DSN)
	default:
		err := fmt.Errorf("unsupported database driver: %s", config.Driver)
		// Use slog Error
		appLogger.Error("Unsupported database driver", "driver", config.Driver)
		return nil, err
	}

	// Determine GORM logger level
	gormLogLevel := gormlogger.Warn // Default to Warn
	switch config.LogLevel {
	case "silent":
		gormLogLevel = gormlogger.Silent
	case "error":
		gormLogLevel = gormlogger.Error
	case "warn":
		gormLogLevel = gormlogger.Warn
	case "info":
		gormLogLevel = gormlogger.Info
	default:
		appLogger.Warn("Unknown GORM log level specified, using default", "level_provided", config.LogLevel, "level_used", "warn")
	}

	// Configure GORM logger
	// GORM's logger needs an implementation of its logger.Interface.
	// We can create a simple one that wraps our slog.Logger.
	// Or, for simplicity here, use GORM's default logger but configure its output/level.
	newGormLogger := gormlogger.New(
		// Use a writer compatible with log.New (os.Stdout is fine)
		// This GORM logger will format its own messages.
		slog.NewLogLogger(appLogger.Handler(), slog.LevelInfo), // Wrap slog handler for standard log compatibility
		gormlogger.Config{
			SlowThreshold:             200 * time.Millisecond, // Adjust as needed
			LogLevel:                  gormLogLevel,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false, // Usually false for structured logging
		},
	)

	gormConfig := &gorm.Config{
		Logger: newGormLogger,
		// Add other GORM configurations if needed (e.g., NamingStrategy)
	}

	// Open the database connection
	appLogger.Info("Attempting to connect to database...")
	db, err := gorm.Open(dialector, gormConfig)
	if err != nil {
		// Use slog Error
		appLogger.Error("Failed to connect to database", "error", err)
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	appLogger.Info("Database connection established successfully.")

	// Configure connection pool settings
	sqlDB, err := db.DB()
	if err != nil {
		// Use slog Error
		appLogger.Error("Failed to get underlying sql.DB", "error", err)
		// Don't necessarily fail the whole connection for this, maybe just log
		// return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	} else {
		maxIdle := 10
		if config.MaxIdleConns > 0 {
			maxIdle = config.MaxIdleConns
		}
		maxOpen := 100
		if config.MaxOpenConns > 0 {
			maxOpen = config.MaxOpenConns
		}
		maxLifetime := time.Hour
		if config.ConnMaxLifeTime > 0 {
			maxLifetime = config.ConnMaxLifeTime
		}

		sqlDB.SetMaxIdleConns(maxIdle)
		sqlDB.SetMaxOpenConns(maxOpen)
		sqlDB.SetConnMaxLifetime(maxLifetime)
		// Use slog Info
		appLogger.Info("Database pool configured",
			"max_idle_conns", maxIdle,
			"max_open_conns", maxOpen,
			"conn_max_lifetime", maxLifetime)
	}

	return db, nil
}

// Migrate runs GORM auto-migrations for the defined models.
// CHANGE the appLogger parameter type:
func Migrate(db *gorm.DB, appLogger *slog.Logger) error {
	// Use slog Info
	appLogger.Info("Starting database auto-migration...")

	// Add all GORM models that need tables created or updated
	err := db.AutoMigrate(
		&gorm_models.GormUser{},
		// Add other GORM models here
	)

	if err != nil {
		// Use slog Error
		appLogger.Error("Database auto-migration failed", "error", err)
		return fmt.Errorf("database auto-migration failed: %w", err)
	}

	appLogger.Info("Database auto-migration completed successfully.")
	return nil
}
