// internal/infrastructure/persistence/database.go
package persistence

import (
	"fmt"
	"log" // TODO: Replace with a proper logger interface
	"time"

	// GORM drivers - import the ones you intend to support
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger" // GORM's logger

	// Import GORM models defined in this package
	gorm_models "github.com/mohamedhabas11/ddd-crud/internal/infrastructure/persistence/gorm" // Alias import
)

// DBConfig holds database configuration parameters.
type DBConfig struct {
	Driver string // e.g., "postgres", "mysql"
	DSN    string // Data Source Name (connection string)
	// Add other options like pool settings if needed
	MaxIdleConns    int
	MaxOpenConns    int
	ConnMaxLifeTime time.Duration
	LogLevel        string // e.g., "info", "warn", "error", "silent"
}

// NewConnection establishes a new database connection based on the config.
func NewConnection(config DBConfig, appLogger *log.Logger) (*gorm.DB, error) {
	var dialector gorm.Dialector

	// Choose the appropriate GORM dialector based on the driver config
	switch config.Driver {
	case "postgres":
		appLogger.Printf("INFO: Configuring PostgreSQL driver with DSN: %s", config.DSN) // Log DSN carefully in production
		dialector = postgres.Open(config.DSN)
	case "mysql": // MariaDB uses the MySQL driver
		appLogger.Printf("INFO: Configuring MySQL/MariaDB driver with DSN: %s", config.DSN) // Log DSN carefully in production
		dialector = mysql.Open(config.DSN)
	default:
		err := fmt.Errorf("unsupported database driver: %s", config.Driver)
		appLogger.Printf("ERROR: %v", err)
		return nil, err
	}

	// Determine GORM logger level
	gormLogLevel := logger.Warn // Default to Warn
	switch config.LogLevel {
	case "silent":
		gormLogLevel = logger.Silent
	case "error":
		gormLogLevel = logger.Error
	case "warn":
		gormLogLevel = logger.Warn
	case "info":
		gormLogLevel = logger.Info
	}

	// Configure GORM logger (using standard Go logger for output)
	newLogger := logger.New(
		log.New(appLogger.Writer(), "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,  // Slow SQL threshold
			LogLevel:                  gormLogLevel, // Log level
			IgnoreRecordNotFoundError: true,         // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,        // Disable color
		},
	)

	gormConfig := &gorm.Config{
		Logger: newLogger.LogMode(gormLogLevel),
		// Add other GORM configurations if needed (e.g., NamingStrategy)
	}

	// Open the database connection
	appLogger.Println("INFO: Attempting to connect to database...")
	db, err := gorm.Open(dialector, gormConfig)
	if err != nil {
		appLogger.Printf("ERROR: Failed to connect to database: %v", err)
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	appLogger.Println("INFO: Database connection established successfully.")

	// Configure connection pool settings
	sqlDB, err := db.DB()
	if err != nil {
		appLogger.Printf("ERROR: Failed to get underlying sql.DB: %v", err)
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

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
	appLogger.Printf("INFO: Database pool configured: MaxIdle=%d, MaxOpen=%d, MaxLifetime=%v", maxIdle, maxOpen, maxLifetime)

	return db, nil
}

// Migrate runs GORM auto-migrations for the defined models.
// Pass pointers to the GORM model structs you want to migrate.
func Migrate(db *gorm.DB, appLogger *log.Logger) error {
	appLogger.Println("INFO: Starting database auto-migration...")

	// Add all GORM models that need tables created or updated
	err := db.AutoMigrate(
		&gorm_models.GormUser{},
		// Add other GORM models here as they are created, e.g.:
		// &gorm_models.GormShop{},
		// &gorm_models.GormInventory{},
		// &gorm_models.GormOrder{},
	)

	if err != nil {
		appLogger.Printf("ERROR: Database auto-migration failed: %v", err)
		return fmt.Errorf("database auto-migration failed: %w", err)
	}

	appLogger.Println("INFO: Database auto-migration completed successfully.")
	return nil
}
