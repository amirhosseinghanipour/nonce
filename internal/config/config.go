package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Argon2   Argon2Config
}

type ServerConfig struct {
	Port string
}

type DatabaseConfig struct {
	URL string
}

type JWTConfig struct {
	PrivateKeyPath string
	Issuer         string
	Audience       string
	AccessExpiry   int64 // seconds
	RefreshExpiry  int64 // seconds
}

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

func Load() (*Config, error) {
	viper.AutomaticEnv()
	if p := os.Getenv("CONFIG_FILE"); p != "" {
		viper.SetConfigFile(p)
		_ = viper.ReadInConfig()
	}

	cfg := &Config{
		Server: ServerConfig{
			Port: getEnvOrDefault("PORT", "8080"),
		},
		Database: DatabaseConfig{
			URL: getEnvOrDefault("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/nonce?sslmode=disable"),
		},
		JWT: JWTConfig{
			PrivateKeyPath: getEnvOrDefault("JWT_PRIVATE_KEY_PATH", ""),
			Issuer:         getEnvOrDefault("JWT_ISSUER", "nonce"),
			Audience:       getEnvOrDefault("JWT_AUDIENCE", "nonce"),
			AccessExpiry:   viper.GetInt64("JWT_ACCESS_EXPIRY"),
			RefreshExpiry:  viper.GetInt64("JWT_REFRESH_EXPIRY"),
		},
		Argon2: Argon2Config{
			Memory:      uint32(viper.GetInt("ARGON2_MEMORY")),
			Iterations:  uint32(viper.GetInt("ARGON2_ITERATIONS")),
			Parallelism: uint8(viper.GetInt("ARGON2_PARALLELISM")),
		},
	}
	if cfg.JWT.AccessExpiry <= 0 {
		cfg.JWT.AccessExpiry = 900
	}
	if cfg.JWT.RefreshExpiry <= 0 {
		cfg.JWT.RefreshExpiry = 604800
	}
	if cfg.Argon2.Memory == 0 {
		cfg.Argon2.Memory = 64 * 1024
	}
	if cfg.Argon2.Iterations == 0 {
		cfg.Argon2.Iterations = 3
	}
	if cfg.Argon2.Parallelism == 0 {
		cfg.Argon2.Parallelism = 2
	}
	return cfg, nil
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// LoadJWTPrivateKey reads the PEM file and returns its contents.
func (c *Config) LoadJWTPrivateKey() ([]byte, error) {
	if c.JWT.PrivateKeyPath == "" {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY_PATH is required")
	}
	return os.ReadFile(c.JWT.PrivateKeyPath)
}
