package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig
	Redis         RedisConfig
	JWT           JWTConfig
	Argon2        Argon2Config
	RateLimit     RateLimitConfig
	Secure        SecureConfig
	RLS           RLSConfig
	MagicLink          MagicLinkConfig
	PasswordReset      PasswordResetConfig
	EmailVerification  EmailVerificationConfig
	WebAuthn           WebAuthnConfig
	OAuth         OAuthConfig
}

type WebAuthnConfig struct {
	RPID          string   // Relying Party ID (e.g. localhost or your domain)
	RPOrigins     []string // Allowed origins (e.g. https://app.example.com)
	RPDisplayName string   // Display name for the RP
	Timeout       int      // Challenge timeout in ms (optional)
}

type PasswordResetConfig struct {
	BaseURL    string // e.g. https://app.example.com/reset-password (link in email)
	ExpirySecs int64  // token TTL (e.g. 3600 = 1 hour)
}

// EmailVerificationConfig for optional email verification after signup.
type EmailVerificationConfig struct {
	BaseURL    string // e.g. https://app.example.com/verify-email (link in email)
	ExpirySecs int64  // token TTL (e.g. 86400 = 24h)
	Enabled    bool   // if true, send verification after signup and optionally guard routes
}

type OAuthConfig struct {
	CallbackBaseURL string // e.g. https://api.example.com (no trailing slash)
	RedirectURL     string // where to send user after OAuth with tokens, e.g. https://app.example.com/auth/callback
	SessionSecret   string // for gothic cookie store
	Google          OAuthProviderConfig
}

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

type MagicLinkConfig struct {
	BaseURL     string // e.g. https://app.example.com/auth/callback
	ExpirySecs  int64  // token TTL
}

type RedisConfig struct {
	URL string // optional; used for Asynq and health check
}

type RateLimitConfig struct {
	// Per IP ("100-M" = 100/min). Empty = disabled.
	RatePerIP string
	// Per project ("200-M"). Empty = disabled.
	RatePerProject string
}

type SecureConfig struct {
	// IsDevelopment disables strict host/SSL/STS in dev.
	IsDevelopment bool
}

type RLSConfig struct {
	// Enabled turns on Row-Level Security for users and refresh_tokens.
	Enabled bool
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
		Redis: RedisConfig{
			URL: getEnvOrDefault("REDIS_URL", ""),
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
	cfg.RateLimit = RateLimitConfig{
		RatePerIP:      getEnvOrDefault("RATE_LIMIT_PER_IP", "100-M"),
		RatePerProject: getEnvOrDefault("RATE_LIMIT_PER_PROJECT", "200-M"),
	}
	cfg.Secure = SecureConfig{
		IsDevelopment: getEnvOrDefault("SECURE_IS_DEV", "true") == "true" || os.Getenv("SECURE_IS_DEV") == "1",
	}
	cfg.RLS = RLSConfig{
		Enabled: getEnvOrDefault("RLS_ENABLED", "false") == "true" || os.Getenv("RLS_ENABLED") == "1",
	}
	cfg.MagicLink = MagicLinkConfig{
		BaseURL:    getEnvOrDefault("MAGIC_LINK_BASE_URL", "http://localhost:8080"),
		ExpirySecs: viper.GetInt64("MAGIC_LINK_EXPIRY_SECONDS"),
	}
	if cfg.MagicLink.ExpirySecs <= 0 {
		cfg.MagicLink.ExpirySecs = 900 // 15 min
	}
	cfg.PasswordReset = PasswordResetConfig{
		BaseURL:    getEnvOrDefault("PASSWORD_RESET_BASE_URL", "http://localhost:3000/reset-password"),
		ExpirySecs: viper.GetInt64("PASSWORD_RESET_EXPIRY_SECONDS"),
	}
	if cfg.PasswordReset.ExpirySecs <= 0 {
		cfg.PasswordReset.ExpirySecs = 3600 // 1 hour
	}
	cfg.EmailVerification = EmailVerificationConfig{
		BaseURL:    getEnvOrDefault("EMAIL_VERIFICATION_BASE_URL", "http://localhost:3000/verify-email"),
		ExpirySecs: viper.GetInt64("EMAIL_VERIFICATION_EXPIRY_SECONDS"),
		Enabled:    getEnvOrDefault("EMAIL_VERIFICATION_ENABLED", "false") == "true" || os.Getenv("EMAIL_VERIFICATION_ENABLED") == "1",
	}
	if cfg.EmailVerification.ExpirySecs <= 0 {
		cfg.EmailVerification.ExpirySecs = 86400 // 24h
	}
	cfg.WebAuthn = WebAuthnConfig{
		RPID:          getEnvOrDefault("WEBAUTHN_RP_ID", "localhost"),
		RPDisplayName: getEnvOrDefault("WEBAUTHN_RP_DISPLAY_NAME", "Nonce"),
		Timeout:       60000,
	}
	if o := os.Getenv("WEBAUTHN_RP_ORIGINS"); o != "" {
		for _, p := range strings.Split(o, ",") {
			if t := strings.TrimSpace(p); t != "" {
				cfg.WebAuthn.RPOrigins = append(cfg.WebAuthn.RPOrigins, t)
			}
		}
	}
	if len(cfg.WebAuthn.RPOrigins) == 0 {
		cfg.WebAuthn.RPOrigins = []string{getEnvOrDefault("WEBAUTHN_RP_ORIGIN", "http://localhost:3000")}
	}
	cfg.OAuth = OAuthConfig{
		CallbackBaseURL: getEnvOrDefault("OAUTH_CALLBACK_BASE_URL", "http://localhost:8080"),
		RedirectURL:     getEnvOrDefault("OAUTH_REDIRECT_URL", "http://localhost:3000/auth/callback"),
		SessionSecret:   getEnvOrDefault("OAUTH_SESSION_SECRET", "nonce-oauth-secret-change-me"),
		Google: OAuthProviderConfig{
			ClientID:     getEnvOrDefault("OAUTH_GOOGLE_CLIENT_ID", ""),
			ClientSecret: getEnvOrDefault("OAUTH_GOOGLE_CLIENT_SECRET", ""),
		},
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
