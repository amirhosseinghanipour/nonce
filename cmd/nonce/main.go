package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/application/auth"
	"github.com/amirhosseinghanipour/nonce/internal/config"
	infraauth "github.com/amirhosseinghanipour/nonce/internal/infrastructure/auth"
	httprouter "github.com/amirhosseinghanipour/nonce/internal/infrastructure/http"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/handlers"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/postgres"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/security"
)

func main() {
	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect to database")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatal().Err(err).Msg("ping database")
	}

	queries := db.New(pool)
	userRepo := postgres.NewUserRepository(queries, pool, cfg.RLS.Enabled)
	projectRepo := postgres.NewProjectRepository(queries)
	tokenStore := postgres.NewTokenStore(queries)

	hasher := security.NewArgon2Hasher(security.Argon2Params{
		Memory:      cfg.Argon2.Memory,
		Iterations:  cfg.Argon2.Iterations,
		Parallelism: cfg.Argon2.Parallelism,
		SaltLength:  16,
		KeyLength:   32,
	})

	pemBytes, err := cfg.LoadJWTPrivateKey()
	if err != nil {
		log.Fatal().Err(err).Msg("load JWT private key")
	}
	privateKey, err := infraauth.LoadRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		log.Fatal().Err(err).Msg("parse JWT private key")
	}
	issuer := infraauth.NewTokenIssuer(privateKey, cfg.JWT.Issuer, cfg.JWT.Audience)

	registerUC := auth.NewRegisterUser(userRepo, hasher)
	loginUC := auth.NewLogin(userRepo, hasher, issuer, tokenStore, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)
	refreshUC := auth.NewRefresh(issuer, tokenStore, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)

	hashAPIKey := func(key string) string {
		h := sha256.Sum256([]byte(key))
		return hex.EncodeToString(h[:])
	}
	tenantResolver := middleware.NewTenantResolver(projectRepo, hashAPIKey)

	ipLimit, err := middleware.NewIPRateLimiter(cfg.RateLimit.RatePerIP)
	if err != nil {
		log.Fatal().Err(err).Msg("create IP rate limiter")
	}
	projectLimit, err := middleware.NewProjectRateLimiter(cfg.RateLimit.RatePerProject)
	if err != nil {
		log.Fatal().Err(err).Msg("create project rate limiter")
	}
	secureMiddleware := middleware.NewSecure(middleware.SecureOptions(cfg.Secure.IsDevelopment))

	authHandler := handlers.NewAuthHandler(registerUC, loginUC, refreshUC, log)
	router := httprouter.NewRouter(httprouter.RouterConfig{
		AuthHandler:      authHandler,
		Tenant:           tenantResolver,
		Log:              log,
		Secure:           secureMiddleware,
		IPRateLimit:      ipLimit,
		ProjectRateLimit: projectLimit,
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Info().Str("port", cfg.Server.Port).Msg("server starting")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("server shutdown")
	}
	log.Info().Msg("server stopped")
}
