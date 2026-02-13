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

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/application/auth"
	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/application/project"
	"github.com/amirhosseinghanipour/nonce/internal/config"
	infraauth "github.com/amirhosseinghanipour/nonce/internal/infrastructure/auth"
	httprouter "github.com/amirhosseinghanipour/nonce/internal/infrastructure/http"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/handlers"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/postgres"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/queue"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/security"
	webauthnsvc "github.com/amirhosseinghanipour/nonce/internal/infrastructure/webauthn"
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

	var redisClient *redis.Client
	if cfg.Redis.URL != "" {
		opt, err := redis.ParseURL(cfg.Redis.URL)
		if err != nil {
			log.Fatal().Err(err).Msg("parse REDIS_URL")
		}
		redisClient = redis.NewClient(opt)
		defer redisClient.Close()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			log.Warn().Err(err).Msg("redis ping failed; continuing without redis")
			redisClient = nil
		}
	}

	healthHandler := handlers.NewHealthHandler(pool, redisClient)

	queries := db.New(pool)
	userRepo := postgres.NewUserRepository(queries, pool, cfg.RLS.Enabled)
	projectRepo := postgres.NewProjectRepository(queries)
	tokenStore := postgres.NewTokenStore(queries)
	magicLinkStore := postgres.NewMagicLinkRepository(queries, pool)

	var taskEnqueuer ports.TaskEnqueuer
	var asynqWorker *queue.Worker
	if redisClient != nil {
		redisOpt, _ := redis.ParseURL(cfg.Redis.URL)
		asynqOpt := asynq.RedisClientOpt{Addr: redisOpt.Addr, Password: redisOpt.Password, DB: redisOpt.DB}
		asynqEnq, err := queue.NewAsynqEnqueuer(asynqOpt, log)
		if err != nil {
			log.Fatal().Err(err).Msg("create asynq enqueuer")
		}
		defer asynqEnq.Close()
		taskEnqueuer = asynqEnq
		asynqWorker = queue.NewWorker(asynqOpt, log)
		go func() {
			if err := asynqWorker.Run(); err != nil {
				log.Warn().Err(err).Msg("asynq worker stopped")
			}
		}()
	} else {
		taskEnqueuer = queue.NewNoopEnqueuer()
	}

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

	totpStore := postgres.NewTOTPRepository(queries, pool)
	const mfaPendingExpiry = 300
	registerUC := auth.NewRegisterUser(userRepo, hasher)
	loginUC := auth.NewLogin(userRepo, hasher, issuer, tokenStore, totpStore, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry, mfaPendingExpiry)
	refreshUC := auth.NewRefresh(issuer, tokenStore, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)
	issueTOTPUC := auth.NewIssueTOTP(totpStore)
	verifyTOTPUC := auth.NewVerifyTOTP(totpStore)
	verifyMFAUC := auth.NewVerifyMFA(issuer, tokenStore, totpStore, userRepo, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)
	identityStore := postgres.NewIdentityRepository(queries, pool)
	oauthCallbackUC := auth.NewOAuthCallback(identityStore, userRepo, hasher, issuer, tokenStore, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)
	handlers.InitOAuthProviders(cfg.OAuth.CallbackBaseURL, cfg.OAuth.SessionSecret, cfg.OAuth.Google.ClientID, cfg.OAuth.Google.ClientSecret)
	sendMagicLinkUC := auth.NewSendMagicLink(magicLinkStore, taskEnqueuer, cfg.MagicLink.BaseURL, cfg.MagicLink.ExpirySecs)
	verifyMagicLinkUC := auth.NewVerifyMagicLink(magicLinkStore, userRepo, hasher, issuer, tokenStore, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)
	passwordResetStore := postgres.NewPasswordResetRepository(queries, pool)
	forgotPasswordUC := auth.NewForgotPassword(passwordResetStore, userRepo, taskEnqueuer, cfg.PasswordReset.BaseURL, cfg.PasswordReset.ExpirySecs)
	resetPasswordUC := auth.NewResetPassword(passwordResetStore, userRepo, hasher)
	emailVerificationStore := postgres.NewEmailVerificationRepository(queries, pool)
	sendEmailVerificationUC := auth.NewSendEmailVerification(emailVerificationStore, userRepo, taskEnqueuer, cfg.EmailVerification.BaseURL, cfg.EmailVerification.ExpirySecs)
	verifyEmailUC := auth.NewVerifyEmail(emailVerificationStore, userRepo)
	signInAnonymousUC := auth.NewSignInAnonymous(userRepo, issuer, tokenStore, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry)

	webauthnCredStore := postgres.NewWebAuthnCredentialRepository(queries, pool)
	webauthnSvc, err := webauthnsvc.NewService(&webauthnsvc.Config{
		RPID:          cfg.WebAuthn.RPID,
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	}, webauthnCredStore, userRepo)
	if err != nil {
		log.Fatal().Err(err).Msg("create webauthn service")
	}
	webauthnHandler := handlers.NewWebAuthnHandler(webauthnSvc, issuer, tokenStore, userRepo, cfg.JWT.AccessExpiry, cfg.JWT.RefreshExpiry, log)

	hashAPIKey := func(key string) string {
		h := sha256.Sum256([]byte(key))
		return hex.EncodeToString(h[:])
	}
	tenantResolver := middleware.NewTenantResolver(projectRepo, hashAPIKey)
	createProjectUC := project.NewCreateProject(projectRepo, hashAPIKey)
	rotateProjectKeyUC := project.NewRotateProjectKey(projectRepo, hashAPIKey)
	adminHandler := handlers.NewAdminHandler(createProjectUC, rotateProjectKeyUC, userRepo, log)
	requireAdmin := middleware.RequireAdminSecret(cfg.Admin.Secret)

	ipLimit, err := middleware.NewIPRateLimiter(cfg.RateLimit.RatePerIP)
	if err != nil {
		log.Fatal().Err(err).Msg("create IP rate limiter")
	}
	projectLimit, err := middleware.NewProjectRateLimiter(cfg.RateLimit.RatePerProject)
	if err != nil {
		log.Fatal().Err(err).Msg("create project rate limiter")
	}
	secureMiddleware := middleware.NewSecure(middleware.SecureOptions(cfg.Secure.IsDevelopment))

	authHandler := handlers.NewAuthHandler(registerUC, loginUC, refreshUC, sendMagicLinkUC, verifyMagicLinkUC, forgotPasswordUC, resetPasswordUC, sendEmailVerificationUC, verifyEmailUC, signInAnonymousUC, cfg.EmailVerification.Enabled, issueTOTPUC, verifyTOTPUC, verifyMFAUC, userRepo, log)
	usersHandler := handlers.NewUsersHandler(userRepo)
	requireJWT := middleware.NewAuthValidator(issuer).Handler
	router := httprouter.NewRouter(httprouter.RouterConfig{
		AuthHandler:      authHandler,
		HealthHandler:     healthHandler,
		UsersHandler:      usersHandler,
		WebAuthnHandler:   webauthnHandler,
		AdminHandler:      adminHandler,
		Tenant:            tenantResolver,
		RequireJWT:        requireJWT,
		RequireAdmin:      requireAdmin,
		OAuthBegin:        handlers.OAuthBegin(oauthCallbackUC),
		OAuthCallback:     handlers.OAuthCallback(oauthCallbackUC, cfg.OAuth.RedirectURL),
		Log:               log,
		Secure:            secureMiddleware,
		IPRateLimit:       ipLimit,
		ProjectRateLimit:  projectLimit,
		Metrics:           true,
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
	if asynqWorker != nil {
		asynqWorker.Shutdown()
	}
	log.Info().Msg("server stopped")
}
