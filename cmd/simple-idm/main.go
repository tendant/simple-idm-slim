package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/config"
	httpserver "github.com/tendant/simple-idm-slim/internal/http"
	"github.com/tendant/simple-idm-slim/internal/notification"
	"github.com/tendant/simple-idm-slim/internal/repository"
)

func main() {
	// Load .env file if present (ignore error if not found)
	_ = godotenv.Load()

	// Setup logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Connect to database
	db, err := repository.NewDB(repository.Config{
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
		User:     cfg.DBUser,
		Password: cfg.DBPassword,
		DBName:   cfg.DBName,
		SSLMode:  cfg.DBSSLMode,
	})
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	logger.Info("connected to database")

	// Initialize repositories
	usersRepo := repository.NewUsersRepository(db)
	credsRepo := repository.NewCredentialsRepository(db)
	identitiesRepo := repository.NewIdentitiesRepository(db)
	sessionsRepo := repository.NewSessionsRepository(db)
	verificationTokensRepo := repository.NewVerificationTokensRepository(db)

	// Initialize services
	passwordService := auth.NewPasswordService(db, usersRepo, credsRepo)
	sessionService := auth.NewSessionService(auth.SessionConfig{
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		JWTSecret:       []byte(cfg.JWTSecret),
		Issuer:          cfg.JWTIssuer,
	}, sessionsRepo, usersRepo)

	verificationService := auth.NewVerificationService(auth.VerificationConfig{
		EmailVerificationTTL: cfg.EmailVerificationTTL,
		PasswordResetTTL:     cfg.PasswordResetTTL,
	}, db, verificationTokensRepo, usersRepo)

	// Initialize email service if configured
	var emailService *notification.EmailService
	if cfg.HasSMTP() {
		emailService = notification.NewEmailService(notification.EmailConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			User:     cfg.SMTPUser,
			Password: cfg.SMTPPassword,
			From:     cfg.SMTPFrom,
			FromName: cfg.SMTPFromName,
		})
		logger.Info("email service enabled")
	}

	// Initialize Google service if configured
	var googleService *auth.GoogleService
	if cfg.HasGoogleOAuth() {
		googleService = auth.NewGoogleService(
			auth.GoogleConfig{
				ClientID:     cfg.GoogleClientID,
				ClientSecret: cfg.GoogleClientSecret,
				RedirectURI:  cfg.GoogleRedirectURI,
			},
			db,
			usersRepo,
			identitiesRepo,
		)
		logger.Info("Google OAuth enabled")
	}

	// Create router
	router := httpserver.NewRouter(httpserver.RouterConfig{
		Logger:              logger,
		PasswordService:     passwordService,
		GoogleService:       googleService,
		SessionService:      sessionService,
		VerificationService: verificationService,
		EmailService:        emailService,
		UsersRepo:           usersRepo,
		AppBaseURL:          cfg.AppBaseURL,
	})

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.ServerAddr, cfg.ServerPort)
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("starting server", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server shutdown error", "error", err)
	}

	logger.Info("server stopped")
}
