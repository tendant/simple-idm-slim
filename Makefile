.DEFAULT_GOAL := help

# Load .env file if present
-include .env
export

.PHONY: build run test test-cover lint fmt clean help
.PHONY: migrate-up migrate-down migrate-status migrate-create migrate-reset
.PHONY: postgres-start postgres-stop postgres-logs

# Database connection string (built from .env or defaults)
DB_HOST ?= localhost
DB_PORT ?= 25432
DB_USER ?= postgres
DB_PASSWORD ?= postgres
DB_NAME ?= simple_idm
DB_SSLMODE ?= disable
DB_URL ?= postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSLMODE)

# Build the standalone server
build:
	go build -o bin/simple-idm ./cmd/simple-idm

# Run the standalone server
run:
	go run ./cmd/simple-idm

# Run all tests
test:
	go test ./...

# Run tests with coverage
test-cover:
	go test -cover ./...

# Run tests with coverage report
test-cover-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Format code
fmt:
	go fmt ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Tidy dependencies
tidy:
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Install goose CLI
install-goose:
	go install github.com/pressly/goose/v3/cmd/goose@latest

# Run migrations up
migrate-up:
	goose -dir migrations postgres "$(DB_URL)" up

# Run migrations down (one step)
migrate-down:
	goose -dir migrations postgres "$(DB_URL)" down

# Show migration status
migrate-status:
	goose -dir migrations postgres "$(DB_URL)" status

# Create a new migration
migrate-create:
	@read -p "Migration name: " name; \
	goose -dir migrations create $$name sql

# Reset database (down all, then up all)
migrate-reset:
	goose -dir migrations postgres "$(DB_URL)" reset
	goose -dir migrations postgres "$(DB_URL)" up

# Start PostgreSQL 17 in Podman
postgres-start:
	podman run -d --name simple-idm-postgres \
		-e POSTGRES_USER=postgres \
		-e POSTGRES_PASSWORD=postgres \
		-e POSTGRES_DB=simple_idm \
		-p 25432:5432 \
		postgres:17

# Stop PostgreSQL container
postgres-stop:
	podman stop simple-idm-postgres && podman rm simple-idm-postgres

# Show PostgreSQL logs
postgres-logs:
	podman logs -f simple-idm-postgres

# Show help
help:
	@echo "Available targets:"
	@echo ""
	@echo "  Build & Run:"
	@echo "    build            - Build the standalone server"
	@echo "    run              - Run the standalone server"
	@echo ""
	@echo "  Testing:"
	@echo "    test             - Run all tests"
	@echo "    test-cover       - Run tests with coverage summary"
	@echo "    test-cover-html  - Generate HTML coverage report"
	@echo ""
	@echo "  Code Quality:"
	@echo "    fmt              - Format code"
	@echo "    lint             - Run linter (requires golangci-lint)"
	@echo "    tidy             - Tidy go.mod dependencies"
	@echo ""
	@echo "  Database (goose):"
	@echo "    install-goose    - Install goose CLI"
	@echo "    migrate-up       - Run all pending migrations"
	@echo "    migrate-down     - Rollback one migration"
	@echo "    migrate-status   - Show migration status"
	@echo "    migrate-create   - Create a new migration"
	@echo "    migrate-reset    - Reset and re-run all migrations"
	@echo ""
	@echo "  PostgreSQL (podman):"
	@echo "    postgres-start   - Start PostgreSQL 17 on port 25432"
	@echo "    postgres-stop    - Stop and remove PostgreSQL container"
	@echo "    postgres-logs    - Follow PostgreSQL logs"
	@echo ""
	@echo "  Other:"
	@echo "    clean            - Remove build artifacts"
	@echo "    help             - Show this help"
	@echo ""
	@echo "  Configuration:"
	@echo "    Copy .env.example to .env and edit as needed."
	@echo "    Makefile loads .env automatically."
	@echo ""
	@echo "    DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSLMODE"
	@echo "    Or override with: DB_URL=postgres://... make migrate-up"
