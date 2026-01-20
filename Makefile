.PHONY: build run test test-cover lint fmt clean help
.PHONY: migrate-up migrate-down migrate-status migrate-create migrate-reset

# Database connection string (override with environment variable)
DB_URL ?= postgres://localhost/simple_idm?sslmode=disable

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
	@echo "  Other:"
	@echo "    clean            - Remove build artifacts"
	@echo "    help             - Show this help"
	@echo ""
	@echo "  Environment variables:"
	@echo "    DB_URL           - Database connection string"
	@echo "                       Default: postgres://localhost/simple_idm?sslmode=disable"
