# 

# Load environment variables from .env if it exists
ifneq (,$(wildcard ./.env))
	include .env
	export
endif

BINARY_NAME := server
BUILD_DIR := ./out
CMD_PATH := ./cmd/server

.PHONY: build run test migrate-up migrate-down lint

## build: compile the server binary to ./out
build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

## run: run the server locally
run:
	go run $(CMD_PATH)

## test: run the test suite
test:
	go test -v -race ./...

## migrate-up: apply pending migrations
migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

## migrate-down: roll back the last migration
migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down 1

## lint: run golangci-lint
lint:
	golangci-lint run ./...
