# Makefile for SQL Injection Detection Plugin

BINARY_NAME=injection
GO_FILES=$(wildcard *.go)

.PHONY: all build clean test install

all: build

build: $(BINARY_NAME)

$(BINARY_NAME): $(GO_FILES)
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)

test:
	@echo "Running tests..."
	go test -v ./...

install: build
	@echo "Installing plugin..."
	mkdir -p ~/.gibson/plugins/injection/
	cp $(BINARY_NAME) ~/.gibson/plugins/injection/
	cp plugin.yml ~/.gibson/plugins/injection/

.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download

.PHONY: lint
lint:
	@echo "Running linters..."
	go vet ./...
	go fmt ./...