VERSION := $(shell git describe --always --dirty --tags)
LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

.PHONY: all
all: lint test build

.PHONY: lint
lint:
	@$(LINT) run
	@$(LINT) fmt -d

.PHONY: test
test:
	@go test ./...

.PHONY: build
build:
	@go build -ldflags "-X main.version=$(VERSION)" -o hush .

.PHONY: clean
clean:
	@rm -f hush
