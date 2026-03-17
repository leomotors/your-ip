.PHONY: dev build preview format lint test clean

BINARY := your-ip

## dev: Run in development mode with live reload (requires air)
dev:
	@command -v air >/dev/null 2>&1 && air || go run .

## build: Compile the binary
build:
	go build -ldflags="-s -w" -o $(BINARY) .

## preview: Build and run the binary
preview: build
	./$(BINARY)

## format: Format Go source files
format:
	gofmt -w .

## lint: Run static analysis
lint:
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || go vet ./...

## test: Run unit tests
test:
	go test -v -race ./...

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)
