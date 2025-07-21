.PHONY: build clean test run

# Build the Dyphira blockchain
build:
	go build -o bin/dyphira-node cmd/dyphira/main.go

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f dyphira.db

# Run tests
test:
	go test ./...

# Run the node
run: build
	./bin/dyphira-node start

# Create a new account
account: build
	./bin/dyphira-node create-account

# Show help
help: build
	./bin/dyphira-node

# Install dependencies
deps:
	go mod tidy
	go mod download

# Build for different platforms
build-linux:
	GOOS=linux GOARCH=amd64 go build -o bin/dyphira-node-linux cmd/dyphira/main.go

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -o bin/dyphira-node-darwin cmd/dyphira/main.go

build-windows:
	GOOS=windows GOARCH=amd64 go build -o bin/dyphira-node-windows.exe cmd/dyphira/main.go

# Build all platforms
build-all: build-linux build-darwin build-windows 