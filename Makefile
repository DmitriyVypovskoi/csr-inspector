APP_NAME := csr-inspector
MAIN_PACKAGE := ./cmd/server

.PHONY: run
run:
	go run $(MAIN_PACKAGE)

.PHONY: build
build:
	go build -o ./bin/$(APP_NAME) $(MAIN_PACKAGE)

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	go test -race ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: check
check: fmt vet test

.PHONY: clean
clean:
	go clean
	rm -rf ./bin