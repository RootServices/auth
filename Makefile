.PHONY: clean run test test-yaegi build version
PROJECT_ID?="barncat"
SHORT_SHA?=`git rev-parse --short HEAD`

version:
	mkdir -p internal/version
	echo "{" > internal/version/version.json
	echo "  \"build\": \"$(SHORT_SHA)\"," >> internal/version/version.json
	echo "  \"branch\": \"$(BRANCH)\"" >> internal/version/version.json
	echo "}" > internal/version/version.json

test: version
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-wasm: version
	GOOS=js GOARCH=wasm go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

build: version
	go build ./...

build-wasm: version
	GOOS=js GOARCH=wasm go build -o bin/main.wasm ./main.go
