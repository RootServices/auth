.PHONY: clean run test build version
PROJECT_ID?="barncat"
SHORT_SHA?=`git rev-parse --short HEAD`

vendor:
	go mod tidy && go mod vendor

version:
	mkdir -p internal/version
	echo "{" > internal/version/version.json
	echo "  \"build\": \"$(SHORT_SHA)\"," >> internal/version/version.json
	echo "  \"branch\": \"$(BRANCH)\"" >> internal/version/version.json
	echo "}" > internal/version/version.json

test: version
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

build: version
	go build ./...