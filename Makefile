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

yaegi-test:
	go install github.com/traefik/yaegi/cmd/yaegi@latest
	mkdir -p .tmp/src/github.com/rootservices
	ln -sf $(CURDIR) .tmp/src/github.com/rootservices/auth
	@echo "Running yaegi test..."
	@GOPATH=$(CURDIR)/.tmp yaegi test -v -unsafe -tags=yaegi github.com/rootservices/auth || (rm -rf .tmp; exit 1)
	rm -rf .tmp