.PHONY: all build build-web test test-race test-postgres test-replicas test-web tidy-check lint pqc-tls-check smoke ci run clean docker-build notes-check audit-web

all: build-web build

build-web:
	@echo "==> Building frontend web assets..."
	@cd web && npm ci && npm run build

build:
	@echo "==> Compiling kyguard-server binary..."
	@go build -o kyguard-server ./cmd/server
	@go build -o kyguard-cli ./cmd/cli
	@GOOS=linux go build -o kyguard-broker ./cmd/broker

test:
	@echo "==> Running test suite..."
	@go test -v ./...

test-race:
	@echo "==> Running test suite with race detector..."
	@go test -race -covermode=atomic -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

# Runs the same suite against PostgreSQL; needs a reachable server.
test-postgres:
	@echo "==> Running test suite against PostgreSQL..."
	@KY_TEST_POSTGRES_DSN="$${KY_TEST_POSTGRES_DSN:-postgres://postgres:postgrespassword@127.0.0.1:5432/ky_server?sslmode=disable}" go test -count=1 ./...

# Builds the image and runs the Compose replica failure tests (Docker; a few minutes). The
# test removes its own project; relays stay off in every throwaway container.
test-replicas:
	@python3 scripts/check-replicas-compose.py
	@docker build -t kyguard-server:local .
	@KY_E2E_COMPOSE=1 KY_IMAGE=kyguard-server:local PUSH_RELAY_URL= APNS_RELAY_URL= go test -count=1 -v -timeout 30m ./e2e

test-web:
	@echo "==> Running frontend test suite..."
	@cd web && npm ci && npm test

audit-web:
	@cd web && npm run audit

# The same gate CI runs: a stale go.sum fails the build there, so fail here first.
tidy-check:
	@echo "==> Checking go.mod is tidy..."
	@go mod tidy
	@git diff --exit-code go.mod go.sum

lint:
	@echo "==> Checking formatting and vet..."
	@test -z "$$(gofmt -l $$(git ls-files '*.go'))" || { echo "gofmt needed:"; gofmt -l $$(git ls-files '*.go'); exit 1; }
	@go vet ./...

pqc-tls-check:
	@echo "==> Checking post-quantum TLS guard..."
	@./scripts/check-pqc-tls.sh

smoke: build
	@./scripts/smoke-test.sh

notes-check:
	@python3 -B -m unittest discover -s scripts -p test_release_notes.py
	@python3 scripts/check-release-notes.py

ci: notes-check tidy-check lint pqc-tls-check test-race test-web audit-web smoke
	@echo "==> Local CI checks passed"

run: build
	@./kyguard-server

docker-build:
	@docker build -t kyguard-server .

clean:
	@rm -rf kyguard-server kyguard-cli kyguard-broker web/dist web/node_modules coverage.out
