# gatekeep — one command gates everything: `make check`.
GO            ?= go
GOLANGCI_LINT ?= golangci-lint
COVER_MIN     ?= 85
export GOFLAGS ?= -p=3
SHELL         := /bin/bash
.SHELLFLAGS   := -o pipefail -c

# "Core" = everything under internal/ except demo/test scaffolding.
CORE_PKGS := $(shell $(GO) list ./internal/... | grep -v -e /internal/demo -e /idptest -e /internal/e2e -e /internal/bench | paste -sd, -)

.PHONY: check fmt-check vet lint test cover-report demo bench fuzz build quickstart clean

check: fmt-check vet lint test ## format + vet + lint + race tests + coverage gate

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi; echo "gofmt: ok"

vet:
	$(GO) vet ./...

lint:
	$(GOLANGCI_LINT) run ./...

# Race-enabled tests with cross-package coverage of core packages (the e2e
# suite exercises gateway/oidc/idp code from another package).
test:
	$(GO) test -race -count=1 -coverpkg=$(CORE_PKGS) -coverprofile=coverage.out ./... | sed -E 's/ of statements in .*//'
	@./scripts/coverage-gate.sh coverage.out $(COVER_MIN)

cover-report: test
	$(GO) tool cover -func=coverage.out | sort -k3 -n | head -25

demo:
	$(GO) run ./cmd/gatekeep-demo

bench:
	$(GO) test -run='^$$' -bench=. -benchmem -count=1 ./internal/bench/

fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzParse -fuzztime=20s ./internal/jose/
	$(GO) test -run='^$$' -fuzz=FuzzJWK -fuzztime=20s ./internal/jose/
	$(GO) test -run='^$$' -fuzz=FuzzOpen -fuzztime=20s ./internal/session/

build:
	$(GO) build -o bin/ ./cmd/...

quickstart:
	./scripts/quickstart.sh

clean:
	rm -rf bin coverage.out .gatekeep
