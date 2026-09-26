VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/saiaunghlyanhtet/netker/internal/cli.Version=$(VERSION)

.PHONY: build test test-integration e2e check fmt vet

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/netker ./cmd/netker

test:
	go test ./...

# Creates real netkit devices inside an unprivileged user+net namespace.
test-integration:
	unshare -rnm go test -count=1 ./internal/network/

# Full CLI test without root, inside hack/sandbox.sh.
e2e: build
	hack/sandbox.sh pull alpine
	hack/sandbox.sh hack/e2e.sh

check: build
	bin/netker system check

fmt:
	gofmt -w .

vet:
	go vet ./...
