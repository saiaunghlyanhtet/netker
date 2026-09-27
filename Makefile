VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/saiaunghlyanhtet/netker/internal/cli.Version=$(VERSION)

.PHONY: build test test-integration test-ebpf e2e e2e-root check fmt vet

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

# eBPF datapath tests need real root. They run in a throwaway privileged
# container, which has its own network namespace and bpffs mount.
test-ebpf:
	CGO_ENABLED=0 go test -c -o bin/network.test ./internal/network/
	docker run --rm --privileged -v $(CURDIR)/bin:/t:ro alpine:latest sh -c \
		'apk add -q nftables && mount -t bpf bpf /sys/fs/bpf && /t/network.test -test.v -test.count=1'

# Full CLI test as real root (eBPF datapath) in a throwaway privileged
# container. The state dir is a tmpfs because overlayfs can't use Docker's
# overlay root as its upper layer.
e2e-root: build
	docker run --rm --privileged --tmpfs /var/lib/netker -v $(CURDIR):/src:ro -w /src alpine:latest sh -c \
		'apk add -q bash crun nftables curl iproute2 && mount -t bpf bpf /sys/fs/bpf && \
		 export PATH=/src/bin:$$PATH && netker system check; netker pull alpine >/dev/null && hack/e2e.sh'
