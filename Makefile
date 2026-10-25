VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/saiaunghlyanhtet/netker/internal/cli.Version=$(VERSION)

.PHONY: build test test-integration test-ebpf e2e e2e-root e2e-ubuntu check fmt vet generate check-generate

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

# The BPF objects are committed (go:embed needs them, and "go install" never
# runs go generate), so they're built in a pinned container: the same clang
# and libbpf headers everywhere, and byte-identical output. The image digest
# pins Go and Debian trixie, whose clang-19, llvm-19 and libbpf-dev it installs.
BPF_BUILDER = golang:1.26.4-trixie@sha256:68b7145ec43d1820b9a56704554b53d1520aa2a15cb5233e374188a31b2a1bce

generate:
	docker run --rm -v $(CURDIR):/src -v netker-gomod:/go/pkg/mod -w /src -e GOFLAGS=-buildvcs=false -e DEBIAN_FRONTEND=noninteractive $(BPF_BUILDER) sh -c \
		'apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends clang-19 llvm-19 libbpf-dev >/dev/null && \
		 ln -s /usr/bin/clang-19 /usr/local/bin/clang && ln -s /usr/bin/llvm-strip-19 /usr/local/bin/llvm-strip && \
		 ln -s /usr/include/$$(uname -m)-linux-gnu/asm /usr/include/asm && go generate ./internal/datapath/ && \
		 chown $(shell id -u):$(shell id -g) internal/datapath/netker_bpf_bpfel.* internal/datapath/testdata/drop_tcp_port.o'

# Fails if the committed BPF objects don't match bpf/ and examples/hooks/.
check-generate: generate
	git diff --exit-code -- internal/datapath/

# eBPF datapath tests need real root. They run in a throwaway privileged
# container, which has its own network namespace and bpffs mount.
test-ebpf:
	CGO_ENABLED=0 go test -c -o bin/network.test ./internal/network/
	docker run --rm --privileged -v $(CURDIR)/bin:/t:ro alpine:latest sh -c \
		'apk add -q nftables && mount -t bpf bpf /sys/fs/bpf && /t/network.test -test.v -test.count=1 -test.timeout 10m'

# Inside a Docker container the cgroup root holds processes, so cgroup v2
# won't enable the memory and io controllers for children (the "no
# internal processes" rule). Move everything into a child first, as
# Docker-in-Docker setups do, so container stats can be tested.
CGROUP_DELEGATE = mkdir -p /sys/fs/cgroup/init && \
	for p in $$(cat /sys/fs/cgroup/cgroup.procs); do echo $$p > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true; done && \
	echo "+memory +io +pids +cpu" > /sys/fs/cgroup/cgroup.subtree_control

# Full CLI test as real root (eBPF datapath) in a throwaway privileged
# container. The state dir is a tmpfs because overlayfs can't use Docker's
# overlay root as its upper layer.
e2e-root: build
	docker run --rm --privileged --tmpfs /var/lib/netker -v $(CURDIR):/src:ro -w /src alpine:latest sh -c \
		'apk add -q bash crun nftables curl iproute2 && mount -t bpf bpf /sys/fs/bpf && $(CGROUP_DELEGATE) && \
		 export PATH=/src/bin:$$PATH && netker system check; netker pull alpine >/dev/null && E2E_INTERNET=1 hack/e2e.sh'

# The e2e suite with Ubuntu 24.04's userspace (crun 1.14, iproute2 6.1), as
# on the GitHub runners, which is older than most dev machines.
e2e-ubuntu: build
	docker run --rm --privileged --tmpfs /var/lib/netker -v $(CURDIR):/src:ro -w /src ubuntu:24.04 bash -c \
		'export DEBIAN_FRONTEND=noninteractive && apt-get update -qq >/dev/null && \
		 apt-get install -y -qq crun nftables curl iproute2 >/dev/null 2>&1 && mount -t bpf bpf /sys/fs/bpf && $(CGROUP_DELEGATE) && \
		 export PATH=/src/bin:$$PATH && netker pull alpine >/dev/null && hack/e2e.sh'
