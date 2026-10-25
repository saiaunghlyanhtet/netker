package datapath

// bpf2go is pinned as a tool in go.mod. "make generate" runs these in a
// pinned clang container, so the committed objects are reproducible; CI
// checks that they match bpf/ (see "make check-generate").
//
// The example hook is compiled with relative debug paths: the object is
// committed, and must not depend on where the repo was checked out.
//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -output-stem netker_bpf netker ../../bpf/netker.c
//go:generate clang -O2 -g -Wall -Werror -target bpf -fdebug-compilation-dir=. -I../../bpf/include -c ../../examples/hooks/drop_tcp_port.c -o testdata/drop_tcp_port.o
