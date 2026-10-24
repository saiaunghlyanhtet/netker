package datapath

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -output-stem netker_bpf netker ../../bpf/netker.c
//go:generate clang -O2 -g -Wall -Werror -target bpf -I../../bpf/include -c ../../examples/hooks/drop_tcp_port.c -o testdata/drop_tcp_port.o
