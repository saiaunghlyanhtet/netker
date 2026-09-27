package datapath

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -output-stem netker_bpf netker ../../bpf/netker.c
