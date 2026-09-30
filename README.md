# netker

Docker-compatible containers networked with Linux **netkit** devices
(`drivers/net/netkit.c`) instead of veth pairs and a bridge.

Each container gets a netkit pair. The primary device stays in the host,
and the peer becomes the container's `eth0`. BPF programs attached to the
pair (the approach Cilium uses for pods) decide what the container may send
and forward traffic between containers without the host stack.

> Without the privileges to load BPF, netker falls back to the "legacy"
> datapath (same devices, host stack forwarding). Force either one with
> `NETKER_DATAPATH=ebpf|legacy`.

## Requirements

- Linux with `CONFIG_NETKIT` (6.7+). `netker system check` verifies it.
- `crun` (or `runc` via `NETKER_RUNTIME=runc`), `nft`, cgroup v2, overlayfs
- root (see "Try it without root" below)

## Usage

```sh
make build
sudo bin/netker system check

sudo bin/netker run -d --name web -p 8080:80 nginx
sudo bin/netker ps
sudo bin/netker exec web ip -d link show eth0     # a netkit peer, L3 mode
ip -d link show type netkit                      # the primary on the host
sudo bin/netker run --rm alpine wget -qO- http://<web IP>/

sudo bin/netker network create --subnet 10.99.0.0/24 --netkit-mode l2 lab
sudo bin/netker run --rm --network lab alpine ip link

sudo bin/netker rm -f web
```

Commands: `run create start stop restart kill rm ps exec logs inspect port`,
`pull images rmi`, `network create|ls|rm|inspect`, `system check|gc`,
`system datapath status|upgrade`, `version`.

```sh
sudo bin/netker system datapath status    # pinned links, endpoint map, counters per verdict
sudo bin/netker system datapath upgrade   # swap every container's programs atomically
```

## Try it without root

`hack/sandbox.sh` runs netker inside new user, mount and network namespaces.
Inside them netker can create netkit devices, overlay mounts and nftables rules.
The sandbox has no uplink, so pull images first:

```sh
hack/sandbox.sh pull alpine
hack/sandbox.sh          # shell with netker on PATH
make e2e                 # the end-to-end test suite, unprivileged
```

## Development

```sh
make test               # unit tests
make test-integration   # real netkit devices in an unprivileged netns (legacy datapath)
make e2e                # full CLI test in the sandbox (legacy datapath)
make test-ebpf          # network tests as root in a privileged Docker container (eBPF)
make e2e-root           # full CLI test as root in a privileged Docker container (eBPF)
go generate ./internal/datapath/   # rebuild bpf/netker.c (needs clang)
```

## Known gaps

- Published ports aren't reachable through `127.0.0.1`. Use a host address.
  (The BPF datapath will handle this with a cgroup `connect` hook.)
- There is no shim yet, so exit codes of detached containers aren't recorded, and
  `--rm` only works for foreground runs.
- No seccomp profile, resource limits, or container name DNS yet.
- On hosts running firewalld, its forward policy may drop routed container traffic.

## License

GPL-2.0, see [LICENSE](LICENSE).
