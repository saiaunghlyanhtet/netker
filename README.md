# netker

Docker-compatible containers networked with Linux **netkit** devices
(`drivers/net/netkit.c`) instead of veth pairs and a bridge.

Each container gets a netkit pair. The primary device stays in the host,
and the peer becomes the container's `eth0`. The design (docs/DESIGN.md) moves
forwarding and NAT into BPF programs attached to those devices, following the
approach Cilium uses for pods.

> Status: early. Milestones M0 and M1 from [docs/DESIGN.md](docs/DESIGN.md) work: container
> lifecycle plus netkit networking with the host stack and nftables doing
> forwarding and NAT ("netkit-legacy" datapath). The eBPF datapath (M2+) is next.

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
`pull images rmi`, `network create|ls|rm|inspect`, `system check`, `version`.

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
make test-integration   # real netkit devices in an unprivileged netns
make e2e                # full CLI test in the sandbox
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
