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
sudo bin/netker run --rm --network netker --network lab alpine ip -4 addr   # eth0 + eth1
sudo bin/netker network connect lab web       # hot-plug eth1 into a running container
sudo bin/netker network disconnect lab web
sudo bin/netker network create --subnet 10.98.0.0/24 --icc=false isolated   # no container-to-container traffic
sudo bin/netker network create --subnet 10.97.0.0/24 --subnet fd00:97::/64 dual   # dual-stack

sudo bin/netker rm -f web
```

Commands: `run create start stop restart kill rm ps exec logs inspect port`,
`pull images rmi`, `network create|ls|rm|inspect|connect|disconnect`, `system check|gc`,
`system datapath status|upgrade`, `version`.

```sh
sudo bin/netker system datapath status    # pinned links, endpoint map, counters per verdict
sudo bin/netker system datapath upgrade   # swap every container's programs atomically
                                          # (run after upgrading netker; see below)
sudo bin/netker system datapath sync      # attach to uplinks that appeared since
sudo bin/netker system datapath reset-host  # detach uplink/lo/cgroup hooks
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

## Upgrading netker

The datapath outlives the CLI: maps and links are pinned under
`/sys/fs/bpf/netker`, and running containers keep using the programs of the
netker version that started them. After installing a new netker, run
`sudo netker system datapath upgrade` to move every container onto the new
programs without restarting anything.

If the new version changed the layout of a map, netker refuses to start new
eBPF containers until you do (`system check` shows it, and `auto` doesn't
fall back to the legacy datapath behind your back). The upgrade then
recreates those maps and refills endpoints and published ports from the
container records; connections through NAT reset once if the NAT maps were
among them. The pinned maps are only replaced once every container runs the
new programs, so an upgrade that fails leaves everything as it was, and
running it again is always safe.

## Known gaps

- eBPF datapath:
  - NAT state is an LRU map with no TCP state or timeouts; idle flows are evicted
    only when it fills (256k entries).
  - ICMP errors (e.g. port unreachable) for masqueraded flows aren't translated back.
  - Unconnected UDP to `127.0.0.1:<published port>` isn't redirected (no
    `sendmsg4`/`recvmsg4` hooks yet); connected UDP and TCP are.
  - It sets `net.ipv4.conf.lo.accept_local=1`: replies to the host's
    connections to its own address on a published port are injected into `lo`
    without a route, and the kernel would otherwise drop their local source
    address. `netker system datapath reset-host` restores the old value.
  - Netfilter is bypassed for container traffic, so host firewalls (firewalld,
    nftables policies) don't see it, as with Cilium's eBPF host routing.
  - IPv6 packets with extension headers aren't translated in BPF; they fall
    back to the host stack and nftables masquerade.
- IPv6 (L3 networks only): containers get an address, routes and `/etc/hosts`
  entries. On the eBPF datapath IPv6 is forwarded, masqueraded (NAT66) and
  published like IPv4: `-p 8080:80` listens on IPv4 and, for dual-stack
  containers, IPv6 (including `[::1]`); `-p [::1]:8080:80` picks one address.
  The legacy datapath forwards IPv6 through the host stack and publishes
  ports on IPv4 only. Enabling IPv6 forwarding moves interfaces with
  `accept_ra=1` to `accept_ra=2`, so the host keeps its own router-advertised
  addresses.
- Legacy datapath: published ports aren't reachable through `127.0.0.1`.
- There is no shim yet, so exit codes of detached containers aren't recorded, and
  `--rm` only works for foreground runs.
- No seccomp profile or resource limits yet.
- Container names resolve through `/etc/hosts`, not a DNS server: containers on
  a shared network see each other by name, hostname and short ID, and the files
  are rewritten when containers join or leave. Unlike Docker's DNS, stopped
  containers stay listed (they keep their addresses), and names don't resolve
  for tools that skip `/etc/hosts` (e.g. `dig`).

## License

GPL-2.0, see [LICENSE](LICENSE).
