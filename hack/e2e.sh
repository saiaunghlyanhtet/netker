#!/usr/bin/env bash
# End-to-end test of the netker CLI. Runs as root, or unprivileged through
# hack/sandbox.sh (make e2e). Needs the alpine image to be pulled already.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
expect() { # expect <description> <want> <got>
	if [[ "$3" != *"$2"* ]]; then fail "$1: want '$2', got '$3'"; fi
	echo "ok: $1"
}
cleanup() {
	netker rm -f e2e-web e2e-solo >/dev/null 2>&1 || true
	netker network rm e2e-two >/dev/null 2>&1 || true
	netker network rm e2e-l2 >/dev/null 2>&1 || true
	ip link del e2e-pub0 2>/dev/null || true
}
trap cleanup EXIT
cleanup
# This namespace plays the host; a fresh "unshare --net" (as in CI) has lo
# down, and a host's connections to its own addresses go over lo.
ip link set lo up

netker run -d --name e2e-web -p 8080:80 alpine sh -c \
	'echo serving; while true; do printf "HTTP/1.0 200 OK\r\n\r\nhello from $(hostname)\n" | nc -l -p 80; done' >/dev/null
sleep 0.5
expect "detached container is running" "running" "$(netker ps --format json)"
ip=$(netker inspect e2e-web | sed -n 's/.*"ip": "\(.*\)".*/\1/p' | head -1)
[[ -n "$ip" ]] || fail "no IP in inspect output"

host_if=$(netker inspect e2e-web | sed -n 's/.*"host_if": "\(.*\)".*/\1/p' | head -1)
# Read the device through netker: iproute2 before netkit support (e.g. 6.1
# in Ubuntu 24.04) only prints the link kind.
devices=$(netker inspect e2e-web | tr -d ' \n' | grep -o '"netkit_devices":\[[^]]*\]')
expect "host side is a netkit device" "netkit" "$(ip -d link show "$host_if")"
expect "host side is the netkit primary in L3 mode" '"mode":"l3","primary":true' "$devices"
expect "container side is eth0 in L3 mode" "NOARP" "$(netker exec e2e-web ip link show eth0)"

expect "host -> container" "hello from" "$(curl -s --max-time 3 "http://$ip/")"
expect "container -> container" "hello from" "$(timeout 10 netker run --rm alpine wget -T 3 -qO- "http://$ip/")"

datapath=$(netker inspect e2e-web | sed -n 's/.*"datapath": "\(.*\)".*/\1/p' | head -1)
echo "datapath: $datapath"
if [[ "$datapath" == ebpf ]]; then
	expect "eBPF: container egress is fail-closed" '"peer_policy":"drop"' "$devices"
	status=$(netker system datapath status)
	expect "eBPF: programs pinned on both sides" "primary" "$status"
	expect "eBPF: container->container was redirected in BPF" "forward-local" "$status"
	updated=$(netker system datapath upgrade | sed -n 's/updated \([0-9]*\) link.*/\1/p')
	(( updated >= 2 )) || fail "eBPF: upgrade updated '$updated' links, want the container's 2 plus host hooks"
	echo "ok: eBPF: upgrade swapped $updated programs in place"
	expect "eBPF: traffic flows after upgrade" "hello from" "$(curl -s --max-time 3 "http://$ip/")"
fi

ip link add e2e-pub0 type dummy
ip addr add 192.0.2.10/24 dev e2e-pub0
ip link set e2e-pub0 up
expect "published port (address added after the container started)" "hello from" "$(curl -s --max-time 3 http://192.0.2.10:8080/)"
if [[ "$datapath" == ebpf ]]; then
	expect "eBPF: published port on 127.0.0.1" "hello from" "$(curl -s --max-time 3 http://127.0.0.1:8080/)"
	expect "eBPF: port published in BPF, not nftables" "0.0.0.0:8080/tcp" "$(netker system datapath status)"
	if nft list table ip netker 2>/dev/null | grep -q "dport 8080"; then fail "eBPF endpoint got nftables DNAT rules"; fi
	echo "ok: eBPF: no nftables DNAT rules for the port"
	if [[ -n "${E2E_INTERNET:-}" ]]; then
		expect "eBPF: container reaches the internet" "Example Domain" "$(netker exec e2e-web wget -T 5 -qO- http://example.com)"
		expect "eBPF: internet traffic masqueraded in BPF" "rev-snat" "$(netker system datapath status)"
	fi
fi

expect "logs" "serving" "$(netker logs e2e-web)"
expect "exec" "e2e" "$(netker exec -e X=e2e e2e-web sh -c 'echo $X')"

netker stop -t 1 e2e-web >/dev/null
expect "stopped container shows as exited" "exited" "$(netker ps -a)"
netker start e2e-web >/dev/null
sleep 0.5
expect "restarted container keeps its IP" "hello from" "$(curl -s --max-time 3 "http://$ip/")"

set +e
netker run --rm alpine sh -c 'exit 3'; code=$?
set -e
expect "run returns the container exit code" "3" "$code"

netker network create --subnet 10.99.0.0/24 --netkit-mode l2 e2e-l2 >/dev/null
out=$(netker run --rm --network e2e-l2 alpine sh -c 'ip link show eth0; ping -c1 -W2 10.99.0.1')
expect "L2 network: ARP enabled on eth0" "02:" "$out"
expect "L2 network: gateway reachable" "1 packets received" "$out"

netker network create --subnet 10.94.0.0/24 e2e-two >/dev/null
netker run -d --name e2e-solo --network e2e-two alpine sh -c \
	'while true; do printf "HTTP/1.0 200 OK\r\n\r\nsolo\n" | nc -l -p 80; done' >/dev/null
sleep 0.5
solo_ip=$(netker inspect e2e-solo | sed -n 's/.*"ip": "\(.*\)".*/\1/p' | head -1)
out=$(netker run --rm --network netker --network e2e-two alpine sh -c "ip -o -4 addr show; ip route; wget -T 3 -qO- http://$solo_ip/")
expect "two networks: eth0 on the first" "eth0    inet 10.87." "$out"
expect "two networks: eth1 on the second" "eth1    inet 10.94." "$out"
expect "two networks: default route on eth0" "default via 10.87.0.1 dev eth0" "$out"
expect "two networks: reaches a container on the second network" "solo" "$out"
if netker run --rm --network host --network e2e-two alpine true 2>/dev/null; then fail "--network host combined with another network was accepted"; fi
echo "ok: --network host can't be combined with other networks"
netker rm -f e2e-solo >/dev/null
netker network rm e2e-two >/dev/null

expect "--network none has only lo" "1: lo" "$(netker run --rm --network none alpine ip -o link)"

netker rm -f e2e-web >/dev/null
netker network rm e2e-l2 >/dev/null
[[ -z "$(ip link show type netkit)" ]] || fail "netkit devices left behind: $(ip link show type netkit)"
if nft list table ip netker 2>/dev/null | grep -q "netker:ctr:"; then fail "port rules left behind"; fi
echo "ok: cleanup removed all netkit devices and port rules"
if [[ "$datapath" == ebpf ]]; then
	links=$(netker system datapath status --format json | tr -d ' \n' | grep -o '"links":\[[^]]*\]' || true)
	[[ "$links" == '"links":null' || "$links" == '"links":[]' || -z "$links" ]] || fail "BPF links left behind: $links"
	echo "ok: cleanup removed all BPF links"
fi
echo PASS
