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
	netker rm -f e2e-web >/dev/null 2>&1 || true
	netker network rm e2e-l2 >/dev/null 2>&1 || true
	ip link del e2e-pub0 2>/dev/null || true
}
trap cleanup EXIT
cleanup

netker run -d --name e2e-web -p 8080:80 alpine sh -c \
	'echo serving; while true; do printf "HTTP/1.0 200 OK\r\n\r\nhello from $(hostname)\n" | nc -l -p 80; done' >/dev/null
sleep 0.5
expect "detached container is running" "running" "$(netker ps --format json)"
ip=$(netker inspect e2e-web | sed -n 's/.*"ip": "\(.*\)".*/\1/p' | head -1)
[[ -n "$ip" ]] || fail "no IP in inspect output"

host_if=$(netker inspect e2e-web | sed -n 's/.*"host_if": "\(.*\)".*/\1/p' | head -1)
expect "host side is a netkit primary" "netkit mode l3 type primary" "$(ip -d link show "$host_if")"
expect "container side is eth0 in L3 mode" "NOARP" "$(netker exec e2e-web ip link show eth0)"

expect "host -> container" "hello from" "$(curl -s --max-time 3 "http://$ip/")"
expect "container -> container" "hello from" "$(timeout 10 netker run --rm alpine wget -T 3 -qO- "http://$ip/")"

datapath=$(netker inspect e2e-web | sed -n 's/.*"datapath": "\(.*\)".*/\1/p' | head -1)
echo "datapath: $datapath"
if [[ "$datapath" == ebpf ]]; then
	expect "eBPF: container egress is fail-closed" "peer policy blackhole" "$(ip -d link show "$host_if")"
	status=$(netker system datapath status)
	expect "eBPF: programs pinned on both sides" "primary" "$status"
	expect "eBPF: container->container was redirected in BPF" "forward-local" "$status"
	expect "eBPF: upgrade swaps programs in place" "updated 2 link(s)" "$(netker system datapath upgrade)"
	expect "eBPF: traffic flows after upgrade" "hello from" "$(curl -s --max-time 3 "http://$ip/")"
fi

ip link add e2e-pub0 type dummy
ip addr add 192.0.2.10/24 dev e2e-pub0
ip link set e2e-pub0 up
expect "published port" "hello from" "$(curl -s --max-time 3 http://192.0.2.10:8080/)"

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
