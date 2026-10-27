#!/usr/bin/env bash
# Runs netker's privileged tests inside a VM booted with another kernel, as
# .github/workflows/bpf.yml does with little-vm-helper (LVH). The repo is
# mounted at /host, with bin/netker and bin/network.test already built
# (static, CGO_ENABLED=0), so the VM needs no Go toolchain.
#
#   hack/vm-test.sh            # system check, network tests, e2e (eBPF)
#   hack/vm-test.sh no-netkit  # a kernel without netkit: system check must fail
#
# Logs go to /host/vm-logs, which the workflow uploads.
set -euo pipefail

repo=/host
logs="$repo/vm-logs"
mkdir -p "$logs"
trap 'dmesg > "$logs/dmesg.log" 2>&1 || true' EXIT

echo "kernel: $(uname -r)" | tee "$logs/kernel.log"

missing=()
for bin in nft crun ip curl; do
	command -v "$bin" >/dev/null || missing+=("$bin")
done
if ((${#missing[@]})); then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends nftables crun iproute2 curl ca-certificates >/dev/null
fi
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

if [[ "${1:-}" == no-netkit ]]; then
	if out=$("$repo/bin/netker" system check 2>&1); then
		echo "$out"
		echo "FAIL: system check passed on a kernel without netkit" >&2
		exit 1
	fi
	echo "$out" | tee "$logs/system-check.log"
	grep -q "FAIL.*netkit" <<<"$out" || { echo "FAIL: system check didn't name netkit" >&2; exit 1; }
	echo "ok: system check rejects a kernel without netkit"
	exit 0
fi

"$repo/bin/netker" system check | tee "$logs/system-check.log"

# State on the VM's disk: overlayfs can't use the 9p host mount as upper dir.
export NETKER_ROOT=/var/tmp/netker/root NETKER_RUN=/var/tmp/netker/run
export NETKER_DATAPATH=ebpf E2E_EXPECT_DATAPATH=ebpf

cd "$repo"
# The network tests' own netns plays the host, as in the integration workflow.
unshare --net --mount bin/network.test -test.v -test.count=1 -test.timeout 15m 2>&1 |
	tee "$logs/network-tests.log"

bin/netker pull alpine >/dev/null
PATH="$repo/bin:$PATH" unshare --net --mount hack/e2e.sh 2>&1 | tee "$logs/e2e.log"
