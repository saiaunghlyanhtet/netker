#!/usr/bin/env bash
# Run netker without root: starts a shell (or runs the given command) inside
# new user, mount and network namespaces where netker has the privileges it
# needs. The sandbox's network namespace plays the role of "the host", so
# containers can't reach the internet; pull images before entering:
#
#   hack/sandbox.sh pull alpine        # pulls outside the sandbox
#   hack/sandbox.sh                    # interactive shell with netker on PATH
#   hack/sandbox.sh -c 'netker run --rm alpine ip addr'
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
export NETKER_ROOT="${NETKER_ROOT:-$repo/.sandbox/root}"
export NETKER_RUN="${NETKER_RUN:-$repo/.sandbox/run}"
export NETKER_CGROUP_MANAGER=disabled
mkdir -p "$NETKER_ROOT" "$NETKER_RUN"

go build -o "$repo/bin/netker" "$repo/cmd/netker"
export PATH="$repo/bin:$PATH"

if [[ "${1:-}" == "pull" ]]; then
	shift
	exec netker pull "$@"
fi

if [[ $# -eq 0 ]]; then
	cat >&2 <<-EOF
	netker sandbox: you are now "root" in new user, mount and network namespaces.
	  netker is on PATH, state lives in $NETKER_ROOT
	  containers have no internet here; pull images outside with: hack/sandbox.sh pull IMAGE
	  type 'exit' to leave
	EOF
fi
export NETKER_SANDBOX=1
rc=0
unshare --map-auto --map-root-user --mount --net --fork bash "$@" || rc=$?
[[ $# -eq 0 ]] && echo "left the netker sandbox" >&2
exit $rc
